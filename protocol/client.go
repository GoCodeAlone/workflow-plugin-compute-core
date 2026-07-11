package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultClientTimeout = 30 * time.Second

type ClientConfig struct {
	ServerURL  string
	Token      string
	HTTPClient *http.Client
	Timeout    time.Duration
}

type Client struct {
	baseURL *url.URL
	token   string
	http    *http.Client
}

type TaskResponse struct {
	Task Task `json:"task"`
}

type TaskList struct {
	Tasks  []Task      `json:"tasks"`
	Stalls []TaskStall `json:"stalls,omitempty"`
}

type TaskStall struct {
	TaskID  string `json:"task_id,omitempty"`
	LeaseID string `json:"lease_id,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
	Reason  string `json:"reason"`
	AgeMS   int64  `json:"age_ms"`
}

type ProofList struct {
	Proofs []ProofReceipt `json:"proofs"`
}

type agentListResponse struct {
	Agents  []Agent          `json:"agents"`
	Summary agentListSummary `json:"summary"`
}

type agentListSummary struct {
	Total      int `json:"total"`
	Active     int `json:"active"`
	Stale      int `json:"stale"`
	Offline    int `json:"offline"`
	Registered int `json:"registered"`
	Historical int `json:"historical"`
}

type leaseListResponse struct {
	Leases []Lease `json:"leases"`
}

type taskArtifactListResponse struct {
	Artifacts []TaskArtifact `json:"artifacts"`
}

type StatusError struct {
	Method     string
	Path       string
	StatusCode int
}

func (e StatusError) Error() string {
	return fmt.Sprintf("%s %s: got status %d", e.Method, e.Path, e.StatusCode)
}

func NewClient(config ClientConfig) (*Client, error) {
	parsed, err := url.ParseRequestURI(config.ServerURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("server_url must be absolute http(s) URL")
	}
	if config.Token != "" && parsed.Scheme != "https" && !isLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("server_url must use https when auth token is set")
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		timeout := config.Timeout
		if timeout <= 0 {
			timeout = defaultClientTimeout
		}
		httpClient = &http.Client{Timeout: timeout}
	}
	return &Client{
		baseURL: parsed,
		token:   config.Token,
		http:    httpClient,
	}, nil
}

func (c *Client) SubmitTask(ctx context.Context, task Task) (Task, error) {
	var out TaskResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/tasks", task, http.StatusCreated, &out); err != nil {
		return Task{}, err
	}
	return out.Task, nil
}

func (c *Client) ListTasks(ctx context.Context) (TaskList, error) {
	var out TaskList
	if err := c.doJSON(ctx, http.MethodGet, "/v1/tasks", nil, http.StatusOK, &out); err != nil {
		return TaskList{}, err
	}
	return out, nil
}

func (c *Client) ListAgents(ctx context.Context) ([]Agent, error) {
	var out agentListResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/agents", nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return out.Agents, nil
}

func (c *Client) ListLeases(ctx context.Context) ([]Lease, error) {
	var out leaseListResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/leases", nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return out.Leases, nil
}

func (c *Client) ListTaskArtifacts(ctx context.Context, taskID string) ([]TaskArtifact, error) {
	if taskID == "" || taskID == "." || taskID == ".." {
		return nil, errors.New(`taskID must not be empty, ".", or ".."`)
	}
	path := escapedPath("v1", "tasks", taskID, "artifacts")
	var out taskArtifactListResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return out.Artifacts, nil
}

func (c *Client) DownloadTaskArtifact(ctx context.Context, ref string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("maxBytes must be positive")
	}
	_, taskID, proofID, name, err := taskArtifactRefParts(ref)
	if err != nil {
		return nil, err
	}
	segments := []string{"v1", "tasks", taskID, "proofs", proofID, "artifacts"}
	segments = append(segments, strings.Split(name, "/")...)
	path := escapedPath(segments...)
	endpoint := c.baseURL.JoinPath(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", http.MethodGet, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, StatusError{Method: http.MethodGet, Path: path, StatusCode: resp.StatusCode}
	}
	readLimit := maxBytes
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("artifact exceeds maxBytes %d", maxBytes)
	}
	return data, nil
}

func (c *Client) TaskSnapshot(ctx context.Context, id string) (Task, bool, []TaskStall, error) {
	list, err := c.ListTasks(ctx)
	if err != nil {
		return Task{}, false, nil, err
	}
	matchingStalls := make([]TaskStall, 0)
	for _, stall := range list.Stalls {
		if stall.TaskID == id {
			matchingStalls = append(matchingStalls, stall)
		}
	}
	for _, task := range list.Tasks {
		if task.ID == id {
			return task, true, matchingStalls, nil
		}
	}
	return Task{}, false, matchingStalls, nil
}

func (c *Client) ListProofs(ctx context.Context) ([]ProofReceipt, error) {
	var out ProofList
	if err := c.doJSON(ctx, http.MethodGet, "/v1/proofs", nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return out.Proofs, nil
}

func (c *Client) FindProof(ctx context.Context, taskID string) (ProofReceipt, bool, error) {
	proofs, err := c.ListProofs(ctx)
	if err != nil {
		return ProofReceipt{}, false, err
	}
	for _, proof := range proofs {
		if proof.TaskID == taskID {
			return proof, true, nil
		}
	}
	return ProofReceipt{}, false, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, want int, out any) error {
	var requestBody io.Reader = http.NoBody
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		requestBody = bytes.NewReader(data)
	}
	endpoint := c.baseURL.JoinPath(path)
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), requestBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		return StatusError{Method: method, Path: path, StatusCode: resp.StatusCode}
	}
	if out == nil {
		return nil
	}
	return DecodeStrict(resp.Body, out)
}

func DecodeStrict(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) == io.EOF {
		return nil
	}
	return errors.New("multiple JSON values are not allowed")
}

func escapedPath(segments ...string) string {
	escaped := make([]string, len(segments))
	for i, segment := range segments {
		escaped[i] = url.PathEscape(segment)
	}
	return "/" + strings.Join(escaped, "/")
}

func taskArtifactRefParts(ref string) (poolID, taskID, proofID, name string, err error) {
	if !strings.HasPrefix(ref, "artifact://") {
		return "", "", "", "", errors.New("artifact ref must use artifact://")
	}
	parts := strings.Split(strings.TrimPrefix(ref, "artifact://"), "/")
	if len(parts) < 7 || parts[1] != "tasks" || parts[3] != "proofs" || parts[5] != "artifacts" {
		return "", "", "", "", errors.New("artifact ref must use artifact://<pool>/tasks/<task>/proofs/<proof>/artifacts/<name>")
	}
	dataSegments := append([]string{parts[0], parts[2], parts[4]}, parts[6:]...)
	for _, segment := range dataSegments {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "\\\x00\r\n\t ?#") {
			return "", "", "", "", errors.New("artifact ref contains unsafe segment")
		}
	}
	return parts[0], parts[2], parts[4], strings.Join(parts[6:], "/"), nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
