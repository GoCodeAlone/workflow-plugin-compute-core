package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
