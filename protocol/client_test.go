package protocol_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestClientSubmitTaskUsesStrictJSONAndBearerAuth(t *testing.T) {
	want := validTask(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tasks" {
			t.Fatalf("request = %s %s, want POST /v1/tasks", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content-type = %q", got)
		}
		var submitted protocol.Task
		if err := protocol.DecodeStrict(r.Body, &submitted); err != nil {
			t.Fatalf("decode submitted task: %v", err)
		}
		if submitted.ID != want.ID {
			t.Fatalf("submitted task id = %q, want %q", submitted.ID, want.ID)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(protocol.TaskResponse{Task: want})
	}))
	defer server.Close()

	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	got, err := client.SubmitTask(context.Background(), want)
	if err != nil {
		t.Fatalf("submit task: %v", err)
	}
	if got.ID != want.ID {
		t.Fatalf("task id = %q, want %q", got.ID, want.ID)
	}
}

func TestClientListSnapshotAndProofLookup(t *testing.T) {
	task := validTask(t)
	proof := protocol.ProofReceipt{
		ID:        "proof-1",
		OrgID:     task.OrgID,
		TaskID:    task.ID,
		TaskHash:  protocol.CanonicalHash(task),
		InputHash: task.InputHash,
		Verifier: protocol.VerifierResult{
			Provider: "shape",
			Status:   protocol.VerificationAccepted,
		},
		AgentSignature: protocol.SoftwareAgentProofSignature(protocol.ProofReceipt{ID: "proof-1"}),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks":
			_ = json.NewEncoder(w).Encode(protocol.TaskListWithSummary{
				Tasks: []protocol.Task{task},
				Stalls: []protocol.TaskStall{{
					TaskID: task.ID,
					Reason: "waiting_for_worker",
					AgeMS:  250,
				}},
				Summary: protocol.TaskListSummary{Total: 1, Open: 1, Queued: 1, Stalled: 1},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/proofs":
			_ = json.NewEncoder(w).Encode(protocol.ProofListWithSummary{
				Proofs:  []protocol.ProofReceipt{proof},
				Summary: protocol.ProofListSummary{Total: 1, Accepted: 1},
			})
		default:
			t.Fatalf("unexpected request = %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	list, err := client.ListTasks(context.Background())
	if err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	if len(list.Tasks) != 1 || list.Tasks[0].ID != task.ID {
		t.Fatalf("tasks = %+v", list.Tasks)
	}
	snapshot, ok, stalls, err := client.TaskSnapshot(context.Background(), task.ID)
	if err != nil {
		t.Fatalf("task snapshot: %v", err)
	}
	if !ok || snapshot.ID != task.ID || len(stalls) != 1 {
		t.Fatalf("snapshot = %+v ok=%v stalls=%+v", snapshot, ok, stalls)
	}
	proofs, err := client.ListProofs(context.Background())
	if err != nil {
		t.Fatalf("list proofs: %v", err)
	}
	if len(proofs) != 1 || proofs[0].TaskID != task.ID {
		t.Fatalf("proofs = %+v", proofs)
	}
	found, ok, err := client.FindProof(context.Background(), task.ID)
	if err != nil {
		t.Fatalf("find proof: %v", err)
	}
	if !ok || found.ID != proof.ID {
		t.Fatalf("found = %+v ok=%v", found, ok)
	}
}

func TestClientLegacyListWrappersPreserveJSONEncoding(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "tasks", value: protocol.TaskList{}, want: `{"tasks":null}`},
		{name: "proofs", value: protocol.ProofList{}, want: `{"proofs":null}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatalf("marshal wrapper: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("encoded wrapper = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClientListResponsesMatchLiveServerContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			_, _ = w.Write([]byte(`{"tasks":[{"id":"queued-1","status":"queued"},{"id":"queued-2","status":"queued"},{"id":"queued-3","status":"queued"},{"id":"running-1","status":"running"},{"id":"succeeded-1","status":"succeeded"}],"stalls":[{"task_id":"queued-1","reason":"waiting_for_worker","age_ms":1},{"task_id":"queued-2","reason":"waiting_for_worker","age_ms":1}],"summary":{"total":5,"open":4,"queued":3,"stalled":2,"succeeded":1}}`))
		case "/v1/proofs":
			_, _ = w.Write([]byte(`{"proofs":[{"id":"accepted-1","verifier":{"status":"accepted"}},{"id":"accepted-2","verifier":{"status":"accepted"}},{"id":"pending-1","verifier":{"status":"pending"}},{"id":"rejected-1","verifier":{"status":"rejected"}},{"id":"conflicted-1","verifier":{"status":"conflicted"}}],"summary":{"total":5,"accepted":2,"pending":1,"rejected":1,"conflicted":1}}`))
		default:
			t.Errorf("unexpected request = %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	tasks, err := client.ListTasksWithSummary(t.Context())
	if err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	wantTasks := protocol.TaskListSummary{Total: 5, Open: 4, Queued: 3, Stalled: 2, Succeeded: 1}
	if tasks.Summary != wantTasks {
		t.Fatalf("task summary = %+v, want %+v", tasks.Summary, wantTasks)
	}

	proofs, err := client.ListProofsWithSummary(t.Context())
	if err != nil {
		t.Fatalf("list proofs with summary: %v", err)
	}
	wantProofs := protocol.ProofListSummary{Total: 5, Accepted: 2, Pending: 1, Rejected: 1, Conflicted: 1}
	if proofs.Summary != wantProofs {
		t.Fatalf("proof summary = %+v, want %+v", proofs.Summary, wantProofs)
	}
}

func TestClientListResponsesRejectUnknownFields(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		call func(*protocol.Client) error
	}{
		{
			name: "tasks top level",
			path: "/v1/tasks",
			body: `{"tasks":[],"summary":{"total":0,"open":0,"queued":0,"stalled":0,"succeeded":0},"unexpected":true}`,
			call: func(client *protocol.Client) error {
				_, err := client.ListTasksWithSummary(t.Context())
				return err
			},
		},
		{
			name: "tasks summary",
			path: "/v1/tasks",
			body: `{"tasks":[],"summary":{"total":0,"open":0,"queued":0,"stalled":0,"succeeded":0,"unexpected":true}}`,
			call: func(client *protocol.Client) error {
				_, err := client.ListTasksWithSummary(t.Context())
				return err
			},
		},
		{
			name: "proofs top level",
			path: "/v1/proofs",
			body: `{"proofs":[],"summary":{"total":0,"accepted":0,"pending":0,"rejected":0,"conflicted":0},"unexpected":true}`,
			call: func(client *protocol.Client) error {
				_, err := client.ListProofsWithSummary(t.Context())
				return err
			},
		},
		{
			name: "proofs summary",
			path: "/v1/proofs",
			body: `{"proofs":[],"summary":{"total":0,"accepted":0,"pending":0,"rejected":0,"conflicted":0,"unexpected":true}}`,
			call: func(client *protocol.Client) error {
				_, err := client.ListProofsWithSummary(t.Context())
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.path {
					t.Errorf("path = %q, want %q", r.URL.Path, tt.path)
					http.Error(w, "unexpected path", http.StatusNotFound)
					return
				}
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			if err := tt.call(client); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("error = %v, want strict unknown-field rejection", err)
			}
		})
	}
}

func TestClientPreservesServerURLBasePath(t *testing.T) {
	task := validTask(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/tasks" {
			t.Fatalf("request = %s %s, want POST /api/v1/tasks", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(protocol.TaskResponse{Task: task})
	}))
	defer server.Close()
	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL + "/api"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if _, err := client.SubmitTask(context.Background(), task); err != nil {
		t.Fatalf("submit task: %v", err)
	}
}

func TestClientRejectsTokenOverNonLoopbackHTTP(t *testing.T) {
	if _, err := protocol.NewClient(protocol.ClientConfig{ServerURL: "http://example.test", Token: "secret"}); err == nil {
		t.Fatal("expected token over non-loopback http to fail")
	}
}

func TestClientStatusErrorDoesNotExposeBody(t *testing.T) {
	const sentinel = "secret-response-body"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, sentinel, http.StatusUnauthorized)
	}))
	defer server.Close()
	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = client.SubmitTask(context.Background(), validTask(t))
	if err == nil {
		t.Fatal("expected status error")
	}
	var statusErr protocol.StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("error %T = %v, want StatusError", err, err)
	}
	if statusErr.Method != http.MethodPost || statusErr.Path != "/v1/tasks" || statusErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status error = %+v", statusErr)
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("status error leaked response body: %v", err)
	}
}

func TestClientStrictDecodeRejectsUnknownFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"task":{},"unexpected":true}`))
	}))
	defer server.Close()
	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = client.SubmitTask(context.Background(), validTask(t))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("SubmitTask error = %v, want strict decode unknown field", err)
	}
}

func TestClientListsAgentsAndLeasesWithBearerAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer read-token" {
			t.Fatalf("authorization = %q", got)
		}
		switch r.URL.Path {
		case "/v1/agents":
			_, _ = w.Write([]byte(`{"agents":[{"id":"agent-1","org_id":"org-1","pool_id":"pool-1","status":"online","capabilities":{"os":"linux","arch":"amd64","runtime_backend_reports":[{"protocol_version":"compute.v1alpha1","backend_id":"podman-rootless","family":"podman","tool":"podman","version":"5.0.0","status":"supported","isolation_mode":"user-namespace","runtime_profiles":["sandboxed-oci-v1"]}]},"last_seen_at":"2026-07-11T12:00:00Z","created_at":"2026-07-01T10:30:00Z"}],"summary":{"total":1,"active":1,"stale":0,"offline":0,"registered":1,"historical":0}}`))
		case "/v1/leases":
			_, _ = w.Write([]byte(`{"leases":[{"id":"lease-1","task_id":"task-1","worker_id":"agent-1","pool_id":"pool-1","executor":{"provider":"provider-1","version":"v1"},"capability_snapshot":{"os":"linux","arch":"amd64"},"provider_artifact_specs":[{"name":"product_json","required":true,"content_type":"application/json","max_bytes":4096}],"leased_at":"2026-07-11T11:59:00Z","expires_at":"2026-07-11T12:01:00Z"}]}`))
		default:
			t.Fatalf("unexpected request = %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL, Token: "read-token"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	agents, err := client.ListAgents(t.Context())
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if len(agents) != 1 || agents[0].ID != "agent-1" || agents[0].Status != protocol.AgentOnline {
		t.Fatalf("agents = %+v", agents)
	}
	if want := time.Date(2026, 7, 1, 10, 30, 0, 0, time.UTC); !agents[0].CreatedAt.Equal(want) {
		t.Fatalf("created_at = %s, want %s", agents[0].CreatedAt, want)
	}
	if reports := agents[0].Capabilities.RuntimeBackendReports; len(reports) != 1 || reports[0].BackendID != "podman-rootless" {
		t.Fatalf("runtime backend reports = %+v", reports)
	}
	leases, err := client.ListLeases(t.Context())
	if err != nil {
		t.Fatalf("list leases: %v", err)
	}
	if len(leases) != 1 || len(leases[0].ProviderArtifactSpecs) != 1 || leases[0].ProviderArtifactSpecs[0].Name != "product_json" {
		t.Fatalf("leases = %+v", leases)
	}
}

func TestClientListTaskArtifactsEscapesTaskID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.EscapedPath(), "/v1/tasks/task%20%2F%25/artifacts"; got != want {
			t.Fatalf("escaped path = %q, want %q", got, want)
		}
		_, _ = w.Write([]byte(`{"artifacts":[]}`))
	}))
	defer server.Close()
	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	artifacts, err := client.ListTaskArtifacts(t.Context(), "task /%")
	if err != nil {
		t.Fatalf("list task artifacts: %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("artifacts = %+v", artifacts)
	}
}

func TestClientListTaskArtifactsRejectsEmptyAndDotTaskIDs(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
	}))
	defer server.Close()
	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	for _, taskID := range []string{"", ".", ".."} {
		artifacts, err := client.ListTaskArtifacts(t.Context(), taskID)
		if err == nil || artifacts != nil {
			t.Errorf("ListTaskArtifacts(%q) = %+v, %v; want nil, error", taskID, artifacts, err)
			continue
		}
		if got, want := err.Error(), `taskID must not be empty, ".", or ".."`; got != want {
			t.Errorf("ListTaskArtifacts(%q) error = %q, want %q", taskID, got, want)
		}
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want 0", requests)
	}
}

func TestClientTaskArtifactServerFixtureRoundTrip(t *testing.T) {
	const (
		ref     = "artifact://pool-1/tasks/task-1/proofs/proof-1/run-logs/result.json"
		payload = `{"status":"captured","items":[1,2]}`
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer fixture-token" {
			t.Fatalf("authorization = %q", got)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.EscapedPath() == "/v1/tasks/task-1/artifacts":
			_, _ = w.Write([]byte(`{"artifacts":[{"task_id":"task-1","proof_id":"proof-1","pool_id":"pool-1","name":"run-logs/result.json","ref":"artifact://pool-1/tasks/task-1/proofs/proof-1/run-logs/result.json","content_type":"application/json","sha256":"sha256:0e6c1551d69759758a92a684a2071f892dc834d6f292e75ec76645f7dd04e740","size_bytes":35,"created_at":"2026-07-11T12:00:00Z","expires_at":"2026-07-11T13:00:00Z"}]}`))
		case r.Method == http.MethodGet && r.URL.EscapedPath() == "/v1/tasks/task-1/proofs/proof-1/artifacts/run-logs/result.json":
			_, _ = w.Write([]byte(payload))
		default:
			t.Fatalf("unexpected request = %s %s", r.Method, r.URL.EscapedPath())
		}
	}))
	defer server.Close()
	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL, Token: "fixture-token"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	artifacts, err := client.ListTaskArtifacts(t.Context(), "task-1")
	if err != nil {
		t.Fatalf("list task artifacts: %v", err)
	}
	if len(artifacts) != 1 || artifacts[0].Ref != ref {
		t.Fatalf("artifacts = %+v", artifacts)
	}
	digest := sha256.Sum256([]byte(payload))
	wantSHA256 := "sha256:" + hex.EncodeToString(digest[:])
	if artifacts[0].SHA256 != wantSHA256 || artifacts[0].SizeBytes != int64(len(payload)) {
		t.Fatalf("artifact integrity = sha256 %q, size %d; want %q, %d", artifacts[0].SHA256, artifacts[0].SizeBytes, wantSHA256, len(payload))
	}
	got, err := client.DownloadTaskArtifact(t.Context(), artifacts[0].Ref, 1024)
	if err != nil {
		t.Fatalf("download task artifact: %v", err)
	}
	if !bytes.Equal(got, []byte(payload)) {
		t.Fatalf("download = %q, want exact JSON %q", got, payload)
	}
}

func TestClientDownloadTaskArtifactEscapesCanonicalSegments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.EscapedPath(), "/v1/tasks/task%25id/proofs/proof%25id/artifacts/run-logs/stderr%25.txt"; got != want {
			t.Fatalf("escaped path = %q, want %q", got, want)
		}
		_, _ = w.Write([]byte("stderr"))
	}))
	defer server.Close()
	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	got, err := client.DownloadTaskArtifact(t.Context(), "artifact://pool%id/tasks/task%id/proofs/proof%id/run-logs/stderr%.txt", 32)
	if err != nil {
		t.Fatalf("download task artifact: %v", err)
	}
	if string(got) != "stderr" {
		t.Fatalf("download = %q", got)
	}
}

func TestClientDownloadTaskArtifactRejectsUnsafeRefsAndLimits(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		t.Fatal("invalid artifact download reached server")
	}))
	defer server.Close()
	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	refs := []string{
		"https://example.test/private",
		"artifact:///tasks/task-1/proofs/proof-1/result.json",
		"artifact://pool-1/tasks//proofs/proof-1/result.json",
		"artifact://pool-1/tasks/task-1/proofs//result.json",
		"artifact://pool-1/tasks/task-1/proofs/proof-1",
		"artifact://pool-1/tasks/task-1/proofs/proof-1/",
		"artifact://pool-1/tasks/task-1/proofs/proof-1/run-logs//result.json",
		"artifact://pool-1/task/task-1/proofs/proof-1/result.json",
		"artifact://pool-1/tasks/task-1/proof/proof-1/result.json",
		"artifact://pool-1/tasks/task-1/proofs/proof-1/../secret",
		"artifact://pool-1/tasks/task-1/proofs/proof-1/bad\\name",
		"artifact://pool-1/tasks/task-1/proofs/proof-1/name?token=secret",
	}
	for _, ref := range refs {
		if got, err := client.DownloadTaskArtifact(t.Context(), ref, 32); err == nil || got != nil {
			t.Errorf("DownloadTaskArtifact(%q) = %q, %v; want nil, error", ref, got, err)
		}
	}
	if got, err := client.DownloadTaskArtifact(t.Context(), "artifact://pool-1/tasks/task-1/proofs/proof-1/result.json", 0); err == nil || got != nil {
		t.Fatalf("nonpositive limit = %q, %v; want nil, error", got, err)
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want 0", requests)
	}
}

func TestClientDownloadTaskArtifactRejectsMaxBytesPlusOneWithoutPartialData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("12345"))
	}))
	defer server.Close()
	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	got, err := client.DownloadTaskArtifact(t.Context(), "artifact://pool-1/tasks/task-1/proofs/proof-1/result.txt", 4)
	if err == nil || !strings.Contains(err.Error(), "maxBytes") {
		t.Fatalf("error = %v, want maxBytes rejection", err)
	}
	if got != nil {
		t.Fatalf("partial data = %q, want nil", got)
	}
}

func TestClientDownloadTaskArtifactHandlesMaxInt64LimitWithoutOverflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("artifact"))
	}))
	defer server.Close()
	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	got, err := client.DownloadTaskArtifact(t.Context(), "artifact://pool-1/tasks/task-1/proofs/proof-1/result.txt", math.MaxInt64)
	if err != nil {
		t.Fatalf("download task artifact: %v", err)
	}
	if string(got) != "artifact" {
		t.Fatalf("download = %q", got)
	}
}

func TestClientAgentLeaseArtifactReadMethodsUseStrictJSON(t *testing.T) {
	tests := map[string]func(*protocol.Client) error{
		"agents": func(client *protocol.Client) error {
			_, err := client.ListAgents(t.Context())
			return err
		},
		"leases": func(client *protocol.Client) error {
			_, err := client.ListLeases(t.Context())
			return err
		},
		"artifacts": func(client *protocol.Client) error {
			_, err := client.ListTaskArtifacts(t.Context(), "task-1")
			return err
		},
	}
	for name, call := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"unexpected":true}`))
			}))
			defer server.Close()
			client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			if err := call(client); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("error = %v, want strict decode unknown field", err)
			}
		})
	}
}

func TestClientListLeasesStrictlyDecodesProviderArtifactSpecs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"leases":[{"provider_artifact_specs":[{"name":"result","unexpected":true}]}]}`))
	}))
	defer server.Close()
	client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if _, err := client.ListLeases(t.Context()); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("ListLeases error = %v, want strict artifact spec decode", err)
	}
}

func TestClientAgentLeaseArtifactStatusErrorsDoNotExposeBody(t *testing.T) {
	const sentinel = "private-read-response"
	tests := map[string]func(*protocol.Client) error{
		"agents": func(client *protocol.Client) error {
			_, err := client.ListAgents(t.Context())
			return err
		},
		"leases": func(client *protocol.Client) error {
			_, err := client.ListLeases(t.Context())
			return err
		},
		"artifacts": func(client *protocol.Client) error {
			_, err := client.ListTaskArtifacts(t.Context(), "task-1")
			return err
		},
		"download": func(client *protocol.Client) error {
			_, err := client.DownloadTaskArtifact(t.Context(), "artifact://pool-1/tasks/task-1/proofs/proof-1/result.json", 1024)
			return err
		},
	}
	for name, call := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, sentinel, http.StatusForbidden)
			}))
			defer server.Close()
			client, err := protocol.NewClient(protocol.ClientConfig{ServerURL: server.URL})
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			err = call(client)
			var statusErr protocol.StatusError
			if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusForbidden {
				t.Fatalf("error = %T %v, want StatusError 403", err, err)
			}
			if strings.Contains(err.Error(), sentinel) {
				t.Fatalf("status error leaked response body: %v", err)
			}
		})
	}
}

func TestClientCapacityHelpersSelectOnlineMatchingIdleAgent(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	agents := []protocol.Agent{
		{ID: "offline", OrgID: "org-1", PoolID: "pool-1", Status: protocol.AgentOffline},
		{ID: "other-pool", OrgID: "org-1", PoolID: "pool-2", Status: protocol.AgentOnline},
		{ID: "busy", OrgID: "org-1", PoolID: "pool-1", Status: protocol.AgentOnline},
		{ID: "idle", OrgID: "org-1", PoolID: "pool-1", Status: protocol.AgentOnline},
	}
	leases := []protocol.Lease{
		{WorkerID: "busy", ExpiresAt: now.Add(time.Minute)},
		{WorkerID: "idle", ExpiresAt: now.Add(-time.Minute)},
	}

	got, ok := protocol.SelectIdleAgent(agents, leases, "org-1", "pool-1", now)
	if !ok || got.ID != "idle" {
		t.Fatalf("SelectIdleAgent = %+v, %v; want idle", got, ok)
	}
}

func TestClientCapacityHelpersFindQueuedMatchingTask(t *testing.T) {
	tasks := []protocol.Task{
		{ID: "done", OrgID: "org-1", PoolID: "pool-1", Status: protocol.TaskSucceeded},
		{ID: "other", OrgID: "org-1", PoolID: "pool-2", Status: protocol.TaskQueued},
		{ID: "queued", OrgID: "org-1", PoolID: "pool-1", Status: protocol.TaskQueued},
	}

	got, ok := protocol.FindQueuedTask(tasks, "org-1", "pool-1")
	if !ok || got.ID != "queued" {
		t.Fatalf("FindQueuedTask = %+v, %v; want queued", got, ok)
	}
}

func TestClientCapacityHelpersSelectAdditionalNetworkMembership(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	agents := []protocol.Agent{{
		ID:     "additional-member",
		OrgID:  "org-default",
		PoolID: "pool-default",
		Status: protocol.AgentOnline,
		Networks: []protocol.AgentNetworkProfile{{
			OrgID:  " org-target ",
			PoolID: " pool-target ",
		}},
	}}

	got, ok := protocol.SelectIdleAgent(agents, nil, "org-target", "pool-target", now)
	if !ok || got.ID != "additional-member" {
		t.Fatalf("SelectIdleAgent = %+v, %v; want additional-member", got, ok)
	}
}

func TestClientCapacityHelpersDisabledExplicitDefaultBlocksImplicitMembership(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	agents := []protocol.Agent{{
		ID:     "disabled-default",
		OrgID:  "org-1",
		PoolID: "pool-1",
		Status: protocol.AgentOnline,
		Networks: []protocol.AgentNetworkProfile{{
			OrgID:    " org-1 ",
			PoolID:   " pool-1 ",
			Disabled: true,
		}},
	}}

	if got, ok := protocol.SelectIdleAgent(agents, nil, "org-1", "pool-1", now); ok {
		t.Fatalf("SelectIdleAgent = %+v, true; want disabled explicit default rejected", got)
	}
}
