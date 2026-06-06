package protocol_test

import (
	"context"
	"encoding/json"
	"errors"
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
			_ = json.NewEncoder(w).Encode(protocol.TaskList{
				Tasks: []protocol.Task{task},
				Stalls: []protocol.TaskStall{{
					TaskID: task.ID,
					Reason: "waiting_for_worker",
					AgeMS:  250,
				}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/proofs":
			_ = json.NewEncoder(w).Encode(protocol.ProofList{Proofs: []protocol.ProofReceipt{proof}})
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
