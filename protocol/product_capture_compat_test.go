package protocol_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestProductCapturePublicSDKSurface(t *testing.T) {
	workload := protocol.WorkloadSpec{
		Kind: protocol.WorkloadProvider,
		Provider: &protocol.ProviderWorkload{
			ProviderConfig: protocol.ProviderConfig{
				PluginID:   "workflow-plugin-product-capture",
				ProviderID: "browser",
				ContractID: "product-capture.browser.v1",
				Version:    "v1.0.0",
				ConfigRef:  "config://providers/product-capture/browser",
			},
			Operation: "capture_product",
			ImageRef:  "ghcr.io/gocodealone/product-capture@sha256:" + testHex64("a"),
			Input: mustTaskRawMessage(t, map[string]any{
				"url":           "https://example.test/products/sku-1",
				"allowed_hosts": []string{"example.test"},
				"capture_mode":  string(protocol.ProductCaptureModeBrowser),
			}),
		},
	}
	if err := workload.Validate(); err != nil {
		t.Fatalf("workload invalid: %v", err)
	}
	task := protocol.Task{
		ProtocolVersion: protocol.Version,
		ID:              "task-product-capture-compat",
		ProductID:       "product-capture",
		OrgID:           "org-1",
		PoolID:          "pool-1",
		PolicyID:        "policy-1",
		Status:          protocol.TaskQueued,
		Workload:        workload,
		InputHash:       protocol.CanonicalHash(workload),
		RequestedAt:     validTask(t).RequestedAt,
		TimeoutSeconds:  60,
		Signature: protocol.SignatureEnvelope{
			Algorithm: "test-sha256",
			KeyID:     "test-key",
			Value:     testHex64("b"),
		},
	}
	if err := task.Validate(); err != nil {
		t.Fatalf("task invalid: %v", err)
	}
	proof := protocol.ProofReceipt{
		ID:        "proof-product-capture-compat",
		TaskID:    task.ID,
		InputHash: task.InputHash,
		Verifier: protocol.VerifierResult{
			Provider: "shape",
			Status:   protocol.VerificationAccepted,
		},
	}
	list := protocol.TaskList{
		Tasks: []protocol.Task{task},
		Stalls: []protocol.TaskStall{{
			TaskID: task.ID,
			Reason: "waiting_for_worker",
			AgeMS:  100,
		}},
	}
	data, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal task list: %v", err)
	}
	var roundTrip protocol.TaskList
	if err := protocol.DecodeStrict(bytes.NewReader(data), &roundTrip); err != nil {
		t.Fatalf("strict decode task list: %v", err)
	}
	if len(roundTrip.Tasks) != 1 || roundTrip.Tasks[0].ID != task.ID {
		t.Fatalf("round trip tasks = %+v", roundTrip.Tasks)
	}
	if _, err := protocol.NewClient(protocol.ClientConfig{ServerURL: "https://wfcompute.example.test", Token: "token"}); err != nil {
		t.Fatalf("new client: %v", err)
	}
	if proof.Verifier.Status != protocol.VerificationAccepted {
		t.Fatalf("proof verifier status = %q", proof.Verifier.Status)
	}
}

func testHex64(char string) string {
	var buf bytes.Buffer
	for range 64 {
		buf.WriteString(char)
	}
	return buf.String()
}
