package internal

import (
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
)

// IaCServer is the IaC-mode stub for the scaffold. Embeds
// pb.UnimplementedIaCProviderRequiredServer so all required RPCs (Initialize,
// Name, Version, Capabilities, Plan, Destroy, Status, Import, ResolveSizing,
// BootstrapStateBackend) return codes.Unimplemented by default.
//
// Instantiators using `bash scripts/rename-from-scaffold.sh <name> --mode iac`
// replace this stub with their real IaC provider implementation. The
// rename script removes cmd/scaffold-workflow-plugin/ in IaC mode, so the
// non-IaC NewPlugin() entrypoint is gone — only the IaC server remains.
//
// To implement additional optional IaC contracts, embed the corresponding
// Unimplemented*Server type:
//   - pb.UnimplementedIaCProviderServer
//   - pb.UnimplementedIaCProviderLogCaptureServer
//   - pb.UnimplementedIaCProviderFinalizerServer
type IaCServer struct {
	pb.UnimplementedIaCProviderRequiredServer
}

// NewIaCServer constructs the IaC-mode plugin server. Called from
// cmd/scaffold-workflow-plugin-iac/main.go.
func NewIaCServer() *IaCServer {
	return &IaCServer{}
}
