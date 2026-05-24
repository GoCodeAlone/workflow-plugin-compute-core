// Command scaffold-workflow-plugin is the NON-IaC variant of the workflow
// plugin scaffold. It runs as a subprocess and communicates with the host
// workflow engine via the go-plugin gRPC protocol.
//
// Instantiators run `bash scripts/rename-from-scaffold.sh <name> --mode non-iac`
// to copy this file to cmd/workflow-plugin-<their-name>/main.go and delete
// the IaC variant (cmd/scaffold-workflow-plugin-iac/).
package main

import (
	"github.com/GoCodeAlone/scaffold-workflow-plugin/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.Serve(internal.NewPlugin(),
		sdk.WithBuildVersion(sdk.ResolveBuildVersion(internal.Version)),
	)
}
