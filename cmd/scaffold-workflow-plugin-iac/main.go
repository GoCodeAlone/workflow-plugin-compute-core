// Command scaffold-workflow-plugin-iac is the IaC variant of the workflow
// plugin scaffold. Use this entrypoint when the plugin provisions
// infrastructure (cloud resources, etc.) — it serves the typed
// pb.IaCProvider* surface required by wfctl infra apply/plan/destroy.
//
// Instantiators run `bash scripts/rename-from-scaffold.sh <name> --mode iac`
// to copy this file to cmd/workflow-plugin-<their-name>/main.go and delete
// the non-IaC variant (cmd/scaffold-workflow-plugin/).
//
// Non-IaC plugins use cmd/scaffold-workflow-plugin/main.go instead. The
// rename script's --mode flag selects which entrypoint survives.
package main

import (
	"github.com/GoCodeAlone/scaffold-workflow-plugin/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.ServeIaCPlugin(internal.NewIaCServer(), sdk.IaCServeOptions{
		BuildVersion: sdk.ResolveBuildVersion(internal.Version),
	})
}
