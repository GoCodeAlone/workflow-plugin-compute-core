// Command workflow-plugin-compute-core exposes compute protocol metadata as an
// external Workflow plugin dependency anchor.
package main

import (
	"github.com/GoCodeAlone/workflow-plugin-compute-core/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.Serve(internal.NewPlugin(),
		sdk.WithBuildVersion(sdk.ResolveBuildVersion(internal.Version)),
	)
}
