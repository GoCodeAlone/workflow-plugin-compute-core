// Package internal implements the workflow-plugin-compute-core plugin.
package internal

import (
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// Version is set at build time via -ldflags
// "-X github.com/GoCodeAlone/workflow-plugin-compute-core/internal.Version=X.Y.Z".
// Default is a bare semver so plugin loaders that validate semver accept
// unreleased dev builds; goreleaser overrides with the real release tag.
var Version = "0.0.0"

// ComputeCorePlugin exposes compute-core protocol metadata.
type ComputeCorePlugin struct{}

// NewPlugin returns a new plugin instance. main.go calls sdk.Serve(NewPlugin()).
func NewPlugin() sdk.PluginProvider {
	return &ComputeCorePlugin{}
}

// Manifest returns the plugin metadata used by the workflow engine for
// discovery and capability negotiation.
func (p *ComputeCorePlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-compute-core",
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "Public compute protocol and provider catalog core for Workflow.",
	}
}
