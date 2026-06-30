package protocol

import "context"

type ServiceProvider interface {
	Name() string
	Descriptor() RuntimeDescriptor
	CanServe(task Task, lease Lease) bool
	RunService(ctx context.Context, req ServiceRunRequest) (RuntimeServiceResult, error)
}

type ServiceSessionProvider interface {
	ServiceProvider
	StartServiceSession(ctx context.Context, req ServiceRunRequest) (ServiceSession, error)
}

type ServiceSession interface {
	Health(ctx context.Context) (RuntimeServiceResult, error)
	Stop(ctx context.Context) (RuntimeServiceResult, error)
}

type ServiceRunRequest struct {
	Task            Task                  `json:"task"`
	Lease           Lease                 `json:"lease"`
	Workspace       string                `json:"workspace,omitempty"`
	Env             map[string]string     `json:"env,omitempty"`
	Limits          ResourceLimits        `json:"limits,omitzero"`
	Network         NetworkBinding        `json:"network,omitzero"`
	RuntimeScope    ContainerRuntimeScope `json:"runtime_scope,omitzero"`
	HTTPHelperImage string                `json:"http_helper_image,omitempty"`
	DataMounts      []SandboxMount        `json:"data_mounts,omitempty"`
}

type NetworkBinding struct {
	Mode            NetworkMode `json:"mode,omitempty"`
	SandboxNetwork  string      `json:"sandbox_network,omitempty"`
	Captive         bool        `json:"captive,omitempty"`
	GatewayEndpoint string      `json:"gateway_endpoint,omitempty"`
	ProxyURL        string      `json:"proxy_url,omitempty"`
}

type ContainerRuntimeScope struct {
	Args []string `json:"args,omitempty"`
}

type SandboxMount struct {
	HostPath       string `json:"host_path"`
	ContainerPath  string `json:"container_path"`
	ReadOnly       bool   `json:"read_only,omitempty"`
	RequiredPrefix string `json:"required_prefix,omitempty"`
}
