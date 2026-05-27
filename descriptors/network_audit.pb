
½
<workflow_plugin_compute_core/protocol/v1/network_audit.proto(workflow_plugin_compute_core.protocol.v1"–
NetworkAuditRecord)
protocol_version (	RprotocolVersion
	record_id (	RrecordId
task_id (	RtaskId
lease_id (	RleaseId
	worker_id (	RworkerIdb
provider (2F.workflow_plugin_compute_core.protocol.v1.NetworkAuditProviderEvidenceRproviderc
destination (2A.workflow_plugin_compute_core.protocol.v1.NetworkAuditDestinationRdestinationj
resource_usage (2C.workflow_plugin_compute_core.protocol.v1.NetworkAuditResourceUsageRresourceUsage`
labels	 (2H.workflow_plugin_compute_core.protocol.v1.NetworkAuditRecord.LabelsEntryRlabels/
started_at_unix_nano
 (RstartedAtUnixNano1
finished_at_unix_nano (RfinishedAtUnixNano1
observed_at_unix_nano (RobservedAtUnixNano9
LabelsEntry
key (	Rkey
value (	Rvalue:8"€
NetworkAuditProviderEvidence
provider_id (	R
providerId
plugin_name (	R
pluginName%
plugin_version (	RpluginVersion
contract_id (	R
contractId)
contract_version (	RcontractVersion+
descriptor_digest (	RdescriptorDigest"C
NetworkAuditDestination
kind (	Rkind
value (	Rvalue"À
NetworkAuditResourceUsage

cpu_millis (R	cpuMillis

gpu_millis (R	gpuMillis(
max_memory_bytes (RmaxMemoryBytes(
network_rx_bytes (RnetworkRxBytes(
network_tx_bytes (RnetworkTxBytes'
workspace_bytes (RworkspaceBytes!
output_bytes (RoutputBytes
	limit_hit (	RlimitHit"a
NetworkAuditValidationIssue
code (	Rcode
field (	Rfield
message (	RmessageBDZBgithub.com/GoCodeAlone/workflow-plugin-compute-core/protocol/pb;pbbproto3