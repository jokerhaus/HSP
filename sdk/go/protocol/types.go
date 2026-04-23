package protocol

type TenantID string
type KeyPolicyID string
type EncryptionProfileID string
type OperationName string
type VisibilityMode string
type CapabilityScope string
type ErrorCategory string
type ObjectSelectorKind string
type GetPreference string
type PayloadMode string

const (
	OperationInfo      OperationName = "INFO"
	OperationHead      OperationName = "HEAD"
	OperationGet       OperationName = "GET"
	OperationResolve   OperationName = "RESOLVE"
	OperationBind      OperationName = "BIND"
	OperationUnbind    OperationName = "UNBIND"
	OperationList      OperationName = "LIST"
	OperationSubscribe OperationName = "SUBSCRIBE"
	OperationPutInit   OperationName = "PUT_INIT"
	OperationPutChunk  OperationName = "PUT_CHUNK"
	OperationPutCommit OperationName = "PUT_COMMIT"
)

const (
	VisibilityModeServerVisible VisibilityMode = "server_visible"
	VisibilityModeEncryptedOnly VisibilityMode = "encrypted_only"
	VisibilityModeSplit         VisibilityMode = "split"
)

const (
	CapabilityScopeRead             CapabilityScope = "read"
	CapabilityScopeWrite            CapabilityScope = "write"
	CapabilityScopeBind             CapabilityScope = "bind"
	CapabilityScopeUnbind           CapabilityScope = "unbind"
	CapabilityScopeList             CapabilityScope = "list"
	CapabilityScopeSubscribe        CapabilityScope = "subscribe"
	CapabilityScopePin              CapabilityScope = "pin"
	CapabilityScopeReplicate        CapabilityScope = "replicate"
	CapabilityScopeAdminMetricsRead CapabilityScope = "admin.metrics.read"
	CapabilityScopeAdminAuditRead   CapabilityScope = "admin.audit.read"
	CapabilityScopeAdminRepair      CapabilityScope = "admin.repair"
	CapabilityScopeAdminKeyRotate   CapabilityScope = "admin.key.rotate"
	CapabilityScopeAdminPolicyWrite CapabilityScope = "admin.policy.write"
)

const (
	ErrorCategoryAuth        ErrorCategory = "auth"
	ErrorCategoryReplay      ErrorCategory = "replay"
	ErrorCategoryPolicy      ErrorCategory = "policy"
	ErrorCategoryValidation  ErrorCategory = "validation"
	ErrorCategoryUnsupported ErrorCategory = "unsupported"
	ErrorCategoryNotFound    ErrorCategory = "not_found"
	ErrorCategoryConflict    ErrorCategory = "conflict"
	ErrorCategoryStorage     ErrorCategory = "storage"
)

const (
	ObjectSelectorKindCID       ObjectSelectorKind = "cid"
	ObjectSelectorKindNamespace ObjectSelectorKind = "namespace"
)

const (
	GetPreferenceRaw          GetPreference = "raw"
	GetPreferenceChunkStream  GetPreference = "chunk-stream"
	GetPreferenceManifestOnly GetPreference = "manifest-only"
)

const (
	PayloadModeNone        PayloadMode = "none"
	PayloadModeJSON        PayloadMode = "json"
	PayloadModeRaw         PayloadMode = "raw"
	PayloadModeChunkStream PayloadMode = "chunk_stream"
)

type APIError struct {
	Category ErrorCategory `json:"category"`
	Code     string        `json:"code"`
	Message  string        `json:"message"`
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}

	return e.Message
}

type ServiceLimits struct {
	MaxChunkSize            uint64 `json:"max_chunk_size"`
	MaxManifestSize         uint64 `json:"max_manifest_size"`
	MaxObjectSize           uint64 `json:"max_object_size"`
	MaxParallelChunkStreams uint16 `json:"max_parallel_chunk_streams"`
}

type BootstrapNativeEndpoint struct {
	ALPN string `json:"alpn"`
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

type BootstrapGatewayEndpoint struct {
	BaseURL string `json:"base_url"`
}

type BootstrapDocument struct {
	Version                   uint8                    `json:"version"`
	Authority                 string                   `json:"authority"`
	Native                    BootstrapNativeEndpoint  `json:"native"`
	Gateway                   BootstrapGatewayEndpoint `json:"gateway"`
	E2EERequired              bool                     `json:"e2ee_required"`
	StorageEncryptionRequired bool                     `json:"storage_encryption_required"`
	CryptoSuite               []string                 `json:"crypto_suite"`
	KeyWrappingSuite          string                   `json:"key_wrapping_suite"`
	TenantIsolationProfile    string                   `json:"tenant_isolation_profile"`
	SupportedTokenProfiles    []string                 `json:"supported_token_profiles"`
	SupportedExtensions       []string                 `json:"supported_extensions"`
	LimitsRevision            uint64                   `json:"limits_revision"`
	Limits                    ServiceLimits            `json:"limits"`
}

type InfoResponse struct {
	Version                   uint8         `json:"version"`
	AuthorityProfile          string        `json:"authority_profile"`
	E2EERequired              bool          `json:"e2ee_required"`
	StorageEncryptionRequired bool          `json:"storage_encryption_required"`
	CryptoSuite               []string      `json:"crypto_suite"`
	KeyWrappingSuite          string        `json:"key_wrapping_suite"`
	TenantIsolationProfile    string        `json:"tenant_isolation_profile"`
	SupportedTokenProfiles    []string      `json:"supported_token_profiles"`
	SupportedExtensions       []string      `json:"supported_extensions"`
	LimitsRevision            uint64        `json:"limits_revision"`
	Limits                    ServiceLimits `json:"limits"`
}

type WrappedObjectKeyRecord struct {
	RecipientKeyID     string `json:"recipient_key_id"`
	WrappingSuite      string `json:"wrapping_suite"`
	WrappedKeyBase64   string `json:"wrapped_key_b64"`
	KeyVersion         uint32 `json:"key_version"`
	EncapsulatedKeyB64 string `json:"encapsulated_key_b64,omitempty"`
}

type EncryptionDescriptor struct {
	EncryptionProfileID     EncryptionProfileID      `json:"encryption_profile_id"`
	KeyPolicyID             KeyPolicyID              `json:"key_policy_id"`
	ContentEncryptionSuite  string                   `json:"content_encryption_suite"`
	KeyWrappingSuite        string                   `json:"key_wrapping_suite"`
	MetadataVisibility      VisibilityMode           `json:"metadata_visibility"`
	WrappedObjectKeys       []WrappedObjectKeyRecord `json:"wrapped_object_keys"`
	ServerVisibleMetadata   map[string]string        `json:"server_visible_metadata"`
	EncryptedClientMetadata map[string]string        `json:"encrypted_client_metadata"`
}

type ChunkRef struct {
	ChunkIndex      uint32 `json:"chunk_index"`
	CID             string `json:"cid"`
	Offset          uint64 `json:"offset"`
	LogicalLength   uint64 `json:"logical_len"`
	StoredLength    uint64 `json:"stored_len"`
	ContentEncoding string `json:"content_encoding"`
}

type Manifest struct {
	Version              uint8                `json:"version"`
	TenantID             TenantID             `json:"tenant_id"`
	LogicalSize          uint64               `json:"logical_size"`
	StoredSize           uint64               `json:"stored_size"`
	Chunker              string               `json:"chunker"`
	ChunkRefs            []ChunkRef           `json:"chunk_refs"`
	ContentType          string               `json:"content_type"`
	CreatedAtMS          uint64               `json:"created_at_ms"`
	EncryptionDescriptor EncryptionDescriptor `json:"encryption_descriptor"`
}

type ChannelBindingProof struct {
	BindingKind string `json:"binding_kind"`
	ProofBase64 string `json:"proof_b64"`
	Nonce       string `json:"nonce"`
}

type CapabilityClaims struct {
	ISS                string            `json:"iss"`
	SUB                string            `json:"sub"`
	AUD                string            `json:"aud"`
	EXP                uint64            `json:"exp"`
	NBF                *uint64           `json:"nbf,omitempty"`
	JTI                string            `json:"jti,omitempty"`
	OPS                []CapabilityScope `json:"ops"`
	TenantID           TenantID          `json:"tenant_id"`
	NamespacePrefix    string            `json:"namespace_prefix,omitempty"`
	PathPrefix         string            `json:"path_prefix,omitempty"`
	MaxObjectSize      *uint64           `json:"max_object_size,omitempty"`
	StorageClasses     []string          `json:"storage_classes"`
	KeyPolicyID        string            `json:"key_policy_id,omitempty"`
	MetadataVisibility *VisibilityMode   `json:"metadata_visibility,omitempty"`
}

type ObjectSelector struct {
	Kind      ObjectSelectorKind `json:"kind"`
	CID       string             `json:"cid,omitempty"`
	Namespace string             `json:"namespace,omitempty"`
	Path      string             `json:"path,omitempty"`
}

func CIDSelector(cid string) ObjectSelector {
	return ObjectSelector{
		Kind: ObjectSelectorKindCID,
		CID:  cid,
	}
}

func NamespaceSelector(namespace string, path string) ObjectSelector {
	return ObjectSelector{
		Kind:      ObjectSelectorKindNamespace,
		Namespace: namespace,
		Path:      path,
	}
}

type AtomicBindRequest struct {
	Namespace       string            `json:"namespace"`
	Path            string            `json:"path"`
	IfRevision      *uint64           `json:"if_revision,omitempty"`
	Metadata        map[string]string `json:"metadata"`
	TTLMS           *uint64           `json:"ttl_ms,omitempty"`
	SignedRecordB64 string            `json:"signed_record_b64"`
}

type NamespaceMutationKind string

const (
	NamespaceMutationBind       NamespaceMutationKind = "bind"
	NamespaceMutationUnbind     NamespaceMutationKind = "unbind"
	NamespaceMutationHardDelete NamespaceMutationKind = "hard_delete"
)

type NamespaceMutationRecord struct {
	Version    uint8                 `json:"version"`
	TenantID   TenantID              `json:"tenant_id"`
	Namespace  string                `json:"namespace"`
	Path       string                `json:"path"`
	Kind       NamespaceMutationKind `json:"kind"`
	TargetCID  string                `json:"target_cid,omitempty"`
	IfRevision *uint64               `json:"if_revision,omitempty"`
	TTLMS      *uint64               `json:"ttl_ms,omitempty"`
	Metadata   map[string]string     `json:"metadata"`
	IssuedAtMS uint64                `json:"issued_at_ms"`
}

type SignedNamespaceMutation struct {
	Record       NamespaceMutationRecord `json:"record"`
	COSESign1B64 string                  `json:"cose_sign1_b64"`
}

type ResolveRequest struct {
	TenantID   TenantID `json:"tenant_id"`
	Namespace  string   `json:"namespace"`
	Path       string   `json:"path"`
	AtRevision *uint64  `json:"at_revision,omitempty"`
	IfRevision *uint64  `json:"if_revision,omitempty"`
}

type ResolveResponse struct {
	Revision    uint64            `json:"revision"`
	TargetCID   string            `json:"target_cid,omitempty"`
	ManifestCID string            `json:"manifest_cid,omitempty"`
	RecordCID   string            `json:"record_cid"`
	Metadata    map[string]string `json:"metadata"`
	Tombstone   bool              `json:"tombstone"`
}

type BindRequest struct {
	TenantID        TenantID          `json:"tenant_id"`
	Namespace       string            `json:"namespace"`
	Path            string            `json:"path"`
	TargetCID       string            `json:"target_cid"`
	IfRevision      *uint64           `json:"if_revision,omitempty"`
	IfAbsent        bool              `json:"if_absent"`
	Metadata        map[string]string `json:"metadata"`
	TTLMS           *uint64           `json:"ttl_ms,omitempty"`
	IdempotencyKey  string            `json:"idempotency_key"`
	SignedRecordB64 string            `json:"signed_record_b64"`
}

type BindResponse struct {
	Revision  uint64 `json:"revision"`
	RecordCID string `json:"record_cid"`
	EventSeq  uint64 `json:"event_seq"`
}

type UnbindRequest struct {
	TenantID        TenantID `json:"tenant_id"`
	Namespace       string   `json:"namespace"`
	Path            string   `json:"path"`
	IfRevision      uint64   `json:"if_revision"`
	HardDelete      bool     `json:"hard_delete"`
	IdempotencyKey  string   `json:"idempotency_key"`
	SignedRecordB64 string   `json:"signed_record_b64"`
}

type UnbindResponse struct {
	Revision  uint64 `json:"revision"`
	RecordCID string `json:"record_cid"`
	EventSeq  uint64 `json:"event_seq"`
	Tombstone bool   `json:"tombstone"`
}

type ListRequest struct {
	TenantID          TenantID `json:"tenant_id"`
	Namespace         string   `json:"namespace"`
	Prefix            string   `json:"prefix,omitempty"`
	Cursor            string   `json:"cursor,omitempty"`
	Limit             *uint32  `json:"limit,omitempty"`
	Recursive         bool     `json:"recursive"`
	IncludeTombstones bool     `json:"include_tombstones"`
}

type ListItem struct {
	Namespace   string            `json:"namespace"`
	Path        string            `json:"path"`
	TargetCID   string            `json:"target_cid,omitempty"`
	ManifestCID string            `json:"manifest_cid,omitempty"`
	Revision    uint64            `json:"revision"`
	RecordCID   string            `json:"record_cid"`
	Metadata    map[string]string `json:"metadata"`
	Tombstone   bool              `json:"tombstone"`
}

type ListResponse struct {
	Items                     []ListItem `json:"items"`
	NextCursor                string     `json:"next_cursor,omitempty"`
	Truncated                 bool       `json:"truncated"`
	NamespaceRevisionSnapshot uint64     `json:"namespace_revision_snapshot"`
}

type EventType string

const (
	EventTypeObjectCommitted     EventType = "object.committed"
	EventTypeNamespaceBound      EventType = "namespace.bound"
	EventTypeNamespaceUnbound    EventType = "namespace.unbound"
	EventTypeNamespaceTombstoned EventType = "namespace.tombstoned"
	EventTypeAuthDenied          EventType = "auth.denied"
	EventTypePinAccepted         EventType = "pin.accepted"
)

type EventRecord struct {
	Version     uint8             `json:"version"`
	Seq         uint64            `json:"seq"`
	AtMS        uint64            `json:"at_ms"`
	EventType   EventType         `json:"event_type"`
	SubjectKind string            `json:"subject_kind"`
	Namespace   string            `json:"namespace,omitempty"`
	Path        string            `json:"path,omitempty"`
	CID         string            `json:"cid,omitempty"`
	Revision    *uint64           `json:"revision,omitempty"`
	TraceID     string            `json:"trace_id,omitempty"`
	Payload     map[string]string `json:"payload"`
}

type EventCursor struct {
	TenantID TenantID `json:"tenant_id"`
	NextSeq  uint64   `json:"next_seq"`
}

type ListCursor struct {
	TenantID         TenantID `json:"tenant_id"`
	Namespace        string   `json:"namespace"`
	Prefix           string   `json:"prefix,omitempty"`
	SnapshotRevision uint64   `json:"snapshot_revision"`
	LastPath         string   `json:"last_path"`
}

type SubscribeFilter struct {
	NamespacePrefix string    `json:"namespace_prefix,omitempty"`
	PathExact       string    `json:"path_exact,omitempty"`
	ObjectCID       string    `json:"object_cid,omitempty"`
	EventType       EventType `json:"event_type,omitempty"`
	TenantScope     string    `json:"tenant_scope,omitempty"`
}

type SubscribeRequest struct {
	TenantID    TenantID          `json:"tenant_id"`
	Filters     []SubscribeFilter `json:"filters"`
	Cursor      string            `json:"cursor,omitempty"`
	FromSeq     *uint64           `json:"from_seq,omitempty"`
	HeartbeatMS *uint64           `json:"heartbeat_ms,omitempty"`
	BatchMax    *uint32           `json:"batch_max,omitempty"`
}

type NoticeFrame struct {
	Kind    string `json:"kind"`
	Message string `json:"message,omitempty"`
	Cursor  string `json:"cursor,omitempty"`
}

type SubscribeEnvelopeKind string

const (
	SubscribeEnvelopeEvent  SubscribeEnvelopeKind = "event"
	SubscribeEnvelopeNotice SubscribeEnvelopeKind = "notice"
)

type SubscribeEnvelope struct {
	Kind   SubscribeEnvelopeKind `json:"kind"`
	Event  *EventRecord          `json:"event,omitempty"`
	Notice *NoticeFrame          `json:"notice,omitempty"`
}

type PutInitRequest struct {
	TenantID            TenantID            `json:"tenant_id"`
	Manifest            Manifest            `json:"manifest"`
	IdempotencyKey      string              `json:"idempotency_key"`
	EncryptionProfileID EncryptionProfileID `json:"encryption_profile_id"`
	KeyPolicyID         KeyPolicyID         `json:"key_policy_id"`
	MetadataVisibility  VisibilityMode      `json:"metadata_visibility"`
	StorageClass        string              `json:"storage_class"`
	AtomicBind          *AtomicBindRequest  `json:"atomic_bind,omitempty"`
}

type PutInitResponse struct {
	SessionID               string   `json:"session_id"`
	MissingChunks           []uint32 `json:"missing_chunks"`
	AcceptedManifestCID     string   `json:"accepted_manifest_cid"`
	UploadDeadlineMS        uint64   `json:"upload_deadline_ms"`
	MaxParallelChunkStreams uint16   `json:"max_parallel_chunk_streams"`
}

type PutChunkRequest struct {
	TenantID        TenantID `json:"tenant_id"`
	SessionID       string   `json:"session_id"`
	ChunkIndex      uint32   `json:"chunk_index"`
	ChunkCID        string   `json:"chunk_cid"`
	ChunkOffset     uint64   `json:"chunk_offset"`
	ChunkLength     uint64   `json:"chunk_length"`
	ContentEncoding string   `json:"content_encoding"`
}

type PutChunkResponse struct {
	Stored      bool `json:"stored"`
	Duplicate   bool `json:"duplicate"`
	VerifiedCID bool `json:"verified_cid"`
}

type PutCommitRequest struct {
	TenantID       TenantID `json:"tenant_id"`
	SessionID      string   `json:"session_id"`
	ManifestCID    string   `json:"manifest_cid"`
	IdempotencyKey string   `json:"idempotency_key"`
}

type PutCommitResponse struct {
	ObjectCID string `json:"object_cid"`
	Committed bool   `json:"committed"`
	EventSeq  uint64 `json:"event_seq"`
}

type RangeSpec struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

type HeadRequest struct {
	TenantID TenantID       `json:"tenant_id"`
	Selector ObjectSelector `json:"selector"`
}

type HeadResponse struct {
	Exists                          bool                `json:"exists"`
	Deleted                         bool                `json:"deleted"`
	CID                             string              `json:"cid"`
	ObjectCID                       string              `json:"object_cid"`
	ManifestCID                     string              `json:"manifest_cid"`
	IntegrityHash                   string              `json:"integrity_hash"`
	StorageClass                    string              `json:"storage_class"`
	ResolvedNamespace               string              `json:"resolved_namespace,omitempty"`
	ResolvedPath                    string              `json:"resolved_path,omitempty"`
	ResolvedRevision                *uint64             `json:"resolved_revision,omitempty"`
	ResolvedRecordCID               string              `json:"resolved_record_cid,omitempty"`
	SizeBytes                       uint64              `json:"size_bytes"`
	CiphertextSizeBytes             uint64              `json:"ciphertext_size_bytes"`
	LogicalSize                     uint64              `json:"logical_size"`
	StoredSize                      uint64              `json:"stored_size"`
	ContentType                     string              `json:"content_type"`
	CreatedAtMS                     uint64              `json:"created_at_ms"`
	EncryptionProfileID             EncryptionProfileID `json:"encryption_profile_id"`
	KeyPolicyID                     KeyPolicyID         `json:"key_policy_id"`
	MetadataVisibility              VisibilityMode      `json:"metadata_visibility"`
	ServerVisibleMetadata           map[string]string   `json:"server_visible_metadata"`
	EncryptedClientMetadataRedacted bool                `json:"encrypted_client_metadata_redacted"`
}

type GetRequest struct {
	TenantID   TenantID       `json:"tenant_id"`
	Selector   ObjectSelector `json:"selector"`
	Preference *GetPreference `json:"preference,omitempty"`
	Range      *RangeSpec     `json:"range,omitempty"`
}

type GetChunkDescriptor struct {
	ChunkIndex        uint32 `json:"chunk_index"`
	ChunkCID          string `json:"chunk_cid"`
	ChunkOffset       uint64 `json:"chunk_offset"`
	LogicalRangeStart uint64 `json:"logical_range_start"`
	LogicalRangeEnd   uint64 `json:"logical_range_end"`
	FragmentOffset    uint64 `json:"fragment_offset"`
	FragmentLength    uint64 `json:"fragment_length"`
	ContentEncoding   string `json:"content_encoding"`
}

type GetResponseMeta struct {
	Exists                          bool                 `json:"exists"`
	Deleted                         bool                 `json:"deleted"`
	CID                             string               `json:"cid"`
	ObjectCID                       string               `json:"object_cid"`
	ManifestCID                     string               `json:"manifest_cid"`
	IntegrityHash                   string               `json:"integrity_hash"`
	StorageClass                    string               `json:"storage_class"`
	ResolvedNamespace               string               `json:"resolved_namespace,omitempty"`
	ResolvedPath                    string               `json:"resolved_path,omitempty"`
	ResolvedRevision                *uint64              `json:"resolved_revision,omitempty"`
	ResolvedRecordCID               string               `json:"resolved_record_cid,omitempty"`
	SizeBytes                       uint64               `json:"size_bytes"`
	CiphertextSizeBytes             uint64               `json:"ciphertext_size_bytes"`
	LogicalSize                     uint64               `json:"logical_size"`
	StoredSize                      uint64               `json:"stored_size"`
	ContentType                     string               `json:"content_type"`
	CreatedAtMS                     uint64               `json:"created_at_ms"`
	EncryptionProfileID             EncryptionProfileID  `json:"encryption_profile_id"`
	KeyPolicyID                     KeyPolicyID          `json:"key_policy_id"`
	MetadataVisibility              VisibilityMode       `json:"metadata_visibility"`
	ServerVisibleMetadata           map[string]string    `json:"server_visible_metadata"`
	EncryptedClientMetadataRedacted bool                 `json:"encrypted_client_metadata_redacted"`
	Preference                      GetPreference        `json:"preference"`
	Manifest                        *Manifest            `json:"manifest,omitempty"`
	ChunkDescriptors                []GetChunkDescriptor `json:"chunk_descriptors"`
}

type GetChunk struct {
	Descriptor GetChunkDescriptor `json:"descriptor"`
	Bytes      []byte             `json:"bytes"`
}

type GetResponse struct {
	Meta   GetResponseMeta `json:"meta"`
	Chunks []GetChunk      `json:"chunks"`
}

type SettingsFrame struct {
	MaxChunkSize              uint64   `json:"max_chunk_size"`
	MaxManifestSize           uint64   `json:"max_manifest_size"`
	MaxObjectSize             uint64   `json:"max_object_size"`
	MaxParallelStreams        uint16   `json:"max_parallel_streams"`
	SupportedChunkers         []string `json:"supported_chunkers"`
	SupportedContentEncodings []string `json:"supported_content_encodings"`
	SupportedTokenProfiles    []string `json:"supported_token_profiles"`
	SupportedExtensions       []string `json:"supported_extensions"`
	ServerInstanceID          string   `json:"server_instance_id"`
	EventReplayWindowSec      uint64   `json:"event_replay_window_sec"`
	LimitsRevision            uint64   `json:"limits_revision"`
}

type ReqHeader struct {
	Version       uint8          `json:"version"`
	Operation     OperationName  `json:"operation"`
	RequestID     *uint64        `json:"request_id,omitempty"`
	PayloadMode   *PayloadMode   `json:"payload_mode,omitempty"`
	PayloadLength *uint64        `json:"payload_length,omitempty"`
	Params        map[string]any `json:"params"`
	Extensions    map[string]any `json:"extensions"`
}

type ResHeader struct {
	Version       uint8          `json:"version"`
	StatusCode    uint16         `json:"status_code"`
	RequestID     *uint64        `json:"request_id,omitempty"`
	PayloadMode   *PayloadMode   `json:"payload_mode,omitempty"`
	PayloadLength *uint64        `json:"payload_length,omitempty"`
	Meta          map[string]any `json:"meta"`
	Extensions    map[string]any `json:"extensions"`
}

type WireErrorFrame struct {
	Category ErrorCategory `json:"category"`
	Code     string        `json:"code"`
	Message  string        `json:"message"`
}

type GoAwayFrame struct {
	Reason string `json:"reason"`
}

type AuthFrame struct {
	TokenBase64    string              `json:"token_b64"`
	ChannelBinding ChannelBindingProof `json:"channel_binding"`
}

type ReadinessReport struct {
	Ready               bool     `json:"ready"`
	KMSProvider         string   `json:"kms_provider"`
	EncryptedStoreRoots []string `json:"encrypted_store_roots"`
}
