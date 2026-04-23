package gatewaybeta

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/loxar/hsp/sdk/go/alpha"
	"github.com/loxar/hsp/sdk/go/protocol"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const tlsExporterLabel = "EXPORTER-HSP-Channel-Binding-v1"

type ClientOptions struct {
	BaseURL         string
	CapabilityToken string
	TLSConfig       *tls.Config
}

type RequestOptions struct {
	CapabilityToken string
}

type Diagnostics struct {
	Bootstrap          protocol.BootstrapDocument `json:"bootstrap"`
	Info               protocol.InfoResponse      `json:"info"`
	ChunkStreamFirst   bool                       `json:"chunk_stream_first"`
	ChannelBindingKind string                     `json:"channel_binding_kind"`
}

type Client struct {
	baseURL         *url.URL
	capabilityToken string
	transport       *http3.Transport
	tracker         *connectionTracker
}

type connectionTracker struct {
	mu    sync.RWMutex
	conns map[string]*quic.Conn
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.BaseURL == "" {
		return nil, &protocol.APIError{
			Category: protocol.ErrorCategoryValidation,
			Code:     "missing_base_url",
			Message:  "base URL is required",
		}
	}

	baseURL, err := url.Parse(options.BaseURL)
	if err != nil {
		return nil, err
	}

	if baseURL.Scheme != "https" {
		return nil, &protocol.APIError{
			Category: protocol.ErrorCategoryValidation,
			Code:     "invalid_base_url_scheme",
			Message:  "gateway base URL must use https",
		}
	}

	if !strings.HasSuffix(baseURL.Path, "/") {
		baseURL.Path += "/"
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{http3.NextProtoH3},
	}
	if options.TLSConfig != nil {
		tlsConfig = options.TLSConfig.Clone()
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = tls.VersionTLS13
		}
		if len(tlsConfig.NextProtos) == 0 {
			tlsConfig.NextProtos = []string{http3.NextProtoH3}
		}
	}

	tracker := &connectionTracker{
		conns: make(map[string]*quic.Conn),
	}

	transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			conn, err := quic.DialAddr(ctx, addr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			tracker.store(addr, conn)
			return conn, nil
		},
	}

	return &Client{
		baseURL:         baseURL,
		capabilityToken: options.CapabilityToken,
		transport:       transport,
		tracker:         tracker,
	}, nil
}

func (c *Client) Close() error {
	if c == nil || c.transport == nil {
		return nil
	}

	return c.transport.Close()
}

func (c *Client) Bootstrap(ctx context.Context) (protocol.BootstrapDocument, error) {
	response, err := c.doRequest(ctx, http.MethodGet, c.bootstrapURL(nil), nil, "", nil, false)
	if err != nil {
		return protocol.BootstrapDocument{}, err
	}
	defer response.Body.Close()

	var document protocol.BootstrapDocument
	if err := decodeJSONResponse(response, &document); err != nil {
		return protocol.BootstrapDocument{}, err
	}

	return document, nil
}

func (c *Client) Info(ctx context.Context) (protocol.InfoResponse, error) {
	response, err := c.doRequest(ctx, http.MethodGet, c.apiURL("info", nil), nil, "", nil, false)
	if err != nil {
		return protocol.InfoResponse{}, err
	}
	defer response.Body.Close()

	var info protocol.InfoResponse
	if err := decodeJSONResponse(response, &info); err != nil {
		return protocol.InfoResponse{}, err
	}

	return info, nil
}

func (c *Client) Diagnostics(ctx context.Context) (Diagnostics, error) {
	bootstrap, err := c.Bootstrap(ctx)
	if err != nil {
		return Diagnostics{}, err
	}

	info, err := c.Info(ctx)
	if err != nil {
		return Diagnostics{}, err
	}

	return Diagnostics{
		Bootstrap:          bootstrap,
		Info:               info,
		ChunkStreamFirst:   true,
		ChannelBindingKind: "tls-exporter",
	}, nil
}

func (c *Client) Head(
	ctx context.Context,
	request protocol.HeadRequest,
	options *RequestOptions,
) (protocol.HeadResponse, error) {
	targetPath, err := selectorObjectPath(request.Selector)
	if err != nil {
		return protocol.HeadResponse{}, err
	}

	query := url.Values{
		"tenant_id": []string{string(request.TenantID)},
	}

	response, err := c.doRequest(
		ctx,
		http.MethodHead,
		c.apiURL(targetPath, query),
		nil,
		"",
		options,
		true,
	)
	if err != nil {
		return protocol.HeadResponse{}, err
	}
	defer response.Body.Close()

	head, err := decodeHeadResponse(response)
	if err != nil {
		return protocol.HeadResponse{}, err
	}

	if err := alpha.ValidateHeadResponse(head); err != nil {
		return protocol.HeadResponse{}, err
	}

	return head, nil
}

func (c *Client) Get(
	ctx context.Context,
	request protocol.GetRequest,
	options *RequestOptions,
) (protocol.GetResponse, error) {
	targetPath, err := selectorObjectPath(request.Selector)
	if err != nil {
		return protocol.GetResponse{}, err
	}

	query := url.Values{
		"tenant_id": []string{string(request.TenantID)},
	}
	if request.Preference != nil {
		query.Set("prefer", string(*request.Preference))
	}
	if request.Range != nil {
		query.Set("range_start", fmt.Sprintf("%d", request.Range.Start))
		query.Set("range_end", fmt.Sprintf("%d", request.Range.End))
	}

	response, err := c.doRequest(
		ctx,
		http.MethodGet,
		c.apiURL(targetPath, query),
		nil,
		"",
		options,
		true,
	)
	if err != nil {
		return protocol.GetResponse{}, err
	}

	if strings.Contains(response.Header.Get("Content-Type"), "application/json") {
		defer response.Body.Close()
		var meta protocol.GetResponseMeta
		if err := decodeJSONResponse(response, &meta); err != nil {
			return protocol.GetResponse{}, err
		}
		if err := alpha.ValidateGetResponseMeta(meta); err != nil {
			return protocol.GetResponse{}, err
		}
		return protocol.GetResponse{Meta: meta, Chunks: []protocol.GetChunk{}}, nil
	}

	reader := NewChunkStreamReader(response.Body)
	meta, err := reader.Meta()
	if err != nil {
		reader.Close()
		return protocol.GetResponse{}, err
	}
	if err := alpha.ValidateGetResponseMeta(meta); err != nil {
		reader.Close()
		return protocol.GetResponse{}, err
	}

	chunks := make([]protocol.GetChunk, 0, len(meta.ChunkDescriptors))
	for {
		chunk, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			reader.Close()
			return protocol.GetResponse{}, err
		}
		chunks = append(chunks, *chunk)
	}

	if err := reader.Close(); err != nil {
		return protocol.GetResponse{}, err
	}

	return protocol.GetResponse{
		Meta:   meta,
		Chunks: chunks,
	}, nil
}

func (c *Client) GetStream(
	ctx context.Context,
	request protocol.GetRequest,
	options *RequestOptions,
) (*ChunkStreamReader, error) {
	if request.Preference != nil && *request.Preference == protocol.GetPreferenceManifestOnly {
		return nil, &protocol.APIError{
			Category: protocol.ErrorCategoryUnsupported,
			Code:     "manifest_only_stream_not_supported",
			Message:  "manifest-only responses are JSON and cannot be consumed as a chunk stream",
		}
	}

	targetPath, err := selectorObjectPath(request.Selector)
	if err != nil {
		return nil, err
	}

	query := url.Values{
		"tenant_id": []string{string(request.TenantID)},
	}
	if request.Preference != nil {
		query.Set("prefer", string(*request.Preference))
	}
	if request.Range != nil {
		query.Set("range_start", fmt.Sprintf("%d", request.Range.Start))
		query.Set("range_end", fmt.Sprintf("%d", request.Range.End))
	}

	response, err := c.doRequest(
		ctx,
		http.MethodGet,
		c.apiURL(targetPath, query),
		nil,
		"",
		options,
		true,
	)
	if err != nil {
		return nil, err
	}

	if strings.Contains(response.Header.Get("Content-Type"), "application/json") {
		response.Body.Close()
		return nil, &protocol.APIError{
			Category: protocol.ErrorCategoryUnsupported,
			Code:     "unexpected_manifest_only_response",
			Message:  "gateway returned manifest-only JSON instead of chunk stream",
		}
	}

	return NewChunkStreamReader(response.Body), nil
}

func (c *Client) PutInit(
	ctx context.Context,
	request protocol.PutInitRequest,
	options *RequestOptions,
) (protocol.PutInitResponse, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return protocol.PutInitResponse{}, err
	}

	response, err := c.doRequest(
		ctx,
		http.MethodPost,
		c.apiURL("uploads", nil),
		payload,
		"application/json",
		options,
		true,
	)
	if err != nil {
		return protocol.PutInitResponse{}, err
	}
	defer response.Body.Close()

	var result protocol.PutInitResponse
	if err := decodeJSONResponse(response, &result); err != nil {
		return protocol.PutInitResponse{}, err
	}

	return result, nil
}

func (c *Client) PutChunk(
	ctx context.Context,
	request protocol.PutChunkRequest,
	payload []byte,
	options *RequestOptions,
) (protocol.PutChunkResponse, error) {
	query := url.Values{
		"tenant_id":        []string{string(request.TenantID)},
		"chunk_cid":        []string{request.ChunkCID},
		"chunk_offset":     []string{fmt.Sprintf("%d", request.ChunkOffset)},
		"chunk_length":     []string{fmt.Sprintf("%d", request.ChunkLength)},
		"content_encoding": []string{request.ContentEncoding},
	}

	response, err := c.doRequest(
		ctx,
		http.MethodPut,
		c.apiURL(fmt.Sprintf("uploads/%s/chunks/%d", request.SessionID, request.ChunkIndex), query),
		payload,
		"application/octet-stream",
		options,
		true,
	)
	if err != nil {
		return protocol.PutChunkResponse{}, err
	}
	defer response.Body.Close()

	var result protocol.PutChunkResponse
	if err := decodeJSONResponse(response, &result); err != nil {
		return protocol.PutChunkResponse{}, err
	}

	return result, nil
}

func (c *Client) PutCommit(
	ctx context.Context,
	request protocol.PutCommitRequest,
	options *RequestOptions,
) (protocol.PutCommitResponse, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return protocol.PutCommitResponse{}, err
	}

	response, err := c.doRequest(
		ctx,
		http.MethodPost,
		c.apiURL(fmt.Sprintf("uploads/%s:commit", request.SessionID), nil),
		payload,
		"application/json",
		options,
		true,
	)
	if err != nil {
		return protocol.PutCommitResponse{}, err
	}
	defer response.Body.Close()

	var result protocol.PutCommitResponse
	if err := decodeJSONResponse(response, &result); err != nil {
		return protocol.PutCommitResponse{}, err
	}

	return result, nil
}

func (c *Client) Resolve(
	ctx context.Context,
	request protocol.ResolveRequest,
	options *RequestOptions,
) (protocol.ResolveResponse, error) {
	query := url.Values{
		"tenant_id": []string{string(request.TenantID)},
	}
	if request.AtRevision != nil {
		query.Set("at_revision", fmt.Sprintf("%d", *request.AtRevision))
	}
	if request.IfRevision != nil {
		query.Set("if_revision", fmt.Sprintf("%d", *request.IfRevision))
	}

	response, err := c.doRequest(
		ctx,
		http.MethodGet,
		c.apiURL(namespaceResolvePath(request.Namespace, request.Path), query),
		nil,
		"",
		options,
		true,
	)
	if err != nil {
		return protocol.ResolveResponse{}, err
	}
	defer response.Body.Close()

	var result protocol.ResolveResponse
	if err := decodeJSONResponse(response, &result); err != nil {
		return protocol.ResolveResponse{}, err
	}
	return result, nil
}

func (c *Client) Bind(
	ctx context.Context,
	request protocol.BindRequest,
	options *RequestOptions,
) (protocol.BindResponse, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return protocol.BindResponse{}, err
	}
	response, err := c.doRequest(
		ctx,
		http.MethodPut,
		c.apiURL(namespaceBindPath(request.Namespace, request.Path), nil),
		payload,
		"application/json",
		options,
		true,
	)
	if err != nil {
		return protocol.BindResponse{}, err
	}
	defer response.Body.Close()

	var result protocol.BindResponse
	if err := decodeJSONResponse(response, &result); err != nil {
		return protocol.BindResponse{}, err
	}
	return result, nil
}

func (c *Client) Unbind(
	ctx context.Context,
	request protocol.UnbindRequest,
	options *RequestOptions,
) (protocol.UnbindResponse, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return protocol.UnbindResponse{}, err
	}
	response, err := c.doRequest(
		ctx,
		http.MethodDelete,
		c.apiURL(namespaceBindPath(request.Namespace, request.Path), nil),
		payload,
		"application/json",
		options,
		true,
	)
	if err != nil {
		return protocol.UnbindResponse{}, err
	}
	defer response.Body.Close()

	var result protocol.UnbindResponse
	if err := decodeJSONResponse(response, &result); err != nil {
		return protocol.UnbindResponse{}, err
	}
	return result, nil
}

func (c *Client) List(
	ctx context.Context,
	request protocol.ListRequest,
	options *RequestOptions,
) (protocol.ListResponse, error) {
	query := url.Values{
		"tenant_id": []string{string(request.TenantID)},
	}
	if request.Prefix != "" {
		query.Set("prefix", request.Prefix)
	}
	if request.Cursor != "" {
		query.Set("cursor", request.Cursor)
	}
	if request.Limit != nil {
		query.Set("limit", fmt.Sprintf("%d", *request.Limit))
	}
	if request.Recursive {
		query.Set("recursive", "true")
	}
	if request.IncludeTombstones {
		query.Set("include_tombstones", "true")
	}

	response, err := c.doRequest(
		ctx,
		http.MethodGet,
		c.apiURL(namespaceListPath(request.Namespace), query),
		nil,
		"",
		options,
		true,
	)
	if err != nil {
		return protocol.ListResponse{}, err
	}
	defer response.Body.Close()

	var result protocol.ListResponse
	if err := decodeJSONResponse(response, &result); err != nil {
		return protocol.ListResponse{}, err
	}
	return result, nil
}

func (c *Client) Subscribe(
	ctx context.Context,
	request protocol.SubscribeRequest,
	options *RequestOptions,
) (*EventStreamReader, error) {
	query := url.Values{
		"tenant_id": []string{string(request.TenantID)},
	}
	if request.Cursor != "" {
		query.Set("cursor", request.Cursor)
	}
	if request.FromSeq != nil {
		query.Set("from_seq", fmt.Sprintf("%d", *request.FromSeq))
	}
	if request.HeartbeatMS != nil {
		query.Set("heartbeat_ms", fmt.Sprintf("%d", *request.HeartbeatMS))
	}
	if request.BatchMax != nil {
		query.Set("batch_max", fmt.Sprintf("%d", *request.BatchMax))
	}
	if len(request.Filters) > 0 {
		filter := request.Filters[0]
		if filter.NamespacePrefix != "" {
			query.Set("namespace_prefix", filter.NamespacePrefix)
		}
		if filter.PathExact != "" {
			query.Set("path_exact", filter.PathExact)
		}
		if filter.ObjectCID != "" {
			query.Set("object_cid", filter.ObjectCID)
		}
		if filter.EventType != "" {
			query.Set("event_type", string(filter.EventType))
		}
	}

	response, err := c.doRequest(
		ctx,
		http.MethodGet,
		c.apiURL("events", query),
		nil,
		"",
		options,
		true,
	)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(response.Header.Get("Content-Type"), "application/x-hsp-events+jsonl") {
		response.Body.Close()
		return nil, &protocol.APIError{
			Category: protocol.ErrorCategoryValidation,
			Code:     "invalid_event_stream_content_type",
			Message:  "event stream response must use application/x-hsp-events+jsonl",
		}
	}
	return NewEventStreamReader(response.Body), nil
}

func (c *Client) bootstrapURL(query url.Values) string {
	root := &url.URL{
		Scheme: c.baseURL.Scheme,
		Host:   c.baseURL.Host,
		Path:   "/.well-known/hsp",
	}
	root.RawQuery = query.Encode()
	return root.String()
}

func (c *Client) apiURL(path string, query url.Values) string {
	target := c.baseURL.ResolveReference(&url.URL{Path: path})
	target.RawQuery = query.Encode()
	return target.String()
}

func (c *Client) doRequest(
	ctx context.Context,
	method string,
	target string,
	payload []byte,
	contentType string,
	options *RequestOptions,
	requiresAuth bool,
) (*http.Response, error) {
	newRequest := func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		if payload != nil && contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		return request, nil
	}

	if !requiresAuth {
		request, err := newRequest()
		if err != nil {
			return nil, err
		}
		response, err := c.transport.RoundTripOpt(request, http3.RoundTripOpt{})
		if err != nil {
			return nil, err
		}
		if response.StatusCode >= 400 {
			defer response.Body.Close()
			return nil, decodeAPIError(response)
		}
		return response, nil
	}

	authHeaders, err := c.authHeaders(ctx, options)
	if err != nil {
		return nil, err
	}

	request, err := newRequest()
	if err != nil {
		return nil, err
	}
	for key, values := range authHeaders {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	response, err := c.transport.RoundTripOpt(request, http3.RoundTripOpt{OnlyCachedConn: true})
	if err == http3.ErrNoCachedConn {
		if _, warmErr := c.ensureWarmConnection(ctx); warmErr != nil {
			return nil, warmErr
		}
		request, err = newRequest()
		if err != nil {
			return nil, err
		}
		for key, values := range authHeaders {
			for _, value := range values {
				request.Header.Add(key, value)
			}
		}
		response, err = c.transport.RoundTripOpt(request, http3.RoundTripOpt{OnlyCachedConn: true})
	}
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		defer response.Body.Close()
		return nil, decodeAPIError(response)
	}
	return response, nil
}

func (c *Client) authHeaders(
	ctx context.Context,
	options *RequestOptions,
) (http.Header, error) {
	token := c.capabilityToken
	if options != nil && options.CapabilityToken != "" {
		token = options.CapabilityToken
	}
	if token == "" {
		return nil, &protocol.APIError{
			Category: protocol.ErrorCategoryAuth,
			Code:     "missing_capability_token",
			Message:  "capability token is required for authenticated gateway operations",
		}
	}

	conn, err := c.ensureWarmConnection(ctx)
	if err != nil {
		return nil, err
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	tlsState := conn.ConnectionState().TLS
	proof, err := tlsState.ExportKeyingMaterial(
		tlsExporterLabel,
		[]byte(nonce),
		32,
	)
	if err != nil {
		return nil, err
	}

	headers := make(http.Header)
	headers.Set("x-hsp-capability", token)
	headers.Set("x-hsp-channel-binding-kind", "tls-exporter")
	headers.Set("x-hsp-channel-binding-nonce", nonce)
	headers.Set("x-hsp-channel-binding-proof", base64.RawURLEncoding.EncodeToString(proof))
	return headers, nil
}

func (c *Client) ensureWarmConnection(ctx context.Context) (*quic.Conn, error) {
	key := connectionKey(c.baseURL)
	if conn := c.tracker.load(key); conn != nil {
		return conn, nil
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL("info", nil), nil)
	if err != nil {
		return nil, err
	}
	response, err := c.transport.RoundTripOpt(request, http3.RoundTripOpt{})
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		defer response.Body.Close()
		return nil, decodeAPIError(response)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()

	conn := c.tracker.load(key)
	if conn == nil {
		return nil, &protocol.APIError{
			Category: protocol.ErrorCategoryAuth,
			Code:     "missing_cached_connection",
			Message:  "HTTP/3 transport did not retain the warmed connection",
		}
	}
	return conn, nil
}

func decodeJSONResponse(response *http.Response, target any) error {
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return err
	}
	return nil
}

func decodeAPIError(response *http.Response) error {
	data, _ := io.ReadAll(response.Body)
	var apiError protocol.APIError
	if len(data) > 0 && json.Unmarshal(data, &apiError) == nil && apiError.Code != "" {
		if apiError.Message == "" {
			apiError.Message = strings.TrimSpace(string(data))
		}
		return &apiError
	}

	code := response.Header.Get("x-hsp-error-code")
	category := protocol.ErrorCategory(response.Header.Get("x-hsp-error-category"))
	message := http.StatusText(response.StatusCode)
	if strings.TrimSpace(string(data)) != "" {
		message = strings.TrimSpace(string(data))
	}
	if code == "" {
		code = "unexpected_http_status"
	}
	if category == "" {
		category = protocol.ErrorCategoryValidation
	}
	return &protocol.APIError{
		Category: category,
		Code:     code,
		Message:  message,
	}
}

func decodeHeadResponse(response *http.Response) (protocol.HeadResponse, error) {
	logicalSize, err := parseUintHeader(response, "x-hsp-logical-size")
	if err != nil {
		return protocol.HeadResponse{}, err
	}
	storedSize, err := parseUintHeader(response, "x-hsp-stored-size")
	if err != nil {
		return protocol.HeadResponse{}, err
	}
	sizeBytes := parseOptionalUintHeader(response, "x-hsp-size-bytes", logicalSize)
	ciphertextSizeBytes := parseOptionalUintHeader(response, "x-hsp-ciphertext-size-bytes", storedSize)
	createdAtMS := parseOptionalUintHeader(response, "x-hsp-created-at-ms", 0)
	var resolvedRevision *uint64
	if response.Header.Get("x-hsp-resolved-revision") != "" {
		value, err := parseUintHeader(response, "x-hsp-resolved-revision")
		if err != nil {
			return protocol.HeadResponse{}, err
		}
		resolvedRevision = &value
	}
	objectCID := response.Header.Get("x-hsp-object-cid")
	cid := response.Header.Get("x-hsp-cid")
	if cid == "" {
		cid = objectCID
	}
	integrityHash := response.Header.Get("x-hsp-integrity-hash")
	if integrityHash == "" {
		integrityHash = objectCID
	}

	return protocol.HeadResponse{
		Exists:                          !strings.EqualFold(response.Header.Get("x-hsp-exists"), "false"),
		Deleted:                         strings.EqualFold(response.Header.Get("x-hsp-deleted"), "true"),
		CID:                             cid,
		ObjectCID:                       objectCID,
		ManifestCID:                     response.Header.Get("x-hsp-manifest-cid"),
		IntegrityHash:                   integrityHash,
		StorageClass:                    response.Header.Get("x-hsp-storage-class"),
		ResolvedNamespace:               response.Header.Get("x-hsp-resolved-namespace"),
		ResolvedPath:                    response.Header.Get("x-hsp-resolved-path"),
		ResolvedRevision:                resolvedRevision,
		ResolvedRecordCID:               response.Header.Get("x-hsp-resolved-record-cid"),
		SizeBytes:                       sizeBytes,
		CiphertextSizeBytes:             ciphertextSizeBytes,
		LogicalSize:                     logicalSize,
		StoredSize:                      storedSize,
		ContentType:                     response.Header.Get("x-hsp-content-type"),
		CreatedAtMS:                     createdAtMS,
		EncryptionProfileID:             protocol.EncryptionProfileID(response.Header.Get("x-hsp-encryption-profile-id")),
		KeyPolicyID:                     protocol.KeyPolicyID(response.Header.Get("x-hsp-key-policy-id")),
		MetadataVisibility:              protocol.VisibilityMode(response.Header.Get("x-hsp-metadata-visibility")),
		ServerVisibleMetadata:           map[string]string{},
		EncryptedClientMetadataRedacted: strings.EqualFold(response.Header.Get("x-hsp-encrypted-client-metadata-redacted"), "true"),
	}, nil
}

func parseUintHeader(response *http.Response, key string) (uint64, error) {
	value := response.Header.Get(key)
	if value == "" {
		return 0, &protocol.APIError{
			Category: protocol.ErrorCategoryValidation,
			Code:     "missing_response_header",
			Message:  fmt.Sprintf("%s header is required", key),
		}
	}

	var parsed uint64
	if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil {
		return 0, &protocol.APIError{
			Category: protocol.ErrorCategoryValidation,
			Code:     "invalid_response_header",
			Message:  fmt.Sprintf("%s header is invalid", key),
		}
	}
	return parsed, nil
}

func parseOptionalUintHeader(response *http.Response, key string, fallback uint64) uint64 {
	if response.Header.Get(key) == "" {
		return fallback
	}
	value, err := parseUintHeader(response, key)
	if err != nil {
		return fallback
	}
	return value
}

func selectorObjectPath(selector protocol.ObjectSelector) (string, error) {
	switch selector.Kind {
	case protocol.ObjectSelectorKindCID:
		if selector.CID == "" {
			return "", &protocol.APIError{
				Category: protocol.ErrorCategoryValidation,
				Code:     "missing_cid_selector",
				Message:  "cid selector must include cid",
			}
		}
		return "objects/cid/" + selector.CID, nil
	case protocol.ObjectSelectorKindNamespace:
		if selector.Namespace == "" || selector.Path == "" {
			return "", &protocol.APIError{
				Category: protocol.ErrorCategoryValidation,
				Code:     "missing_namespace_selector",
				Message:  "namespace selector must include namespace and path",
			}
		}
		return namespaceObjectPath(selector.Namespace, selector.Path), nil
	default:
		return "", &protocol.APIError{
			Category: protocol.ErrorCategoryValidation,
			Code:     "invalid_selector_kind",
			Message:  "selector kind is invalid",
		}
	}
}

func namespaceObjectPath(namespace string, path string) string {
	return fmt.Sprintf("objects/namespace/%s/%s", url.PathEscape(namespace), path)
}

func namespaceResolvePath(namespace string, path string) string {
	return fmt.Sprintf("namespaces/%s/resolve/%s", url.PathEscape(namespace), path)
}

func namespaceBindPath(namespace string, path string) string {
	return fmt.Sprintf("namespaces/%s/bind/%s", url.PathEscape(namespace), path)
}

func namespaceListPath(namespace string) string {
	return fmt.Sprintf("namespaces/%s/list", url.PathEscape(namespace))
}

func connectionKey(target *url.URL) string {
	port := target.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(target.Hostname(), port)
}

func (t *connectionTracker) store(key string, conn *quic.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conns[key] = conn
}

func (t *connectionTracker) load(key string) *quic.Conn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conns[key]
}
