package nativebeta

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/loxar/hsp/sdk/go/alpha"
	"github.com/loxar/hsp/sdk/go/protocol"
	"github.com/quic-go/quic-go"
)

const (
	frameSettings  byte = 0x01
	frameError     byte = 0x02
	frameNotice    byte = 0x03
	frameReqHeader byte = 0x10
	frameResHeader byte = 0x11
	frameData      byte = 0x12
	frameEnd       byte = 0x13
	frameEvent     byte = 0x14
	frameAuth      byte = 0x16
	frameGoAway    byte = 0x17

	tlsExporterLabel = "EXPORTER-HSP-Channel-Binding-v1"
)

type ClientOptions struct {
	Address         string
	Authority       string
	CapabilityToken string
	TLSConfig       *tls.Config
}

type RequestOptions struct {
	CapabilityToken string
}

type Client struct {
	conn            *quic.Conn
	capabilityToken string
	settings        protocol.SettingsFrame
}

type Subscription struct {
	stream *quic.Stream
	cursor string
}

func NewClient(ctx context.Context, options ClientOptions) (*Client, error) {
	if options.Address == "" {
		return nil, validationError("missing_address", "native endpoint address is required")
	}
	if options.Authority == "" {
		return nil, validationError("missing_authority", "native endpoint authority is required")
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"hsp/1"},
		ServerName: options.Authority,
	}
	if options.TLSConfig != nil {
		tlsConfig = options.TLSConfig.Clone()
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = tls.VersionTLS13
		}
		if len(tlsConfig.NextProtos) == 0 {
			tlsConfig.NextProtos = []string{"hsp/1"}
		}
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = options.Authority
		}
	}

	conn, err := quic.DialAddr(ctx, options.Address, tlsConfig, nil)
	if err != nil {
		return nil, err
	}

	settingsStream, err := conn.AcceptUniStream(ctx)
	if err != nil {
		conn.CloseWithError(0, "settings_failed")
		return nil, err
	}

	frameType, payload, err := readFrame(settingsStream)
	if err != nil {
		conn.CloseWithError(0, "settings_failed")
		return nil, err
	}
	if frameType != frameSettings {
		conn.CloseWithError(0, "settings_failed")
		return nil, validationError("missing_settings_frame", "native connection must start with a SETTINGS frame")
	}

	var settings protocol.SettingsFrame
	if err := decodeCBOR(payload, &settings); err != nil {
		conn.CloseWithError(0, "settings_failed")
		return nil, err
	}
	if err := alpha.ValidateSettingsFrame(settings); err != nil {
		conn.CloseWithError(0, "settings_failed")
		return nil, err
	}

	return &Client{
		conn:            conn,
		capabilityToken: options.CapabilityToken,
		settings:        settings,
	}, nil
}

func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.CloseWithError(0, "shutdown")
}

func (c *Client) Settings() protocol.SettingsFrame {
	return c.settings
}

func (c *Client) Info(ctx context.Context) (protocol.InfoResponse, error) {
	header, frames, err := c.executeRequest(ctx, protocol.OperationInfo, protocol.PayloadModeJSON, map[string]any{}, nil, nil, false)
	if err != nil {
		return protocol.InfoResponse{}, err
	}
	if header.PayloadMode == nil || *header.PayloadMode != protocol.PayloadModeJSON || len(frames) != 1 {
		return protocol.InfoResponse{}, validationError("invalid_info_response", "INFO must return a single JSON payload")
	}

	var info protocol.InfoResponse
	if err := json.Unmarshal(frames[0], &info); err != nil {
		return protocol.InfoResponse{}, err
	}
	return info, nil
}

func (c *Client) Head(
	ctx context.Context,
	request protocol.HeadRequest,
	options *RequestOptions,
) (protocol.HeadResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return protocol.HeadResponse{}, err
	}

	header, frames, err := c.executeRequest(ctx, protocol.OperationHead, protocol.PayloadModeJSON, map[string]any{}, body, options, true)
	if err != nil {
		return protocol.HeadResponse{}, err
	}
	if header.PayloadMode == nil || *header.PayloadMode != protocol.PayloadModeJSON || len(frames) != 1 {
		return protocol.HeadResponse{}, validationError("invalid_head_response", "HEAD must return a single JSON payload")
	}

	var head protocol.HeadResponse
	if err := json.Unmarshal(frames[0], &head); err != nil {
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
	body, err := json.Marshal(request)
	if err != nil {
		return protocol.GetResponse{}, err
	}

	header, frames, err := c.executeRequest(ctx, protocol.OperationGet, protocol.PayloadModeJSON, map[string]any{}, body, options, true)
	if err != nil {
		return protocol.GetResponse{}, err
	}
	if header.PayloadMode == nil {
		return protocol.GetResponse{}, validationError("missing_get_payload_mode", "GET response is missing payload mode")
	}

	switch *header.PayloadMode {
	case protocol.PayloadModeJSON:
		if len(frames) != 1 {
			return protocol.GetResponse{}, validationError("invalid_get_json_response", "manifest-only GET must return a single JSON payload")
		}
		var meta protocol.GetResponseMeta
		if err := json.Unmarshal(frames[0], &meta); err != nil {
			return protocol.GetResponse{}, err
		}
		if err := alpha.ValidateGetResponseMeta(meta); err != nil {
			return protocol.GetResponse{}, err
		}
		return protocol.GetResponse{Meta: meta, Chunks: []protocol.GetChunk{}}, nil
	case protocol.PayloadModeChunkStream:
		meta, err := decodeMetaFromHeader(header)
		if err != nil {
			return protocol.GetResponse{}, err
		}
		if err := alpha.ValidateGetResponseMeta(meta); err != nil {
			return protocol.GetResponse{}, err
		}
		chunks := make([]protocol.GetChunk, 0, len(frames))
		for index, payload := range frames {
			if index >= len(meta.ChunkDescriptors) {
				return protocol.GetResponse{}, validationError("chunk_descriptor_mismatch", "GET returned more DATA frames than chunk descriptors")
			}
			chunks = append(chunks, protocol.GetChunk{
				Descriptor: meta.ChunkDescriptors[index],
				Bytes:      append([]byte(nil), payload...),
			})
		}
		return protocol.GetResponse{Meta: meta, Chunks: chunks}, nil
	default:
		return protocol.GetResponse{}, validationError("unsupported_get_payload_mode", "unsupported GET payload mode")
	}
}

func (c *Client) PutInit(
	ctx context.Context,
	request protocol.PutInitRequest,
	options *RequestOptions,
) (protocol.PutInitResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return protocol.PutInitResponse{}, err
	}

	header, frames, err := c.executeRequest(ctx, protocol.OperationPutInit, protocol.PayloadModeJSON, map[string]any{}, body, options, true)
	if err != nil {
		return protocol.PutInitResponse{}, err
	}
	if header.PayloadMode == nil || *header.PayloadMode != protocol.PayloadModeJSON || len(frames) != 1 {
		return protocol.PutInitResponse{}, validationError("invalid_put_init_response", "PUT_INIT must return a single JSON payload")
	}

	var response protocol.PutInitResponse
	if err := json.Unmarshal(frames[0], &response); err != nil {
		return protocol.PutInitResponse{}, err
	}
	return response, nil
}

func (c *Client) PutChunk(
	ctx context.Context,
	request protocol.PutChunkRequest,
	payload []byte,
	options *RequestOptions,
) (protocol.PutChunkResponse, error) {
	params := map[string]any{
		"tenant_id":        string(request.TenantID),
		"session_id":       request.SessionID,
		"chunk_index":      request.ChunkIndex,
		"chunk_cid":        request.ChunkCID,
		"chunk_offset":     request.ChunkOffset,
		"chunk_length":     request.ChunkLength,
		"content_encoding": request.ContentEncoding,
	}

	header, frames, err := c.executeRequest(ctx, protocol.OperationPutChunk, protocol.PayloadModeRaw, params, payload, options, true)
	if err != nil {
		return protocol.PutChunkResponse{}, err
	}
	if header.PayloadMode == nil || *header.PayloadMode != protocol.PayloadModeJSON || len(frames) != 1 {
		return protocol.PutChunkResponse{}, validationError("invalid_put_chunk_response", "PUT_CHUNK must return a single JSON payload")
	}

	var response protocol.PutChunkResponse
	if err := json.Unmarshal(frames[0], &response); err != nil {
		return protocol.PutChunkResponse{}, err
	}
	return response, nil
}

func (c *Client) PutCommit(
	ctx context.Context,
	request protocol.PutCommitRequest,
	options *RequestOptions,
) (protocol.PutCommitResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return protocol.PutCommitResponse{}, err
	}

	header, frames, err := c.executeRequest(ctx, protocol.OperationPutCommit, protocol.PayloadModeJSON, map[string]any{}, body, options, true)
	if err != nil {
		return protocol.PutCommitResponse{}, err
	}
	if header.PayloadMode == nil || *header.PayloadMode != protocol.PayloadModeJSON || len(frames) != 1 {
		return protocol.PutCommitResponse{}, validationError("invalid_put_commit_response", "PUT_COMMIT must return a single JSON payload")
	}

	var response protocol.PutCommitResponse
	if err := json.Unmarshal(frames[0], &response); err != nil {
		return protocol.PutCommitResponse{}, err
	}
	return response, nil
}

func (c *Client) Resolve(
	ctx context.Context,
	request protocol.ResolveRequest,
	options *RequestOptions,
) (protocol.ResolveResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return protocol.ResolveResponse{}, err
	}

	header, frames, err := c.executeRequest(ctx, protocol.OperationResolve, protocol.PayloadModeJSON, map[string]any{}, body, options, true)
	if err != nil {
		return protocol.ResolveResponse{}, err
	}
	if header.PayloadMode == nil || *header.PayloadMode != protocol.PayloadModeJSON || len(frames) != 1 {
		return protocol.ResolveResponse{}, validationError("invalid_resolve_response", "RESOLVE must return a single JSON payload")
	}

	var response protocol.ResolveResponse
	if err := json.Unmarshal(frames[0], &response); err != nil {
		return protocol.ResolveResponse{}, err
	}
	return response, nil
}

func (c *Client) Bind(
	ctx context.Context,
	request protocol.BindRequest,
	options *RequestOptions,
) (protocol.BindResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return protocol.BindResponse{}, err
	}

	header, frames, err := c.executeRequest(ctx, protocol.OperationBind, protocol.PayloadModeJSON, map[string]any{}, body, options, true)
	if err != nil {
		return protocol.BindResponse{}, err
	}
	if header.PayloadMode == nil || *header.PayloadMode != protocol.PayloadModeJSON || len(frames) != 1 {
		return protocol.BindResponse{}, validationError("invalid_bind_response", "BIND must return a single JSON payload")
	}

	var response protocol.BindResponse
	if err := json.Unmarshal(frames[0], &response); err != nil {
		return protocol.BindResponse{}, err
	}
	return response, nil
}

func (c *Client) Unbind(
	ctx context.Context,
	request protocol.UnbindRequest,
	options *RequestOptions,
) (protocol.UnbindResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return protocol.UnbindResponse{}, err
	}

	header, frames, err := c.executeRequest(ctx, protocol.OperationUnbind, protocol.PayloadModeJSON, map[string]any{}, body, options, true)
	if err != nil {
		return protocol.UnbindResponse{}, err
	}
	if header.PayloadMode == nil || *header.PayloadMode != protocol.PayloadModeJSON || len(frames) != 1 {
		return protocol.UnbindResponse{}, validationError("invalid_unbind_response", "UNBIND must return a single JSON payload")
	}

	var response protocol.UnbindResponse
	if err := json.Unmarshal(frames[0], &response); err != nil {
		return protocol.UnbindResponse{}, err
	}
	return response, nil
}

func (c *Client) List(
	ctx context.Context,
	request protocol.ListRequest,
	options *RequestOptions,
) (protocol.ListResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return protocol.ListResponse{}, err
	}

	header, frames, err := c.executeRequest(ctx, protocol.OperationList, protocol.PayloadModeJSON, map[string]any{}, body, options, true)
	if err != nil {
		return protocol.ListResponse{}, err
	}
	if header.PayloadMode == nil || *header.PayloadMode != protocol.PayloadModeJSON || len(frames) != 1 {
		return protocol.ListResponse{}, validationError("invalid_list_response", "LIST must return a single JSON payload")
	}

	var response protocol.ListResponse
	if err := json.Unmarshal(frames[0], &response); err != nil {
		return protocol.ListResponse{}, err
	}
	return response, nil
}

func (c *Client) Subscribe(
	ctx context.Context,
	request protocol.SubscribeRequest,
	options *RequestOptions,
) (*Subscription, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	applyDeadline(stream, ctx)

	if err := c.writeAuthFrame(stream, options); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}

	header := protocol.ReqHeader{
		Version:       1,
		Operation:     protocol.OperationSubscribe,
		RequestID:     nil,
		PayloadMode:   payloadModePtr(protocol.PayloadModeJSON),
		PayloadLength: uint64Ptr(uint64(len(body))),
		Params:        map[string]any{},
		Extensions:    map[string]any{},
	}
	if err := writeCBORFrame(stream, frameReqHeader, header); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	if len(body) > 0 {
		if err := writeFrame(stream, frameData, body); err != nil {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			return nil, err
		}
	}
	if err := writeFrame(stream, frameEnd, nil); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	if err := stream.Close(); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}

	frameType, payload, err := readFrame(stream)
	if err != nil {
		stream.CancelRead(0)
		return nil, err
	}
	switch frameType {
	case frameError:
		var wireError protocol.WireErrorFrame
		if err := decodeCBOR(payload, &wireError); err != nil {
			stream.CancelRead(0)
			return nil, err
		}
		stream.CancelRead(0)
		return nil, wireAPIError(wireError)
	case frameResHeader:
		var responseHeader protocol.ResHeader
		if err := decodeCBOR(payload, &responseHeader); err != nil {
			stream.CancelRead(0)
			return nil, err
		}
		cursor, _ := stringMeta(responseHeader.Meta, "cursor")
		return &Subscription{
			stream: stream,
			cursor: cursor,
		}, nil
	default:
		stream.CancelRead(0)
		return nil, validationError("invalid_subscribe_response", fmt.Sprintf("unexpected first SUBSCRIBE frame type 0x%02x", frameType))
	}
}

func (s *Subscription) Cursor() string {
	if s == nil {
		return ""
	}
	return s.cursor
}

func (s *Subscription) Next() (*protocol.SubscribeEnvelope, error) {
	if s == nil || s.stream == nil {
		return nil, io.EOF
	}

	frameType, payload, err := readFrame(s.stream)
	if err != nil {
		return nil, err
	}
	switch frameType {
	case frameEvent:
		var event protocol.EventRecord
		if err := decodeCBOR(payload, &event); err != nil {
			return nil, err
		}
		return &protocol.SubscribeEnvelope{
			Kind:  protocol.SubscribeEnvelopeEvent,
			Event: &event,
		}, nil
	case frameNotice:
		var notice protocol.NoticeFrame
		if err := decodeCBOR(payload, &notice); err != nil {
			return nil, err
		}
		return &protocol.SubscribeEnvelope{
			Kind:   protocol.SubscribeEnvelopeNotice,
			Notice: &notice,
		}, nil
	case frameGoAway, frameEnd:
		return nil, io.EOF
	case frameError:
		var wireError protocol.WireErrorFrame
		if err := decodeCBOR(payload, &wireError); err != nil {
			return nil, err
		}
		return nil, wireAPIError(wireError)
	default:
		return nil, validationError("invalid_subscribe_frame", fmt.Sprintf("unexpected SUBSCRIBE frame type 0x%02x", frameType))
	}
}

func (s *Subscription) Close() error {
	if s == nil || s.stream == nil {
		return nil
	}
	s.stream.CancelRead(0)
	s.stream.CancelWrite(0)
	return nil
}

func (c *Client) executeRequest(
	ctx context.Context,
	operation protocol.OperationName,
	payloadMode protocol.PayloadMode,
	params map[string]any,
	body []byte,
	options *RequestOptions,
	requiresAuth bool,
) (*protocol.ResHeader, [][]byte, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, nil, err
	}
	applyDeadline(stream, ctx)
	defer stream.CancelRead(0)

	if requiresAuth {
		if err := c.writeAuthFrame(stream, options); err != nil {
			stream.CancelWrite(0)
			return nil, nil, err
		}
	}

	header := protocol.ReqHeader{
		Version:       1,
		Operation:     operation,
		RequestID:     nil,
		PayloadMode:   payloadModePtr(payloadMode),
		PayloadLength: nil,
		Params:        params,
		Extensions:    map[string]any{},
	}
	if len(body) > 0 {
		header.PayloadLength = uint64Ptr(uint64(len(body)))
	}
	if header.Params == nil {
		header.Params = map[string]any{}
	}

	if err := writeCBORFrame(stream, frameReqHeader, header); err != nil {
		stream.CancelWrite(0)
		return nil, nil, err
	}
	if len(body) > 0 {
		if err := writeFrame(stream, frameData, body); err != nil {
			stream.CancelWrite(0)
			return nil, nil, err
		}
	}
	if err := writeFrame(stream, frameEnd, nil); err != nil {
		stream.CancelWrite(0)
		return nil, nil, err
	}
	if err := stream.Close(); err != nil {
		stream.CancelWrite(0)
		return nil, nil, err
	}

	frameType, payload, err := readFrame(stream)
	if err != nil {
		return nil, nil, err
	}
	switch frameType {
	case frameError:
		var wireError protocol.WireErrorFrame
		if err := decodeCBOR(payload, &wireError); err != nil {
			return nil, nil, err
		}
		return nil, nil, wireAPIError(wireError)
	case frameResHeader:
		var responseHeader protocol.ResHeader
		if err := decodeCBOR(payload, &responseHeader); err != nil {
			return nil, nil, err
		}
		dataFrames, err := collectDataFrames(stream)
		if err != nil {
			return nil, nil, err
		}
		return &responseHeader, dataFrames, nil
	default:
		return nil, nil, validationError("invalid_response_frame", fmt.Sprintf("unexpected first response frame type 0x%02x", frameType))
	}
}

func (c *Client) writeAuthFrame(stream *quic.Stream, options *RequestOptions) error {
	token := c.capabilityToken
	if options != nil && options.CapabilityToken != "" {
		token = options.CapabilityToken
	}
	if token == "" {
		return &protocol.APIError{
			Category: protocol.ErrorCategoryAuth,
			Code:     "missing_capability_token",
			Message:  "capability token is required for authenticated native operations",
		}
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	state := c.conn.ConnectionState().TLS
	proof, err := state.ExportKeyingMaterial(tlsExporterLabel, []byte(nonce), 32)
	if err != nil {
		return err
	}

	return writeCBORFrame(stream, frameAuth, protocol.AuthFrame{
		TokenBase64: token,
		ChannelBinding: protocol.ChannelBindingProof{
			BindingKind: "tls-exporter",
			ProofBase64: base64.RawURLEncoding.EncodeToString(proof),
			Nonce:       nonce,
		},
	})
}

func collectDataFrames(stream *quic.Stream) ([][]byte, error) {
	frames := make([][]byte, 0, 1)
	for {
		frameType, payload, err := readFrame(stream)
		if err != nil {
			return nil, err
		}
		switch frameType {
		case frameData:
			frames = append(frames, append([]byte(nil), payload...))
		case frameEnd:
			return frames, nil
		case frameError:
			var wireError protocol.WireErrorFrame
			if err := decodeCBOR(payload, &wireError); err != nil {
				return nil, err
			}
			return nil, wireAPIError(wireError)
		default:
			return nil, validationError("invalid_response_sequence", fmt.Sprintf("unexpected response frame type 0x%02x", frameType))
		}
	}
}

func decodeMetaFromHeader(header *protocol.ResHeader) (protocol.GetResponseMeta, error) {
	if header == nil {
		return protocol.GetResponseMeta{}, validationError("missing_get_header", "GET chunk-stream response header is missing")
	}
	raw, ok := header.Meta["get_meta"]
	if !ok {
		return protocol.GetResponseMeta{}, validationError("missing_get_meta", "chunk-stream GET is missing get_meta in response header")
	}
	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return protocol.GetResponseMeta{}, err
	}
	var meta protocol.GetResponseMeta
	if err := json.Unmarshal(jsonBytes, &meta); err != nil {
		return protocol.GetResponseMeta{}, err
	}
	return meta, nil
}

func readFrame(reader io.Reader) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[1:])
	payload := make([]byte, int(length))
	if length > 0 {
		if _, err := io.ReadFull(reader, payload); err != nil {
			return 0, nil, err
		}
	}
	return header[0], payload, nil
}

func writeFrame(writer io.Writer, frameType byte, payload []byte) error {
	header := make([]byte, 5)
	header[0] = frameType
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := writer.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func writeCBORFrame(writer io.Writer, frameType byte, value any) error {
	payload, err := cbor.Marshal(value)
	if err != nil {
		return err
	}
	return writeFrame(writer, frameType, payload)
}

func decodeCBOR(payload []byte, target any) error {
	return cbor.Unmarshal(payload, target)
}

func applyDeadline(stream *quic.Stream, ctx context.Context) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
		return
	}
	_ = stream.SetDeadline(time.Time{})
}

func validationError(code string, message string) error {
	return &protocol.APIError{
		Category: protocol.ErrorCategoryValidation,
		Code:     code,
		Message:  message,
	}
}

func wireAPIError(wire protocol.WireErrorFrame) error {
	return &protocol.APIError{
		Category: wire.Category,
		Code:     wire.Code,
		Message:  wire.Message,
	}
}

func payloadModePtr(value protocol.PayloadMode) *protocol.PayloadMode {
	return &value
}

func uint64Ptr(value uint64) *uint64 {
	return &value
}

func stringMeta(meta map[string]any, key string) (string, bool) {
	if meta == nil {
		return "", false
	}
	value, ok := meta[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}
