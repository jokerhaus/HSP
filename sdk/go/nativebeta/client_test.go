package nativebeta

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/loxar/hsp/sdk/go/protocol"
	"github.com/quic-go/quic-go"
)

type mockRequest struct {
	Auth   *protocol.AuthFrame
	Header protocol.ReqHeader
	Body   []byte
}

func TestClientInfoHeadAndResolveOverNativeBeta(t *testing.T) {
	server, shutdown := startMockNativeServer(t, func(t *testing.T, request mockRequest, stream *quic.Stream) {
		switch request.Header.Operation {
		case protocol.OperationInfo:
			writeJSONResponse(t, stream, protocol.PublicMultiTenantInfoResponse())
		case protocol.OperationHead:
			if request.Auth == nil || request.Auth.TokenBase64 != "token-123" {
				t.Fatalf("expected auth token on HEAD request, got %+v", request.Auth)
			}
			var headRequest protocol.HeadRequest
			if err := json.Unmarshal(request.Body, &headRequest); err != nil {
				t.Fatalf("decode head request: %v", err)
			}
			if headRequest.Selector.Kind != protocol.ObjectSelectorKindNamespace {
				t.Fatalf("unexpected selector kind: %s", headRequest.Selector.Kind)
			}
			writeJSONResponse(t, stream, protocol.HeadResponse{
				ObjectCID:                       "sha256-manifest",
				ManifestCID:                     "sha256-manifest",
				StorageClass:                    "hot",
				ResolvedNamespace:               "docs",
				ResolvedPath:                    "reports/q1",
				ResolvedRevision:                ptrUint64(1),
				ResolvedRecordCID:               "sha256-record",
				LogicalSize:                     4,
				StoredSize:                      4,
				ContentType:                     "application/octet-stream",
				MetadataVisibility:              protocol.VisibilityModeSplit,
				ServerVisibleMetadata:           map[string]string{"content-language": "ru"},
				EncryptedClientMetadataRedacted: true,
			})
		case protocol.OperationResolve:
			writeJSONResponse(t, stream, protocol.ResolveResponse{
				Revision:    1,
				TargetCID:   "sha256-manifest",
				ManifestCID: "sha256-manifest",
				RecordCID:   "sha256-record",
				Metadata:    map[string]string{"label": "quarterly"},
				Tombstone:   false,
			})
		default:
			t.Fatalf("unexpected operation: %s", request.Header.Operation)
		}
	})
	defer shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewClient(ctx, ClientOptions{
		Address:         server.address,
		Authority:       "localhost",
		CapabilityToken: "token-123",
		TLSConfig:       server.tlsConfig,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if client.Settings().ServerInstanceID != "mock-native-beta" {
		t.Fatalf("unexpected settings: %+v", client.Settings())
	}

	info, err := client.Info(ctx)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if !info.StorageEncryptionRequired {
		t.Fatalf("expected storage encryption requirement")
	}

	head, err := client.Head(ctx, protocol.HeadRequest{
		TenantID: "tenant-alpha",
		Selector: protocol.NamespaceSelector("docs", "reports/q1"),
	}, nil)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if head.ResolvedNamespace != "docs" || head.ResolvedPath != "reports/q1" {
		t.Fatalf("unexpected head response: %+v", head)
	}

	resolveResponse, err := client.Resolve(ctx, protocol.ResolveRequest{
		TenantID:  "tenant-alpha",
		Namespace: "docs",
		Path:      "reports/q1",
	}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolveResponse.TargetCID != "sha256-manifest" {
		t.Fatalf("unexpected resolve response: %+v", resolveResponse)
	}
}

func TestClientNamespaceListGetSubscribeAndUnbindOverNativeBeta(t *testing.T) {
	server, shutdown := startMockNativeServer(t, func(t *testing.T, request mockRequest, stream *quic.Stream) {
		switch request.Header.Operation {
		case protocol.OperationGet:
			writeChunkStreamOrJSONResponse(t, stream, protocol.GetResponseMeta{
				ObjectCID:                       "sha256-manifest",
				ManifestCID:                     "sha256-manifest",
				StorageClass:                    "hot",
				ResolvedNamespace:               "docs",
				ResolvedPath:                    "reports/q1",
				ResolvedRevision:                ptrUint64(1),
				ResolvedRecordCID:               "sha256-record",
				LogicalSize:                     4,
				StoredSize:                      4,
				ContentType:                     "application/octet-stream",
				MetadataVisibility:              protocol.VisibilityModeSplit,
				ServerVisibleMetadata:           map[string]string{"content-language": "ru"},
				EncryptedClientMetadataRedacted: true,
				Preference:                      protocol.GetPreferenceManifestOnly,
			}, nil)
		case protocol.OperationBind:
			writeJSONResponse(t, stream, protocol.BindResponse{
				Revision:  1,
				RecordCID: "sha256-record",
				EventSeq:  2,
			})
		case protocol.OperationList:
			writeJSONResponse(t, stream, protocol.ListResponse{
				Items: []protocol.ListItem{
					{
						Namespace:   "docs",
						Path:        "reports/q1",
						TargetCID:   "sha256-manifest",
						ManifestCID: "sha256-manifest",
						Revision:    1,
						RecordCID:   "sha256-record",
						Metadata:    map[string]string{"label": "quarterly"},
						Tombstone:   false,
					},
				},
				NamespaceRevisionSnapshot: 1,
			})
		case protocol.OperationSubscribe:
			writeSubscribeResponse(t, stream, "cursor-1", protocol.EventRecord{
				Version:     1,
				Seq:         2,
				AtMS:        2,
				EventType:   protocol.EventTypeNamespaceBound,
				SubjectKind: "namespace",
				Namespace:   "docs",
				Path:        "reports/q1",
				CID:         "sha256-manifest",
				Revision:    ptrUint64(1),
				Payload:     map[string]string{"label": "quarterly"},
			})
		case protocol.OperationUnbind:
			writeJSONResponse(t, stream, protocol.UnbindResponse{
				Revision:  2,
				RecordCID: "sha256-record-2",
				EventSeq:  3,
				Tombstone: true,
			})
		default:
			t.Fatalf("unexpected operation: %s", request.Header.Operation)
		}
	})
	defer shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewClient(ctx, ClientOptions{
		Address:         server.address,
		Authority:       "localhost",
		CapabilityToken: "token-123",
		TLSConfig:       server.tlsConfig,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	prefer := protocol.GetPreferenceManifestOnly
	getResponse, err := client.Get(ctx, protocol.GetRequest{
		TenantID:   "tenant-alpha",
		Selector:   protocol.NamespaceSelector("docs", "reports/q1"),
		Preference: &prefer,
	}, nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if getResponse.Meta.ResolvedNamespace != "docs" || getResponse.Meta.Preference != prefer {
		t.Fatalf("unexpected get response: %+v", getResponse.Meta)
	}

	bindResponse, err := client.Bind(ctx, protocol.BindRequest{
		TenantID:        "tenant-alpha",
		Namespace:       "docs",
		Path:            "reports/q1",
		TargetCID:       "sha256-manifest",
		IfAbsent:        true,
		Metadata:        map[string]string{"label": "quarterly"},
		IdempotencyKey:  "idem-bind-1",
		SignedRecordB64: "signed-record",
	}, nil)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if bindResponse.EventSeq != 2 {
		t.Fatalf("unexpected bind response: %+v", bindResponse)
	}

	listLimit := uint32(10)
	listResponse, err := client.List(ctx, protocol.ListRequest{
		TenantID:  "tenant-alpha",
		Namespace: "docs",
		Prefix:    "reports",
		Limit:     &listLimit,
		Recursive: true,
	}, nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listResponse.Items) != 1 || listResponse.Items[0].Path != "reports/q1" {
		t.Fatalf("unexpected list response: %+v", listResponse)
	}

	subscription, err := client.Subscribe(ctx, protocol.SubscribeRequest{
		TenantID: "tenant-alpha",
		Filters: []protocol.SubscribeFilter{
			{
				EventType:       protocol.EventTypeNamespaceBound,
				NamespacePrefix: "docs",
				PathExact:       "reports/q1",
			},
		},
		FromSeq: ptrUint64(0),
	}, nil)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer subscription.Close()

	if subscription.Cursor() != "cursor-1" {
		t.Fatalf("unexpected subscription cursor: %s", subscription.Cursor())
	}

	envelope, err := subscription.Next()
	if err != nil {
		t.Fatalf("subscription next: %v", err)
	}
	if envelope.Kind != protocol.SubscribeEnvelopeEvent || envelope.Event == nil {
		t.Fatalf("unexpected subscribe envelope: %+v", envelope)
	}
	if envelope.Event.EventType != protocol.EventTypeNamespaceBound {
		t.Fatalf("unexpected subscribe event: %+v", envelope.Event)
	}

	unbindResponse, err := client.Unbind(ctx, protocol.UnbindRequest{
		TenantID:        "tenant-alpha",
		Namespace:       "docs",
		Path:            "reports/q1",
		IfRevision:      1,
		IdempotencyKey:  "idem-unbind-1",
		SignedRecordB64: "signed-record-2",
	}, nil)
	if err != nil {
		t.Fatalf("unbind: %v", err)
	}
	if !unbindResponse.Tombstone {
		t.Fatalf("expected tombstone response, got %+v", unbindResponse)
	}
}

func TestClientUploadFlowOverNativeBeta(t *testing.T) {
	server, shutdown := startMockNativeServer(t, func(t *testing.T, request mockRequest, stream *quic.Stream) {
		switch request.Header.Operation {
		case protocol.OperationPutInit:
			writeJSONResponse(t, stream, protocol.PutInitResponse{
				SessionID:               "session-1",
				MissingChunks:           []uint32{0},
				AcceptedManifestCID:     "sha256-manifest",
				UploadDeadlineMS:        1000,
				MaxParallelChunkStreams: 8,
			})
		case protocol.OperationPutChunk:
			writeJSONResponse(t, stream, protocol.PutChunkResponse{
				Stored:      true,
				Duplicate:   false,
				VerifiedCID: true,
			})
		case protocol.OperationPutCommit:
			writeJSONResponse(t, stream, protocol.PutCommitResponse{
				ObjectCID: "sha256-manifest",
				Committed: true,
				EventSeq:  1,
			})
		default:
			t.Fatalf("unexpected operation: %s", request.Header.Operation)
		}
	})
	defer shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewClient(ctx, ClientOptions{
		Address:         server.address,
		Authority:       "localhost",
		CapabilityToken: "token-123",
		TLSConfig:       server.tlsConfig,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	initResponse, err := client.PutInit(ctx, protocol.PutInitRequest{
		TenantID:            "tenant-alpha",
		IdempotencyKey:      "idem-1",
		EncryptionProfileID: "public-e2ee-v1",
		KeyPolicyID:         "policy-default",
		MetadataVisibility:  protocol.VisibilityModeSplit,
		StorageClass:        "hot",
		Manifest: protocol.Manifest{
			Version:     1,
			TenantID:    "tenant-alpha",
			LogicalSize: 4,
			StoredSize:  4,
			Chunker:     "fixed-1m",
			ChunkRefs: []protocol.ChunkRef{
				{
					ChunkIndex:      0,
					CID:             "sha256-chunk",
					Offset:          0,
					LogicalLength:   4,
					StoredLength:    4,
					ContentEncoding: "identity",
				},
			},
			ContentType: "application/octet-stream",
			CreatedAtMS: 1,
			EncryptionDescriptor: protocol.EncryptionDescriptor{
				EncryptionProfileID:    "public-e2ee-v1",
				KeyPolicyID:            "policy-default",
				ContentEncryptionSuite: "XChaCha20-Poly1305",
				KeyWrappingSuite:       "HPKE/X25519",
				MetadataVisibility:     protocol.VisibilityModeSplit,
				WrappedObjectKeys: []protocol.WrappedObjectKeyRecord{
					{
						RecipientKeyID:   "reader-1",
						WrappingSuite:    "HPKE/X25519",
						WrappedKeyBase64: "ZmFrZQ",
						KeyVersion:       1,
					},
				},
				ServerVisibleMetadata:   map[string]string{},
				EncryptedClientMetadata: map[string]string{"name": "encrypted"},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("put init: %v", err)
	}
	if initResponse.SessionID != "session-1" {
		t.Fatalf("unexpected put init response: %+v", initResponse)
	}

	chunkResponse, err := client.PutChunk(ctx, protocol.PutChunkRequest{
		TenantID:        "tenant-alpha",
		SessionID:       "session-1",
		ChunkIndex:      0,
		ChunkCID:        "sha256-chunk",
		ChunkOffset:     0,
		ChunkLength:     4,
		ContentEncoding: "identity",
	}, []byte("test"), nil)
	if err != nil {
		t.Fatalf("put chunk: %v", err)
	}
	if !chunkResponse.VerifiedCID {
		t.Fatalf("unexpected put chunk response: %+v", chunkResponse)
	}

	commitResponse, err := client.PutCommit(ctx, protocol.PutCommitRequest{
		TenantID:       "tenant-alpha",
		SessionID:      "session-1",
		ManifestCID:    "sha256-manifest",
		IdempotencyKey: "idem-1",
	}, nil)
	if err != nil {
		t.Fatalf("put commit: %v", err)
	}
	if !commitResponse.Committed {
		t.Fatalf("unexpected put commit response: %+v", commitResponse)
	}
}

type mockNativeServer struct {
	address   string
	tlsConfig *tls.Config
}

func startMockNativeServer(t *testing.T, handler func(t *testing.T, request mockRequest, stream *quic.Stream)) (*mockNativeServer, func()) {
	t.Helper()

	serverCert, rootPool := generateTLSMaterial(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"hsp/1"},
		Certificates: []tls.Certificate{serverCert},
	}, nil)
	if err != nil {
		t.Fatalf("listen quic: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		settingsStream, err := conn.OpenUniStream()
		if err != nil {
			return
		}
		if err := writeCBORFrame(settingsStream, frameSettings, protocol.PublicMultiTenantSettingsFrame("mock-native-beta")); err != nil {
			return
		}
		_ = settingsStream.Close()

		for {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			request, err := readMockRequest(stream)
			if err != nil {
				return
			}
			handler(t, request, stream)
		}
	}()

	shutdown := func() {
		cancel()
		listener.Close()
		<-done
	}

	return &mockNativeServer{
		address: listener.Addr().String(),
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    rootPool,
			ServerName: "localhost",
			NextProtos: []string{"hsp/1"},
		},
	}, shutdown
}

func readMockRequest(stream *quic.Stream) (mockRequest, error) {
	frameType, payload, err := readFrame(stream)
	if err != nil {
		return mockRequest{}, err
	}

	var request mockRequest
	switch frameType {
	case frameAuth:
		var auth protocol.AuthFrame
		if err := decodeCBOR(payload, &auth); err != nil {
			return mockRequest{}, err
		}
		request.Auth = &auth
		frameType, payload, err = readFrame(stream)
		if err != nil {
			return mockRequest{}, err
		}
	case frameReqHeader:
	default:
		return mockRequest{}, validationError("unexpected_first_frame", "request must start with AUTH or REQ_HEADER")
	}

	if frameType != frameReqHeader {
		return mockRequest{}, validationError("missing_req_header", "request must include REQ_HEADER")
	}
	if err := decodeCBOR(payload, &request.Header); err != nil {
		return mockRequest{}, err
	}

	var body []byte
	for {
		frameType, payload, err = readFrame(stream)
		if err != nil {
			return mockRequest{}, err
		}
		switch frameType {
		case frameData:
			body = append(body, payload...)
		case frameEnd:
			request.Body = body
			return request, nil
		default:
			return mockRequest{}, validationError("invalid_request_sequence", "unexpected frame while reading request body")
		}
	}
}

func writeJSONResponse(t *testing.T, stream *quic.Stream, value any) {
	t.Helper()

	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json response: %v", err)
	}
	if err := writeCBORFrame(stream, frameResHeader, protocol.ResHeader{
		Version:       1,
		StatusCode:    200,
		PayloadMode:   payloadModePtr(protocol.PayloadModeJSON),
		PayloadLength: uint64Ptr(uint64(len(body))),
		Meta:          map[string]any{},
		Extensions:    map[string]any{},
	}); err != nil {
		t.Fatalf("write response header: %v", err)
	}
	if err := writeFrame(stream, frameData, body); err != nil {
		t.Fatalf("write response body: %v", err)
	}
	if err := writeFrame(stream, frameEnd, nil); err != nil {
		t.Fatalf("write response end: %v", err)
	}
}

func writeChunkStreamOrJSONResponse(t *testing.T, stream *quic.Stream, meta protocol.GetResponseMeta, chunks [][]byte) {
	t.Helper()

	if len(chunks) == 0 {
		writeJSONResponse(t, stream, meta)
		return
	}
	if err := writeCBORFrame(stream, frameResHeader, protocol.ResHeader{
		Version:     1,
		StatusCode:  200,
		PayloadMode: payloadModePtr(protocol.PayloadModeChunkStream),
		Meta: map[string]any{
			"get_meta": meta,
		},
		Extensions: map[string]any{},
	}); err != nil {
		t.Fatalf("write chunk response header: %v", err)
	}
	for _, chunk := range chunks {
		if err := writeFrame(stream, frameData, chunk); err != nil {
			t.Fatalf("write chunk response frame: %v", err)
		}
	}
	if err := writeFrame(stream, frameEnd, nil); err != nil {
		t.Fatalf("write chunk response end: %v", err)
	}
}

func writeSubscribeResponse(t *testing.T, stream *quic.Stream, cursor string, event protocol.EventRecord) {
	t.Helper()

	if err := writeCBORFrame(stream, frameResHeader, protocol.ResHeader{
		Version:     1,
		StatusCode:  200,
		PayloadMode: payloadModePtr(protocol.PayloadModeNone),
		Meta: map[string]any{
			"cursor": cursor,
		},
		Extensions: map[string]any{},
	}); err != nil {
		t.Fatalf("write subscribe header: %v", err)
	}
	if err := writeCBORFrame(stream, frameEvent, event); err != nil {
		t.Fatalf("write subscribe event: %v", err)
	}
	if err := writeCBORFrame(stream, frameNotice, protocol.NoticeFrame{
		Kind:   "heartbeat",
		Cursor: "cursor-1",
	}); err != nil {
		t.Fatalf("write subscribe notice: %v", err)
	}
	if err := writeFrame(stream, frameEnd, nil); err != nil {
		t.Fatalf("write subscribe end: %v", err)
	}
}

func generateTLSMaterial(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certificate := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(leaf)
	return certificate, rootPool
}

func ptrUint64(value uint64) *uint64 {
	return &value
}
