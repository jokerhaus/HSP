package gatewaybeta

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/loxar/hsp/sdk/go/protocol"
	"github.com/quic-go/quic-go/http3"
)

func TestChunkStreamReaderParsesMetaAndChunks(t *testing.T) {
	body := io.NopCloser(strings.NewReader(
		`{"type":"meta","meta":{"object_cid":"sha256-object","manifest_cid":"sha256-manifest","storage_class":"hot","logical_size":4,"stored_size":4,"content_type":"application/octet-stream","metadata_visibility":"split","server_visible_metadata":{},"encrypted_client_metadata_redacted":true,"preference":"chunk-stream","chunk_descriptors":[{"chunk_index":0,"chunk_cid":"sha256-chunk","chunk_offset":0,"logical_range_start":0,"logical_range_end":4,"fragment_offset":0,"fragment_length":4,"content_encoding":"identity"}]}}` + "\n" +
			`{"type":"chunk","descriptor":{"chunk_index":0,"chunk_cid":"sha256-chunk","chunk_offset":0,"logical_range_start":0,"logical_range_end":4,"fragment_offset":0,"fragment_length":4,"content_encoding":"identity"},"data_b64":"dGVzdA"}` + "\n",
	))

	reader := NewChunkStreamReader(body)
	meta, err := reader.Meta()
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if meta.ObjectCID != "sha256-object" {
		t.Fatalf("unexpected object cid: %s", meta.ObjectCID)
	}

	chunk, err := reader.Next()
	if err != nil {
		t.Fatalf("next chunk: %v", err)
	}
	if string(chunk.Bytes) != "test" {
		t.Fatalf("unexpected chunk bytes: %q", string(chunk.Bytes))
	}
}

func TestClientBootstrapInfoAndDiagnosticsOverHTTP3(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/.well-known/hsp", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, protocol.PublicMultiTenantBootstrapDocument("localhost", "https://localhost/v1/"))
	})
	handler.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, protocol.PublicMultiTenantInfoResponse())
	})

	baseURL, tlsConfig, shutdown := startHTTP3TestServer(t, handler)
	defer shutdown()

	client, err := NewClient(ClientOptions{
		BaseURL:   baseURL,
		TLSConfig: tlsConfig,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bootstrap, err := client.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if bootstrap.Gateway.BaseURL == "" {
		t.Fatal("expected bootstrap gateway base URL")
	}

	info, err := client.Info(ctx)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if !info.E2EERequired {
		t.Fatal("expected info to require e2ee")
	}

	diagnostics, err := client.Diagnostics(ctx)
	if err != nil {
		t.Fatalf("diagnostics: %v", err)
	}
	if diagnostics.ChannelBindingKind != "tls-exporter" {
		t.Fatalf("unexpected channel binding kind: %s", diagnostics.ChannelBindingKind)
	}
}

func TestClientHeadSendsChannelBindingHeaders(t *testing.T) {
	var seenCapability string
	var seenBindingKind string
	var seenProof string
	var seenNonce string

	handler := http.NewServeMux()
	handler.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, protocol.PublicMultiTenantInfoResponse())
	})
	handler.HandleFunc("/v1/objects/cid/sha256-object", func(w http.ResponseWriter, r *http.Request) {
		seenCapability = r.Header.Get("x-hsp-capability")
		seenBindingKind = r.Header.Get("x-hsp-channel-binding-kind")
		seenProof = r.Header.Get("x-hsp-channel-binding-proof")
		seenNonce = r.Header.Get("x-hsp-channel-binding-nonce")
		w.Header().Set("x-hsp-object-cid", "sha256-object")
		w.Header().Set("x-hsp-manifest-cid", "sha256-manifest")
		w.Header().Set("x-hsp-storage-class", "hot")
		w.Header().Set("x-hsp-logical-size", "4")
		w.Header().Set("x-hsp-stored-size", "4")
		w.Header().Set("x-hsp-content-type", "application/octet-stream")
		w.Header().Set("x-hsp-metadata-visibility", "split")
		w.Header().Set("x-hsp-encrypted-client-metadata-redacted", "true")
		w.WriteHeader(http.StatusOK)
	})

	baseURL, tlsConfig, shutdown := startHTTP3TestServer(t, handler)
	defer shutdown()

	client, err := NewClient(ClientOptions{
		BaseURL:         baseURL,
		CapabilityToken: "token-123",
		TLSConfig:       tlsConfig,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	head, err := client.Head(ctx, protocol.HeadRequest{
		TenantID: "tenant-alpha",
		Selector: protocol.CIDSelector("sha256-object"),
	}, nil)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if head.ObjectCID != "sha256-object" {
		t.Fatalf("unexpected object cid: %s", head.ObjectCID)
	}
	if seenCapability != "token-123" {
		t.Fatalf("unexpected capability token: %s", seenCapability)
	}
	if seenBindingKind != "tls-exporter" {
		t.Fatalf("unexpected binding kind: %s", seenBindingKind)
	}
	if seenProof == "" || seenNonce == "" {
		t.Fatal("expected non-empty channel binding headers")
	}
}

func TestClientGetParsesChunkStreamOverHTTP3(t *testing.T) {
	prefer := protocol.GetPreferenceChunkStream
	handler := http.NewServeMux()
	handler.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, protocol.PublicMultiTenantInfoResponse())
	})
	handler.HandleFunc("/v1/objects/cid/sha256-object", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("prefer"); got != string(prefer) {
			t.Fatalf("unexpected prefer query: %s", got)
		}
		w.Header().Set("Content-Type", "application/x-hsp-chunk-stream+jsonl")
		fmt.Fprint(w, `{"type":"meta","meta":{"object_cid":"sha256-object","manifest_cid":"sha256-manifest","storage_class":"hot","logical_size":4,"stored_size":4,"content_type":"application/octet-stream","metadata_visibility":"split","server_visible_metadata":{},"encrypted_client_metadata_redacted":true,"preference":"chunk-stream","chunk_descriptors":[{"chunk_index":0,"chunk_cid":"sha256-chunk","chunk_offset":0,"logical_range_start":0,"logical_range_end":4,"fragment_offset":0,"fragment_length":4,"content_encoding":"identity"}]}}`+"\n")
		fmt.Fprint(w, `{"type":"chunk","descriptor":{"chunk_index":0,"chunk_cid":"sha256-chunk","chunk_offset":0,"logical_range_start":0,"logical_range_end":4,"fragment_offset":0,"fragment_length":4,"content_encoding":"identity"},"data_b64":"dGVzdA"}`+"\n")
	})

	baseURL, tlsConfig, shutdown := startHTTP3TestServer(t, handler)
	defer shutdown()

	client, err := NewClient(ClientOptions{
		BaseURL:         baseURL,
		CapabilityToken: "token-123",
		TLSConfig:       tlsConfig,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response, err := client.Get(ctx, protocol.GetRequest{
		TenantID:   "tenant-alpha",
		Selector:   protocol.CIDSelector("sha256-object"),
		Preference: &prefer,
	}, nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(response.Chunks) != 1 {
		t.Fatalf("unexpected chunk count: %d", len(response.Chunks))
	}
	if string(response.Chunks[0].Bytes) != "test" {
		t.Fatalf("unexpected chunk bytes: %q", string(response.Chunks[0].Bytes))
	}
}

func TestClientUploadFlowOverHTTP3(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, protocol.PublicMultiTenantInfoResponse())
	})
	handler.HandleFunc("/v1/uploads", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method for uploads: %s", r.Method)
		}
		var request protocol.PutInitRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode put init: %v", err)
		}
		if request.TenantID != "tenant-alpha" {
			t.Fatalf("unexpected tenant id: %s", request.TenantID)
		}
		writeJSON(t, w, protocol.PutInitResponse{
			SessionID:               "session-1",
			MissingChunks:           []uint32{0},
			AcceptedManifestCID:     "sha256-manifest",
			UploadDeadlineMS:        1234,
			MaxParallelChunkStreams: 8,
		})
	})
	handler.HandleFunc("/v1/uploads/session-1/chunks/0", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected method for upload chunk: %s", r.Method)
		}
		if got := r.URL.Query().Get("chunk_cid"); got != "sha256-chunk" {
			t.Fatalf("unexpected chunk cid query: %s", got)
		}
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read chunk body: %v", err)
		}
		if string(payload) != "test" {
			t.Fatalf("unexpected chunk payload: %q", string(payload))
		}
		writeJSON(t, w, protocol.PutChunkResponse{
			Stored:      true,
			Duplicate:   false,
			VerifiedCID: true,
		})
	})
	handler.HandleFunc("/v1/uploads/session-1:commit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method for upload commit: %s", r.Method)
		}
		writeJSON(t, w, protocol.PutCommitResponse{
			ObjectCID: "sha256-manifest",
			Committed: true,
			EventSeq:  1,
		})
	})

	baseURL, tlsConfig, shutdown := startHTTP3TestServer(t, handler)
	defer shutdown()

	client, err := NewClient(ClientOptions{
		BaseURL:         baseURL,
		CapabilityToken: "token-123",
		TLSConfig:       tlsConfig,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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
		t.Fatalf("unexpected session id: %s", initResponse.SessionID)
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
	if !chunkResponse.Stored || !chunkResponse.VerifiedCID {
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

func TestClientNamespaceOperationsOverHTTP3(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, protocol.PublicMultiTenantInfoResponse())
	})
	handler.HandleFunc("/v1/namespaces/docs/resolve/reports/q1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method for resolve: %s", r.Method)
		}
		if got := r.URL.Query().Get("tenant_id"); got != "tenant-alpha" {
			t.Fatalf("unexpected tenant_id query: %s", got)
		}
		writeJSON(t, w, protocol.ResolveResponse{
			Revision:    1,
			TargetCID:   "sha256-manifest",
			ManifestCID: "sha256-manifest",
			RecordCID:   "sha256-record",
			Metadata:    map[string]string{"label": "quarterly"},
			Tombstone:   false,
		})
	})
	handler.HandleFunc("/v1/namespaces/docs/bind/reports/q1", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			var request protocol.BindRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode bind request: %v", err)
			}
			if request.Path != "reports/q1" || request.Namespace != "docs" {
				t.Fatalf("unexpected bind target: %+v", request)
			}
			writeJSON(t, w, protocol.BindResponse{
				Revision:  1,
				RecordCID: "sha256-record",
				EventSeq:  2,
			})
		case http.MethodDelete:
			var request protocol.UnbindRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode unbind request: %v", err)
			}
			if request.IfRevision != 1 {
				t.Fatalf("unexpected unbind revision: %d", request.IfRevision)
			}
			writeJSON(t, w, protocol.UnbindResponse{
				Revision:  2,
				RecordCID: "sha256-record-2",
				EventSeq:  3,
				Tombstone: true,
			})
		default:
			t.Fatalf("unexpected method for bind route: %s", r.Method)
		}
	})
	handler.HandleFunc("/v1/namespaces/docs/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method for list: %s", r.Method)
		}
		writeJSON(t, w, protocol.ListResponse{
			Items: []protocol.ListItem{
				{
					Path:       "reports/q1",
					Revision:   1,
					TargetCID:  "sha256-manifest",
					ManifestCID: "sha256-manifest",
					RecordCID:  "sha256-record",
					Metadata:   map[string]string{"label": "quarterly"},
					Tombstone:  false,
				},
			},
			NextCursor:                "",
			Truncated:                 false,
			NamespaceRevisionSnapshot: 1,
		})
	})
	handler.HandleFunc("/v1/objects/namespace/docs/reports/q1", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			w.Header().Set("x-hsp-object-cid", "sha256-manifest")
			w.Header().Set("x-hsp-manifest-cid", "sha256-manifest")
			w.Header().Set("x-hsp-storage-class", "hot")
			w.Header().Set("x-hsp-logical-size", "4")
			w.Header().Set("x-hsp-stored-size", "4")
			w.Header().Set("x-hsp-content-type", "application/octet-stream")
			w.Header().Set("x-hsp-metadata-visibility", "split")
			w.Header().Set("x-hsp-encrypted-client-metadata-redacted", "true")
			w.Header().Set("x-hsp-resolved-namespace", "docs")
			w.Header().Set("x-hsp-resolved-path", "reports/q1")
			w.Header().Set("x-hsp-resolved-revision", "1")
			w.Header().Set("x-hsp-resolved-record-cid", "sha256-record")
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			if got := r.URL.Query().Get("prefer"); got != string(protocol.GetPreferenceManifestOnly) {
				t.Fatalf("unexpected GET prefer query: %s", got)
			}
			writeJSON(t, w, protocol.GetResponseMeta{
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
			})
		default:
			t.Fatalf("unexpected method for namespace object route: %s", r.Method)
		}
	})
	handler.HandleFunc("/v1/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method for events: %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/x-hsp-events+jsonl")
		fmt.Fprint(w, `{"kind":"event","event":{"version":1,"seq":2,"at_ms":2,"event_type":"namespace.bound","subject_kind":"namespace","namespace":"docs","path":"reports/q1","cid":"sha256-manifest","revision":1,"payload":{"label":"quarterly"}}}`+"\n")
		fmt.Fprint(w, `{"kind":"notice","notice":{"kind":"heartbeat","cursor":"cursor-1"}}`+"\n")
	})

	baseURL, tlsConfig, shutdown := startHTTP3TestServer(t, handler)
	defer shutdown()

	client, err := NewClient(ClientOptions{
		BaseURL:         baseURL,
		CapabilityToken: "token-123",
		TLSConfig:       tlsConfig,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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
	if bindResponse.Revision != 1 {
		t.Fatalf("unexpected bind revision: %d", bindResponse.Revision)
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
		t.Fatalf("unexpected resolve target: %s", resolveResponse.TargetCID)
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

	headResponse, err := client.Head(ctx, protocol.HeadRequest{
		TenantID: "tenant-alpha",
		Selector: protocol.NamespaceSelector("docs", "reports/q1"),
	}, nil)
	if err != nil {
		t.Fatalf("head namespace: %v", err)
	}
	if headResponse.ResolvedNamespace != "docs" || headResponse.ResolvedPath != "reports/q1" {
		t.Fatalf("unexpected namespace head response: %+v", headResponse)
	}

	prefer := protocol.GetPreferenceManifestOnly
	getResponse, err := client.Get(ctx, protocol.GetRequest{
		TenantID:   "tenant-alpha",
		Selector:   protocol.NamespaceSelector("docs", "reports/q1"),
		Preference: &prefer,
	}, nil)
	if err != nil {
		t.Fatalf("get namespace: %v", err)
	}
	if getResponse.Meta.ResolvedNamespace != "docs" || getResponse.Meta.Preference != prefer {
		t.Fatalf("unexpected namespace get response: %+v", getResponse.Meta)
	}

	stream, err := client.Subscribe(ctx, protocol.SubscribeRequest{
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
	defer stream.Close()

	envelope, err := stream.Next()
	if err != nil {
		t.Fatalf("subscribe next: %v", err)
	}
	if envelope.Kind != protocol.SubscribeEnvelopeEvent || envelope.Event == nil {
		t.Fatalf("unexpected subscribe envelope: %+v", envelope)
	}
	if envelope.Event.EventType != protocol.EventTypeNamespaceBound {
		t.Fatalf("unexpected subscribe event type: %s", envelope.Event.EventType)
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

func startHTTP3TestServer(t *testing.T, handler http.Handler) (string, *tls.Config, func()) {
	t.Helper()

	serverCert, rootPool := generateTLSMaterial(t)
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
	}

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}

	server := &http3.Server{
		TLSConfig: tlsConfig,
		Handler:   handler,
	}
	go server.Serve(packetConn)

	addr := packetConn.LocalAddr().String()
	baseURL := fmt.Sprintf("https://localhost:%s/v1/", strings.Split(addr, ":")[1])
	clientTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    rootPool,
		ServerName: "localhost",
		NextProtos: []string{http3.NextProtoH3},
	}

	shutdown := func() {
		server.Close()
		packetConn.Close()
	}
	return baseURL, clientTLSConfig, shutdown
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

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode json response: %v", err)
	}
}

func ptrUint64(value uint64) *uint64 {
	return &value
}
