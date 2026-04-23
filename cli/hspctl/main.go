package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/loxar/hsp/sdk/go/alpha"
	"github.com/loxar/hsp/sdk/go/gatewaybeta"
	"github.com/loxar/hsp/sdk/go/protocol"
	security "github.com/loxar/hsp/sdk/go/security"
)

func main() {
	command := "info"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	switch command {
	case "bootstrap":
		printJSON(protocol.PublicMultiTenantBootstrapDocument("localhost", "https://localhost/v1/"))
	case "diagnostics":
		printJSON(alpha.SecurityDiagnostics())
	case "gateway-bootstrap":
		client := mustGatewayClient()
		defer client.Close()
		printJSON(must(client.Bootstrap(commandContext())))
	case "gateway-info":
		client := mustGatewayClient()
		defer client.Close()
		printJSON(must(client.Info(commandContext())))
	case "gateway-diagnostics":
		client := mustGatewayClient()
		defer client.Close()
		printJSON(must(client.Diagnostics(commandContext())))
	case "gateway-head":
		if len(os.Args) < 3 {
			panic("usage: hspctl gateway-head <cid>")
		}
		client := mustGatewayClient()
		defer client.Close()
		printJSON(must(client.Head(commandContext(), protocol.HeadRequest{
			TenantID: protocol.TenantID(requiredEnv("HSP_TENANT_ID")),
			Selector: protocol.CIDSelector(os.Args[2]),
		}, nil)))
	case "gateway-head-ns":
		if len(os.Args) < 4 {
			panic("usage: hspctl gateway-head-ns <namespace> <path>")
		}
		client := mustGatewayClient()
		defer client.Close()
		printJSON(must(client.Head(commandContext(), protocol.HeadRequest{
			TenantID: protocol.TenantID(requiredEnv("HSP_TENANT_ID")),
			Selector: protocol.NamespaceSelector(os.Args[2], os.Args[3]),
		}, nil)))
	case "gateway-get":
		if len(os.Args) < 3 {
			panic("usage: hspctl gateway-get <cid>")
		}
		client := mustGatewayClient()
		defer client.Close()
		printJSON(must(client.Get(commandContext(), buildGetRequest(os.Args[2]), nil)))
	case "gateway-get-ns":
		if len(os.Args) < 4 {
			panic("usage: hspctl gateway-get-ns <namespace> <path>")
		}
		client := mustGatewayClient()
		defer client.Close()
		request := buildGetRequest("")
		request.Selector = protocol.NamespaceSelector(os.Args[2], os.Args[3])
		printJSON(must(client.Get(commandContext(), request, nil)))
	case "gateway-resolve":
		if len(os.Args) < 4 {
			panic("usage: hspctl gateway-resolve <namespace> <path>")
		}
		client := mustGatewayClient()
		defer client.Close()
		printJSON(must(client.Resolve(commandContext(), protocol.ResolveRequest{
			TenantID:  protocol.TenantID(requiredEnv("HSP_TENANT_ID")),
			Namespace: os.Args[2],
			Path:      os.Args[3],
		}, nil)))
	case "gateway-bind":
		if len(os.Args) < 3 {
			panic("usage: hspctl gateway-bind <request.json>")
		}
		client := mustGatewayClient()
		defer client.Close()
		request := must(readJSONFile[protocol.BindRequest](os.Args[2]))
		printJSON(must(client.Bind(commandContext(), request, nil)))
	case "gateway-unbind":
		if len(os.Args) < 3 {
			panic("usage: hspctl gateway-unbind <request.json>")
		}
		client := mustGatewayClient()
		defer client.Close()
		request := must(readJSONFile[protocol.UnbindRequest](os.Args[2]))
		printJSON(must(client.Unbind(commandContext(), request, nil)))
	case "gateway-list":
		if len(os.Args) < 3 {
			panic("usage: hspctl gateway-list <namespace>")
		}
		client := mustGatewayClient()
		defer client.Close()
		request := protocol.ListRequest{
			TenantID:  protocol.TenantID(requiredEnv("HSP_TENANT_ID")),
			Namespace: os.Args[2],
		}
		printJSON(must(client.List(commandContext(), request, nil)))
	case "gateway-subscribe":
		client := mustGatewayClient()
		defer client.Close()
		reader := must(client.Subscribe(commandContext(), protocol.SubscribeRequest{
			TenantID: protocol.TenantID(requiredEnv("HSP_TENANT_ID")),
			Filters: []protocol.SubscribeFilter{{
				NamespacePrefix: os.Getenv("HSP_NAMESPACE_PREFIX"),
				PathExact:       os.Getenv("HSP_PATH_EXACT"),
				ObjectCID:       os.Getenv("HSP_OBJECT_CID"),
				EventType:       protocol.EventType(os.Getenv("HSP_EVENT_TYPE")),
			}},
		}, nil))
		defer reader.Close()
		limit := envInt("HSP_SUBSCRIBE_LIMIT", 10)
		items := make([]protocol.SubscribeEnvelope, 0, limit)
		for len(items) < limit {
			item, err := reader.Next()
			if err != nil {
				panic(err)
			}
			items = append(items, *item)
		}
		printJSON(items)
	case "gateway-put-init":
		if len(os.Args) < 3 {
			panic("usage: hspctl gateway-put-init <request.json>")
		}
		client := mustGatewayClient()
		defer client.Close()
		request := must(readJSONFile[protocol.PutInitRequest](os.Args[2]))
		printJSON(must(client.PutInit(commandContext(), request, nil)))
	case "gateway-put-chunk":
		if len(os.Args) < 4 {
			panic("usage: hspctl gateway-put-chunk <request.json> <chunk.bin>")
		}
		client := mustGatewayClient()
		defer client.Close()
		request := must(readJSONFile[protocol.PutChunkRequest](os.Args[2]))
		chunk := must(os.ReadFile(os.Args[3]))
		printJSON(must(client.PutChunk(commandContext(), request, chunk, nil)))
	case "gateway-put-commit":
		if len(os.Args) < 3 {
			panic("usage: hspctl gateway-put-commit <request.json>")
		}
		client := mustGatewayClient()
		defer client.Close()
		request := must(readJSONFile[protocol.PutCommitRequest](os.Args[2]))
		printJSON(must(client.PutCommit(commandContext(), request, nil)))
	default:
		profile := security.PublicMultiTenantProfile()
		printJSON(map[string]any{
			"authority_profile":            profile.AuthorityProfile,
			"e2ee_required":                profile.E2EERequired,
			"storage_encryption_required":  profile.StorageEncryptionRequired,
			"crypto_suite":                 profile.CryptoSuite,
			"key_wrapping_suite":           profile.KeyWrappingSuite,
			"tenant_isolation_profile":     profile.TenantIsolationProfile,
			"cross_tenant_plaintext_dedup": false,
		})
	}
}

func mustGatewayClient() *gatewaybeta.Client {
	baseURL := envOrDefault("HSP_BASE_URL", "https://localhost:9444/v1/")
	insecureSkipVerify := envBool("HSP_INSECURE_SKIP_VERIFY")
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: insecureSkipVerify,
	}
	serverName := os.Getenv("HSP_SERVER_NAME")
	if serverName != "" {
		tlsConfig.ServerName = serverName
	}

	client, err := gatewaybeta.NewClient(gatewaybeta.ClientOptions{
		BaseURL:         baseURL,
		CapabilityToken: os.Getenv("HSP_CAPABILITY_TOKEN"),
		TLSConfig:       tlsConfig,
	})
	if err != nil {
		panic(err)
	}
	return client
}

func buildGetRequest(cid string) protocol.GetRequest {
	request := protocol.GetRequest{
		TenantID: protocol.TenantID(requiredEnv("HSP_TENANT_ID")),
	}
	if cid != "" {
		request.Selector = protocol.CIDSelector(cid)
	}

	if preference := os.Getenv("HSP_GET_PREFERENCE"); preference != "" {
		value := protocol.GetPreference(preference)
		request.Preference = &value
	}

	start := os.Getenv("HSP_RANGE_START")
	end := os.Getenv("HSP_RANGE_END")
	if start != "" || end != "" {
		if start == "" || end == "" {
			panic("HSP_RANGE_START and HSP_RANGE_END must both be set")
		}
		request.Range = &protocol.RangeSpec{
			Start: must(strconv.ParseUint(start, 10, 64)),
			End:   must(strconv.ParseUint(end, 10, 64)),
		}
	}

	return request
}

func commandContext() context.Context {
	timeout := 30 * time.Second
	if value := os.Getenv("HSP_TIMEOUT_SEC"); value != "" {
		timeout = time.Duration(must(strconv.ParseUint(value, 10, 64))) * time.Second
	}
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	return ctx
}

func readJSONFile[T any](path string) (T, error) {
	var target T
	data, err := os.ReadFile(path)
	if err != nil {
		return target, err
	}
	if err := json.Unmarshal(data, &target); err != nil {
		return target, err
	}
	return target, nil
}

func requiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic(fmt.Sprintf("%s is required", name))
	}
	return value
}

func envOrDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func envBool(name string) bool {
	value := os.Getenv(name)
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		panic(fmt.Sprintf("%s must be a boolean", name))
	}
	return parsed
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		panic(fmt.Sprintf("%s must be an integer", name))
	}
	return parsed
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func printJSON(value any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("failed to encode JSON: %v", err))
	}

	fmt.Println(string(encoded))
}
