package httpapi

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"mesh/internal/control"
)

func TestOpenAPIExactlyCoversRegisteredApplicationRoutes(t *testing.T) {
	registered := registeredApplicationRoutes(t)
	document := decodedOpenAPI(t)
	paths := document["paths"].(map[string]any)
	contract := make([]string, 0)
	for path, rawPathItem := range paths {
		pathItem := rawPathItem.(map[string]any)
		for method := range pathItem {
			contract = append(contract, strings.ToUpper(method)+" "+path)
		}
	}
	sort.Strings(contract)
	if len(contract) != 70 {
		t.Fatalf("OpenAPI operation count = %d, want 70", len(contract))
	}
	if strings.Join(registered, "\n") != strings.Join(contract, "\n") {
		t.Fatalf(
			"registered application routes and OpenAPI differ\nregistered:\n%s\n\ncontract:\n%s",
			strings.Join(registered, "\n"),
			strings.Join(contract, "\n"),
		)
	}
}

func TestOpenAPIOperationsAreCompleteAndExamplesAreBounded(t *testing.T) {
	document := decodedOpenAPI(t)
	paths := document["paths"].(map[string]any)
	operationIDs := make(map[string]bool)
	for path, rawPathItem := range paths {
		pathItem := rawPathItem.(map[string]any)
		for method, rawOperation := range pathItem {
			operation := rawOperation.(map[string]any)
			operationID, _ := operation["operationId"].(string)
			if operationID == "" || operationIDs[operationID] {
				t.Fatalf("%s %s has empty or duplicate operationId %q", method, path, operationID)
			}
			operationIDs[operationID] = true
			for _, field := range []string{"summary", "description"} {
				if text, ok := operation[field].(string); !ok || strings.TrimSpace(text) == "" {
					t.Fatalf("%s lacks %s", operationID, field)
				}
			}
			if _, ok := operation["security"].([]any); !ok {
				t.Fatalf("%s lacks explicit security", operationID)
			}
			if _, ok := operation["x-interactive"].(bool); !ok {
				t.Fatalf("%s lacks x-interactive", operationID)
			}
			if samples, ok := operation["x-codeSamples"].([]any); !ok || len(samples) != 1 {
				t.Fatalf("%s lacks one curl sample", operationID)
			}
			if request, ok := operation["requestBody"].(map[string]any); ok {
				media := request["content"].(map[string]any)["application/json"].(map[string]any)
				if media["schema"] == nil || media["example"] == nil {
					t.Fatalf("%s request lacks schema or example", operationID)
				}
			}
			for status, rawResponse := range operation["responses"].(map[string]any) {
				response := rawResponse.(map[string]any)
				if response["$ref"] != nil || response["content"] == nil {
					continue
				}
				media := response["content"].(map[string]any)["application/json"].(map[string]any)
				if media["schema"] == nil || media["example"] == nil {
					t.Fatalf("%s response %s lacks schema or example", operationID, status)
				}
			}
		}
	}
	raw, err := CanonicalOpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		strings.Repeat("a", 43),
		`"private_key":"example"`,
		`"token":"example"`,
		`"code":"example"`,
	} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("OpenAPI contains unsafe example material %q", forbidden)
		}
	}
}

func TestOpenAPIAuthenticationAndCSRFGuidance(t *testing.T) {
	document := decodedOpenAPI(t)
	info := document["info"].(map[string]any)
	description := info["description"].(string)
	for _, required := range []string{
		"__Host-mesh_session",
		"__Host-mesh_csrf",
		"X-Mesh-CSRF",
		"exact public origin",
		"legacy administrator bearer",
		"device-scoped",
	} {
		if !strings.Contains(description, required) {
			t.Fatalf("contract guidance lacks %q", required)
		}
	}
	schemes := document["components"].(map[string]any)["securitySchemes"].(map[string]any)
	for _, name := range []string{"cookieSession", "legacyAdminBearer", "agentBearer"} {
		if _, exists := schemes[name]; !exists {
			t.Fatalf("security scheme %q is missing", name)
		}
	}
}

func TestOpenAPIDesktopPollingDocumentsRetryAfter(t *testing.T) {
	document := decodedOpenAPI(t)
	paths := document["paths"].(map[string]any)
	operation := paths["/api/v1/auth/desktop/complete"].(map[string]any)["post"].(map[string]any)
	response := operation["responses"].(map[string]any)["429"].(map[string]any)
	headers := response["headers"].(map[string]any)
	retryAfter := headers["Retry-After"].(map[string]any)
	if required, ok := retryAfter["required"].(bool); !ok || !required {
		t.Fatalf("desktop polling Retry-After required = %#v", retryAfter["required"])
	}
	schema := retryAfter["schema"].(map[string]any)
	if schema["type"] != "integer" || schema["minimum"] != float64(1) ||
		schema["maximum"] != float64(3600) || schema["example"] != float64(5) {
		t.Fatalf("desktop polling Retry-After schema = %#v", schema)
	}
}

func TestOpenAPIEndpointIsPublicAndCanonical(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	serveOpenAPI(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("OpenAPI returned %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/vnd.oai.openapi+json; charset=utf-8" {
		t.Fatalf("OpenAPI content type = %q", got)
	}
	canonical, err := CanonicalOpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	if recorder.Body.String() != string(canonical) {
		t.Fatal("served OpenAPI differs from canonical bytes")
	}
}

func TestOpenAPIErrorSchemaMatchesHTTPBoundary(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeError(recorder, control.ErrUnauthorized)
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 1 {
		t.Fatalf("error payload has fields %v", payload)
	}
	if _, ok := payload["error"].(string); !ok {
		t.Fatalf("error payload = %#v", payload)
	}
	document := decodedOpenAPI(t)
	errorSchema := document["components"].(map[string]any)["schemas"].(map[string]any)["Error"].(map[string]any)
	required := errorSchema["required"].([]any)
	if len(required) != 1 || required[0] != "error" {
		t.Fatalf("Error schema required = %v", required)
	}
	if additional, ok := errorSchema["additionalProperties"].(bool); !ok || additional {
		t.Fatalf("Error schema additionalProperties = %#v", errorSchema["additionalProperties"])
	}
}

func decodedOpenAPI(t *testing.T) map[string]any {
	t.Helper()
	raw, err := CanonicalOpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document["openapi"] != openAPIVersion {
		t.Fatalf("OpenAPI version = %#v", document["openapi"])
	}
	return document
}

func registeredApplicationRoutes(t *testing.T) []string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate openapi_test.go")
	}
	serverPath := filepath.Join(filepath.Dir(current), "server.go")
	source, err := os.ReadFile(serverPath)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), serverPath, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	routes := make([]string, 0)
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (selector.Sel.Name != "Handle" && selector.Sel.Name != "HandleFunc") || len(call.Args) == 0 {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || receiver.Name != "mux" {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatalf("invalid route literal %s: %v", literal.Value, err)
		}
		if pattern == "GET /" || pattern == "GET /openapi.json" {
			return true
		}
		routes = append(routes, pattern)
		return true
	})
	sort.Strings(routes)
	return routes
}
