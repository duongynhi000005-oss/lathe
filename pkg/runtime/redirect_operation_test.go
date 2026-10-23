package runtime

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type operationRedirectTransport func(*http.Request) (*http.Response, error)

func (f operationRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type operationRedirectAuth func(*http.Request) error

func (f operationRedirectAuth) Apply(req *http.Request) error { return f(req) }

func TestInvokeOperationScopesRedirectedJSONBody(t *testing.T) {
	for _, status := range []int{307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			spec := CommandSpec{
				Method: "POST", PathTpl: "/items",
				Params: []ParamSpec{
					{Name: "name", Flag: "name", In: InBody, GoType: "string"},
					{Name: "X-Custom-Token", Flag: "custom-token", In: InHeader, GoType: "string"},
				},
				RequestBody: &RequestBody{Required: true, MediaType: "application/json"},
			}
			name, token := "synthetic", "synthetic-custom"
			input := OperationInput{
				Values:  map[string]any{boundParamKey(spec.Params[0]): &name, boundParamKey(spec.Params[1]): &token},
				Changed: map[string]bool{boundParamKey(spec.Params[0]): true, boundParamKey(spec.Params[1]): true},
			}
			calls := 0
			opts := ClientOptions{MaxRetries: -1, Auth: APIKeyAuth{Key: "synthetic-key"}}
			opts.Transport = operationRedirectTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				key, custom := req.Header.Get("X-API-Key") != "", req.Header.Get("X-Custom-Token") != ""
				t.Logf("hop=%d method=%s body=%s content_type=%q key_present=%t custom_present=%t", calls, req.Method, body, req.Header.Get("Content-Type"), key, custom)
				if req.Method != "POST" || string(body) != `{"name":"synthetic"}` || req.Header.Get("Content-Type") != "application/json" {
					t.Errorf("hop %d did not preserve the generated JSON request contract", calls)
				}
				if key != (calls == 1) || custom != (calls == 1) {
					t.Errorf("hop %d credential headers: key=%t custom=%t", calls, key, custom)
				}
				header := http.Header{"Content-Type": {"application/json"}}
				code := 200
				if calls == 1 {
					code = status
					header.Set("Location", "https://cdn.example/items")
				}
				return &http.Response{StatusCode: code, Header: header, Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
			})
			result, err := InvokeOperation(context.Background(), spec, input, OperationOptions{Hostname: "https://api.example", Client: opts})
			if err != nil || calls != 2 || string(result.Data) != `{}` {
				t.Fatalf("result = %v, err = %v, calls = %d", result, err, calls)
			}
		})
	}
}

func TestHTTPClientPreservesStandardRedirectHeaders(t *testing.T) {
	for _, status := range []int{302, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			headers := []string{"Accept", "Accept-Language", "User-Agent", "Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "If-Range"}
			opts := ClientOptions{MaxRetries: -1, Transport: operationRedirectTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 2 {
					for _, name := range headers {
						if req.Header.Get(name) != "synthetic" {
							t.Errorf("redirect omitted %s", name)
						}
					}
					if req.Header.Get("X-API-Key") != "" || req.Header.Get("Referer") != "" || req.Header.Get("cf-access-token") != "" {
						t.Error("redirect forwarded an excluded header")
					}
					if replayed := req.GetBody != nil; replayed != (status != 302) {
						t.Errorf("replayed = %t for status %d", replayed, status)
					}
					if got := req.Header.Get("Content-Type"); (got == "application/json") != (status != 302) {
						t.Errorf("redirect Content-Type = %q for status %d", got, status)
					}
				}
				header := http.Header{}
				code := 200
				if calls == 1 {
					code = status
					header.Set("Location", "https://cdn.example/items")
				}
				return &http.Response{StatusCode: code, Header: header, Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
			})}
			req, err := http.NewRequestWithContext(context.Background(), "POST", "https://api.example/items", strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range headers {
				req.Header.Set(name, "synthetic")
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-API-Key", "synthetic")
			req.Header.Set("cf-access-token", "synthetic")
			resp, err := HTTPClient(opts).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if calls != 2 || resp.StatusCode != 200 {
				t.Fatalf("calls = %d, status = %d", calls, resp.StatusCode)
			}
		})
	}
}

func TestAuthenticationRejectsForwardedHeaderNames(t *testing.T) {
	for _, name := range []string{"Accept", "Accept-Language", "User-Agent", "Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "If-Range", "Content-Type"} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), "GET", "https://api.example/", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := (APIKeyAuth{Key: "synthetic", Header: strings.ToLower(name)}).Apply(req); err == nil || len(req.Header) != 0 {
				t.Error("API key accepted a reserved header")
			}
			calls := 0
			opts := ClientOptions{MaxRetries: -1, Transport: operationRedirectTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
			})}
			opts.Auth = operationRedirectAuth(func(req *http.Request) error {
				req.Header[strings.ToLower(name)] = []string{"synthetic"}
				return nil
			})
			if _, err := DoRaw(context.Background(), "https://api.example", "GET", "/", nil, opts); err == nil || calls != 0 {
				t.Errorf("custom auth accepted a reserved header: err = %v, calls = %d", err, calls)
			}
			spec := CommandSpec{Method: "GET", PathTpl: "/items", Params: []ParamSpec{{Name: name, Flag: "key", In: InHeader, GoType: "string"}}, Security: &SecurityHint{Requirements: []SecurityRequirement{{Schemes: []SecurityScheme{{Type: "apiKey", In: "header", Param: name}}}}}}
			key := "synthetic"
			input := OperationInput{Values: map[string]any{boundParamKey(spec.Params[0]): &key}, Changed: map[string]bool{boundParamKey(spec.Params[0]): true}}
			opts.Auth = nil
			if _, err := InvokeOperation(context.Background(), spec, input, OperationOptions{Hostname: "https://api.example", Client: opts}); err == nil || calls != 0 {
				t.Errorf("declared API key accepted a reserved header: err = %v, calls = %d", err, calls)
			}
		})
	}
}
