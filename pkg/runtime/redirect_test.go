package runtime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type redirectTransport func(*http.Request) (*http.Response, error)

func (f redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type redirectAuth func(*http.Request) error

func (f redirectAuth) Apply(req *http.Request) error { return f(req) }

func redirectResponse(req *http.Request, status int, location, body string) *http.Response {
	header := http.Header{"Content-Type": {"application/json"}}
	if location != "" {
		header.Set("Location", location)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func TestRedirectHeaderScope(t *testing.T) {
	credentials := []struct {
		name    string
		auth    Authenticator
		headers map[string]string
		key     string
		forward bool
	}{
		{name: "default API key", auth: APIKeyAuth{Key: "synthetic"}, key: "X-API-Key"},
		{name: "custom API key", auth: APIKeyAuth{Key: "synthetic", Header: "X-Custom-Token"}, key: "X-Custom-Token"},
		{name: "pointer API key", auth: &APIKeyAuth{Key: "synthetic", Header: "X-Pointer-Token"}, key: "X-Pointer-Token"},
		{name: "bearer", auth: BearerAuth{Token: "synthetic"}, key: "Authorization"},
		{name: "basic", auth: BasicAuth{Username: "synthetic", Password: "synthetic"}, key: "Authorization"},
		{name: "custom authenticator", auth: redirectAuth(func(req *http.Request) error {
			req.Header["x-extension-token"] = []string{"synthetic"}
			return nil
		}), key: "x-extension-token"},
		{name: "auth cookie", auth: redirectAuth(func(req *http.Request) error {
			req.AddCookie(&http.Cookie{Name: "session", Value: "synthetic"})
			return nil
		}), key: "Cookie"},
		{name: "option header", headers: map[string]string{"x-private-token": "synthetic"}, key: "X-Private-Token"},
		{name: "option cookie", headers: map[string]string{"Cookie": "session=synthetic"}, key: "Cookie"},
		{name: "option accept", headers: map[string]string{"Accept": "synthetic"}, key: "Accept", forward: true},
		{name: "option user agent", headers: map[string]string{"User-Agent": "synthetic"}, key: "User-Agent", forward: true},
	}
	origins := []struct {
		name, source, target string
		same                 bool
	}{
		{"same origin", "https://api.example/start", "https://api.example/end", true},
		{"host case", "https://api.example/start", "https://API.EXAMPLE/end", true},
		{"default port", "https://api.example/start", "https://api.example:443/end", true},
		{"http default port", "http://api.example/start", "http://api.example:80/end", true},
		{"other host", "https://api.example/start", "https://cdn.example/end", false},
		{"subdomain", "https://api.example/start", "https://child.api.example/end", false},
		{"other port", "https://api.example/start", "https://api.example:8443/end", false},
		{"downgrade", "https://api.example/start", "http://api.example/end", false},
		{"upgrade", "http://api.example/start", "https://api.example/end", false},
		{"IPv6 other port", "https://[::1]/start", "https://[::1]:8443/end", false},
	}
	for _, credential := range credentials {
		for _, origin := range origins {
			for _, status := range []int{301, 302, 303, 307, 308} {
				t.Run(credential.name+"/"+origin.name+"/"+http.StatusText(status), func(t *testing.T) {
					calls := 0
					opts := ClientOptions{Auth: credential.auth, Headers: credential.headers, MaxRetries: -1}
					opts.Transport = redirectTransport(func(req *http.Request) (*http.Response, error) {
						calls++
						sent := false
						for name, values := range req.Header {
							if strings.EqualFold(name, credential.key) && len(values) > 0 {
								sent = true
							}
						}
						want := calls == 1 || origin.same || credential.forward
						if sent != want {
							t.Errorf("hop %d sent %s = %t, want %t", calls, credential.key, sent, want)
						}
						if calls == 1 {
							return redirectResponse(req, status, origin.target, ""), nil
						}
						return redirectResponse(req, 200, "", `{}`), nil
					})
					result, err := DoRawFull(context.Background(), origin.source, http.MethodGet, "", nil, opts)
					if err != nil || result == nil || string(result.Body) != `{}` || calls != 2 {
						t.Fatalf("result = %v, err = %v, calls = %d", result, err, calls)
					}
				})
			}
		}
	}
}

func TestRedirectHeaderScopeMultiHop(t *testing.T) {
	for _, targets := range [][]string{
		{"https://cdn.example/one", "https://cdn.example/two"},
		{"https://api.example/one", "https://cdn.example/two", "https://cdn.example/three"},
		{"https://cdn.example/one", "https://api.example/two", "https://other.example/three"},
	} {
		t.Run(strings.Join(targets, ","), func(t *testing.T) {
			calls := 0
			crossed := false
			opts := ClientOptions{Auth: APIKeyAuth{Key: "synthetic"}, Headers: map[string]string{"X-Private": "synthetic"}, MaxRetries: -1}
			opts.Transport = redirectTransport(func(req *http.Request) (*http.Response, error) {
				crossed = crossed || req.URL.Host != "api.example"
				for _, key := range []string{"X-API-Key", "X-Private"} {
					if sent := req.Header.Get(key) != ""; sent == crossed {
						t.Errorf("hop %d sent %s = %t, crossed origin = %t", calls, key, sent, crossed)
					}
				}
				calls++
				if calls <= len(targets) {
					return redirectResponse(req, 302, targets[calls-1], ""), nil
				}
				return redirectResponse(req, 200, "", `{}`), nil
			})
			if _, err := DoRaw(context.Background(), "https://api.example", "GET", "/", nil, opts); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRedirectPreservesDownload(t *testing.T) {
	for _, binary := range []bool{false, true} {
		calls := 0
		opts := ClientOptions{Auth: APIKeyAuth{Key: "synthetic"}, Accept: "application/octet-stream", UserAgent: "synthetic-agent", MaxRetries: -1}
		opts.Transport = redirectTransport(func(req *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return redirectResponse(req, 307, "https://cdn.example/download?signature=synthetic", ""), nil
			}
			if req.Header.Get("X-API-Key") != "" || req.Header.Get("Accept") != opts.Accept || req.Header.Get("User-Agent") != opts.UserAgent || req.URL.Query().Get("signature") != "synthetic" {
				t.Error("download headers or signature did not meet the redirect contract")
			}
			body := `{}`
			if binary {
				body = "\x00\x01\xff"
			}
			return redirectResponse(req, 200, "", body), nil
		})
		var stream strings.Builder
		var out io.Writer
		if binary {
			out = &stream
		}
		result, err := doRawFull(context.Background(), "https://api.example", "GET", "/", nil, opts, out)
		if err != nil || result == nil || result.StatusCode != 200 || calls != 2 {
			t.Fatalf("download failed: result = %v, err = %v, calls = %d", result, err, calls)
		}
		if binary && stream.String() != "\x00\x01\xff" || !binary && string(result.Body) != `{}` {
			t.Error("download body changed")
		}
	}
}

func TestRedirectPreservesPolicyAndLimit(t *testing.T) {
	sentinel := errors.New("custom redirect policy")
	for _, policy := range []func(*http.Request, []*http.Request) error{nil, func(*http.Request, []*http.Request) error { return sentinel }} {
		calls := 0
		opts := ClientOptions{MaxRetries: -1, checkRedirect: policy, Transport: redirectTransport(func(req *http.Request) (*http.Response, error) {
			calls++
			return redirectResponse(req, 302, "/again", ""), nil
		})}
		_, err := DoRaw(context.Background(), "https://api.example", "GET", "/", nil, opts)
		if policy == nil {
			if err == nil || calls != 10 {
				t.Fatalf("default redirect limit: err = %v, calls = %d", err, calls)
			}
		} else if !errors.Is(err, sentinel) || calls != 1 {
			t.Fatalf("custom policy: err = %v, calls = %d", err, calls)
		}
	}
}

func TestHTTPClientScopesRequestHeaders(t *testing.T) {
	calls := 0
	auth := redirectAuth(func(req *http.Request) error {
		req.Header.Set("X-Caller-Auth", "synthetic")
		return nil
	})
	opts := ClientOptions{Auth: auth, Headers: map[string]string{"X-Caller-Option": "synthetic"}, MaxRetries: -1}
	opts.Transport = redirectTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		for _, key := range []string{"X-Caller-Auth", "X-Caller-Option"} {
			if sent := req.Header.Get(key) != ""; sent != (calls == 1) {
				t.Errorf("hop %d sent %s = %t", calls, key, sent)
			}
		}
		if calls == 1 {
			return redirectResponse(req, 302, "https://cdn.example/end", ""), nil
		}
		return redirectResponse(req, 200, "", `{}`), nil
	})
	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://api.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.Apply(req); err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Caller-Option", "synthetic")
	resp, err := HTTPClient(opts).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if calls != 2 || resp.StatusCode != 200 {
		t.Fatalf("calls = %d, status = %d", calls, resp.StatusCode)
	}
}

func TestRedirectPreservesReplayedBody(t *testing.T) {
	calls := 0
	payload := map[string]string{"action": "synthetic"}
	opts := ClientOptions{Auth: APIKeyAuth{Key: "synthetic"}, MaxRetries: -1}
	opts.Transport = redirectTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		if req.Method != "POST" || string(body) != `{"action":"synthetic"}` || req.Header.Get("Content-Type") != "application/json" {
			t.Errorf("hop %d did not preserve the request body contract", calls)
		}
		if calls == 1 {
			return redirectResponse(req, 307, "https://cdn.example/end", ""), nil
		}
		if req.Header.Get("X-API-Key") != "" {
			t.Error("redirect forwarded the API key")
		}
		return redirectResponse(req, 200, "", `{}`), nil
	})
	if _, err := DoRaw(context.Background(), "https://api.example", "POST", "/", payload, opts); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestRedirectClearsRefererAndCallbackHeaders(t *testing.T) {
	calls := 0
	opts := ClientOptions{MaxRetries: -1, checkRedirect: func(req *http.Request, _ []*http.Request) error {
		req.Header.Set("X-Callback-Token", "synthetic")
		return nil
	}}
	opts.Transport = redirectTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return redirectResponse(req, 302, "https://cdn.example/end", ""), nil
		}
		if req.Header.Get("Referer") != "" || req.Header.Get("X-Callback-Token") != "" {
			t.Error("redirect forwarded a source URL or callback header")
		}
		return redirectResponse(req, 200, "", `{}`), nil
	})
	if _, err := DoRaw(context.Background(), "https://api.example", "GET", "/?token=synthetic", nil, opts); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestRedirectLimitWithCustomPolicy(t *testing.T) {
	calls := 0
	opts := ClientOptions{MaxRetries: -1, checkRedirect: func(*http.Request, []*http.Request) error { return nil }}
	opts.Transport = redirectTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls > 10 {
			return redirectResponse(req, 200, "", `{}`), nil
		}
		return redirectResponse(req, 302, "/again", ""), nil
	})
	if _, err := DoRaw(context.Background(), "https://api.example", "GET", "/", nil, opts); err == nil || calls != 10 {
		t.Fatalf("err = %v, calls = %d", err, calls)
	}
}

func TestRedirectPolicyCanReturnLastResponse(t *testing.T) {
	calls := 0
	opts := ClientOptions{MaxRetries: -1, checkRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	opts.Transport = redirectTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		return redirectResponse(req, 302, "/again", "response"), nil
	})
	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://api.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := HTTPClient(opts).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "response" || calls != 1 {
		t.Fatalf("body = %q, err = %v, calls = %d", body, err, calls)
	}
}

func TestRedirectScopesRefreshedAuth(t *testing.T) {
	calls, refreshes := 0, 0
	opts := ClientOptions{Auth: APIKeyAuth{Key: "synthetic-old"}, MaxRetries: -1}
	opts.RefreshAuth = func(context.Context) (Authenticator, error) {
		refreshes++
		return APIKeyAuth{Key: "synthetic-new", Header: "X-Refreshed-Token"}, nil
	}
	opts.Transport = redirectTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			if req.Header.Get("X-API-Key") != "synthetic-old" {
				t.Error("initial auth was missing")
			}
			return redirectResponse(req, 401, "", `{}`), nil
		case 2:
			if req.Header.Get("X-Refreshed-Token") != "synthetic-new" {
				t.Error("refreshed auth was missing")
			}
			return redirectResponse(req, 302, "https://cdn.example/end", ""), nil
		default:
			if req.Header.Get("X-API-Key") != "" || req.Header.Get("X-Refreshed-Token") != "" {
				t.Error("redirect forwarded refreshed auth")
			}
			return redirectResponse(req, 200, "", `{}`), nil
		}
	})
	if _, err := DoRaw(context.Background(), "https://api.example", "GET", "/", nil, opts); err != nil {
		t.Fatal(err)
	}
	if calls != 3 || refreshes != 1 {
		t.Fatalf("calls = %d, refreshes = %d", calls, refreshes)
	}
}
