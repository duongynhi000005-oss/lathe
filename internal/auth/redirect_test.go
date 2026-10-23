package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/lathe-cli/lathe/pkg/config"
	"github.com/lathe-cli/lathe/pkg/runtime"
)

func TestValidateScopesRedirectHeaders(t *testing.T) {
	var sourceCalls, targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		targetCalls.Add(1)
		if req.Header.Get("X-Validate-Token") != "" || req.Header.Get("X-Validate-Option") != "" {
			t.Error("redirect forwarded validation headers")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"username":"synthetic"}`))
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sourceCalls.Add(1)
		if req.Header.Get("X-Validate-Token") != "synthetic" || req.Header.Get("X-Validate-Option") != "synthetic" {
			t.Error("initial request omitted validation headers")
		}
		http.Redirect(w, req, target.URL, http.StatusFound)
	}))
	defer source.Close()
	result, err := validateWithAuth(context.Background(), source.URL, runtime.APIKeyAuth{Key: "synthetic", Header: "X-Validate-Token"}, &config.AuthValidate{
		Path: "/validate", Display: config.AuthValidateDisplay{UsernameField: "username"},
	}, runtime.ClientOptions{Headers: map[string]string{"X-Validate-Option": "synthetic"}})
	if err != nil || result.Username != "synthetic" || sourceCalls.Load() != 1 || targetCalls.Load() != 1 {
		t.Fatalf("result = %v, err = %v, calls = %d/%d", result, err, sourceCalls.Load(), targetCalls.Load())
	}
}
