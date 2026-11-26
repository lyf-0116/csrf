package csrf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestOriginPolicyPortOptionWiring(t *testing.T) {
	newReq := func() *http.Request {
		r := createRequest("POST", "/", false)
		r.Header.Set("Origin", "http://www.gorillatoolkit.org:8080")
		return r
	}
	run := func(comparePort bool) error {
		var reason error
		h := Protect(testKey, ComparePort(comparePort), ErrorHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			reason = FailureReason(r)
		})))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		h.ServeHTTP(httptest.NewRecorder(), newReq())
		return reason
	}

	if err := run(false); err != ErrNoToken {
		t.Fatalf("default should pass origin check and fail at token lookup: %v", err)
	}
	if err := run(true); err != ErrBadOrigin {
		t.Fatalf("ComparePort(true) should reject cross-port origin: %v", err)
	}
}

func TestOriginPolicySecureFalseAllowsHTTPOrigin(t *testing.T) {
	var token string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		token = Token(r)
	})

	handler := Protect(testKey, Secure(false))(mux)

	getRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	getRequest.Host = "localhost:8080"
	getRecorder := httptest.NewRecorder()
	handler.ServeHTTP(getRecorder, getRequest)
	if getRecorder.Code != http.StatusOK || token == "" {
		t.Fatalf("token request failed: code=%d token=%q", getRecorder.Code, token)
	}

	postRequest := httptest.NewRequest(http.MethodPost, "/", nil)
	postRequest.Host = "localhost:8080"
	postRequest.Header.Set("Origin", "http://localhost:8080")
	setCookie(getRecorder, postRequest)
	postRequest.Header.Set("X-CSRF-Token", token)
	postRecorder := httptest.NewRecorder()
	handler.ServeHTTP(postRecorder, postRequest)

	if postRecorder.Code != http.StatusOK {
		t.Fatalf("Secure(false) should normalize request origin to HTTP: code=%d reason=%v", postRecorder.Code, FailureReason(postRequest))
	}
}

func TestOriginPolicyRouteResolver(t *testing.T) {
	reasonFor := func(path string) error {
		var reason error
		errorHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			reason = FailureReason(r)
		})
		csrfHandler := Protect(testKey,
			WithOriginPolicyResolver(func(r *http.Request, policy OriginPolicy) OriginPolicy {
				policy.ComparePort = r.URL.Path == "/strict"
				return policy
			}),
			ErrorHandler(errorHandler),
		)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

		req := createRequest(http.MethodPost, path, false)
		req.Header.Set("Origin", "http://www.gorillatoolkit.org:8080")
		csrfHandler.ServeHTTP(httptest.NewRecorder(), req)
		return reason
	}

	if err := reasonFor("/token"); err != ErrNoToken {
		t.Fatalf("non-strict route should ignore port and continue to token check: %v", err)
	}
	if err := reasonFor("/strict"); err != ErrBadOrigin {
		t.Fatalf("strict route should compare ports: %v", err)
	}
}

func TestOriginPolicyParseTuple(t *testing.T) {
	cases := []struct {
		in   string
		want Origin
	}{
		{"https://example.com:8443/path", Origin{Scheme: "https", Host: "example.com", Port: "8443"}},
		{"example.com:8443", Origin{Scheme: "https", Host: "example.com", Port: "8443"}},
		{"example.com", Origin{Scheme: "https", Host: "example.com", Port: ""}},
		{"http://localhost:3000", Origin{Scheme: "http", Host: "localhost", Port: "3000"}},
	}
	for _, tc := range cases {
		got, err := ParseOrigin(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %+v want %+v", tc.in, got, tc.want)
		}
	}
}

func TestOriginPolicyPortSwitchAndForms(t *testing.T) {
	target := mustParsePolicyTestURL(t, "https://app.example.com")
	source := mustParsePolicyTestURL(t, "https://app.example.com:8443")

	if !sameOrigin(target, source) {
		t.Fatal("default policy should ignore port")
	}
	if sameOriginWithPortComparison(target, source, true) {
		t.Fatal("explicit port policy should compare port")
	}

	for _, entry := range []string{"example.com", "https://example.com", "https://example.com/path"} {
		u := mustParsePolicyTestURL(t, "https://example.com")
		if !trustedOrigin([]string{entry}, u) {
			t.Fatalf("entry %q should match full https origin", entry)
		}
	}

	policy := OriginPolicy{TrustedOrigins: []Origin{{Scheme: "https", Host: "example.com"}}}
	if !policy.Trusted(mustParsePolicyTestURL(t, "https://example.com:9443")) {
		t.Fatal("default policy should ignore trusted port")
	}
	policy.ComparePort = true
	if policy.Trusted(mustParsePolicyTestURL(t, "https://example.com:9443")) {
		t.Fatal("port-aware policy should reject differing effective ports")
	}
	if !policy.Trusted(mustParsePolicyTestURL(t, "https://example.com:443")) {
		t.Fatal("default port should normalize to 443")
	}
}

func TestOriginPolicyHeaderParityAndTokenEntry(t *testing.T) {
	trusted := []string{"https://front.example:3000"}

	originReq := newPolicyTestRequest("POST", "https://api.example/submit", true)
	originReq.Host = "api.example"
	originReq.Header.Set("Origin", "https://front.example:3000")
	if err := Protect(testKey, TrustedOrigins(trusted))(nil).(*csrf).opts.originPolicyForRequest(originReq).Check(originReq); err != nil {
		t.Fatalf("origin path: %v", err)
	}

	refererReq := newPolicyTestRequest("POST", "https://api.example/submit", true)
	refererReq.Host = "api.example"
	refererReq.Header.Set("Referer", "https://front.example:3000/page")
	if err := Protect(testKey, TrustedOrigins(trusted))(nil).(*csrf).opts.originPolicyForRequest(refererReq).Check(refererReq); err != nil {
		t.Fatalf("referer path: %v", err)
	}

	badTokenReq := createRequest("GET", "/token", true)
	badTokenReq.Header.Set("Origin", "https://evil.example")
	rr := httptest.NewRecorder()
	var token string
	h := Protect(testKey, TrustedOrigins(trusted))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))
	h.ServeHTTP(rr, badTokenReq)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("token entry should reject bad origin: code=%d", rr.Code)
	}
	if token != "" {
		t.Fatal("rejected token entry should not expose token")
	}
	if rr.Header().Get("Set-Cookie") != "" {
		t.Fatal("rejected token entry should not generate/save a cookie")
	}

	goodTokenReq := createRequest("GET", "/token", true)
	goodTokenReq.Header.Set("Origin", "https://www.gorillatoolkit.org")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, goodTokenReq)
	if rr.Code != http.StatusOK || token == "" || rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("same-origin token entry should pass: code=%d token=%q cookie=%q", rr.Code, token, rr.Header().Get("Set-Cookie"))
	}
}

func mustParsePolicyTestURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func newPolicyTestRequest(method, target string, tls bool) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	if !tls {
		r = PlaintextHTTPRequest(r)
	}
	return r
}
