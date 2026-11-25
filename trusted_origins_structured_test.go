package csrf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestParseTrustedOriginStructured(t *testing.T) {
	cases := []struct {
		entry   string
		want    TrustedOrigin
		wantErr bool
	}{
		{"https://example.com", TrustedOrigin{Scheme: "https", Host: "example.com"}, false},
		{"HTTPS://Example.COM", TrustedOrigin{Scheme: "https", Host: "example.com"}, false},
		{"http://example.com:8080", TrustedOrigin{Scheme: "http", Host: "example.com:8080"}, false},
		{"https://example.com:8443/path?x=1", TrustedOrigin{Scheme: "https", Host: "example.com:8443"}, false},
		{"https://example.com/", TrustedOrigin{Scheme: "https", Host: "example.com"}, false},
		// Compatibility window: bare hosts default to https.
		{"example.com", TrustedOrigin{Scheme: "https", Host: "example.com"}, false},
		{"example.com:3000", TrustedOrigin{Scheme: "https", Host: "example.com:3000"}, false},
		{"//example.com", TrustedOrigin{Scheme: "https", Host: "example.com"}, false},
		// Invalid configuration must be reported.
		{"", TrustedOrigin{}, true},
		{"   ", TrustedOrigin{}, true},
		{"https://", TrustedOrigin{}, true},
		{"://nohost", TrustedOrigin{}, true},
	}

	for _, tc := range cases {
		t.Run(tc.entry, func(t *testing.T) {
			got, err := ParseTrustedOrigin(tc.entry)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseTrustedOrigin(%q) expected error, got %+v", tc.entry, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTrustedOrigin(%q) unexpected error: %v", tc.entry, err)
			}
			if got != tc.want {
				t.Fatalf("ParseTrustedOrigin(%q) = %+v, want %+v", tc.entry, got, tc.want)
			}
		})
	}
}

func TestTrustedOriginRawHelper(t *testing.T) {
	httpsOrigin, err := url.Parse("https://golang.org/path")
	if err != nil {
		t.Fatal(err)
	}
	httpOrigin, err := url.Parse("http://golang.org")
	if err != nil {
		t.Fatal(err)
	}

	if !trustedOrigin([]string{"golang.org"}, httpsOrigin) {
		t.Fatal("bare host entry should match an https origin during compatibility window")
	}
	if trustedOrigin([]string{"golang.org"}, httpOrigin) {
		t.Fatal("bare host entry defaults to https and must not match a cleartext http origin")
	}
	if !trustedOrigin([]string{"https://golang.org"}, httpsOrigin) {
		t.Fatal("full https://host entry should match the https origin")
	}
	if trustedOrigin([]string{"https://golang.org"}, httpOrigin) {
		t.Fatal("https://host entry must not match an http origin: scheme has to compare equal")
	}
	if !trustedOrigin([]string{"http://golang.org"}, httpOrigin) {
		t.Fatal("explicit http://host entry should match the http origin")
	}
	if trustedOrigin([]string{"http://golang.org"}, httpsOrigin) {
		t.Fatal("http://host entry must not match an https origin")
	}
	if trustedOrigin([]string{"https://golang.org"}, mustParseOriginTestURL(t, "https://golang.org.evil.com")) {
		t.Fatal("suffix look-alike host must not match")
	}
	if trustedOrigin([]string{"https://golang.org:8443"}, httpsOrigin) {
		t.Fatal("entry with a different port must not match")
	}
}

func mustParseOriginTestURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestTrustedOriginsInvalidEntryPanics(t *testing.T) {
	for _, entry := range []string{"", "   ", "https://"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("TrustedOrigins(%q) expected a startup panic", entry)
				}
			}()
			TrustedOrigins([]string{entry})
		}()
	}
}

// TestTrustedOriginsOriginHeaderMatrix drives real requests through Protect and
// proves that full origins match and that the scheme is compared.
func TestTrustedOriginsOriginHeaderMatrix(t *testing.T) {
	cases := []struct {
		name    string
		trusted []string
		origin  string
		useTLS  bool
		want    int
	}{
		{"full https origin matches", []string{"https://ui.example.com"}, "https://ui.example.com", true, http.StatusOK},
		{"full https origin blocks http downgrade", []string{"https://ui.example.com"}, "http://ui.example.com", true, http.StatusForbidden},
		{"explicit http origin matches cleartext", []string{"http://ui.example.com"}, "http://ui.example.com", false, http.StatusOK},
		{"explicit http origin does not match https", []string{"http://ui.example.com"}, "https://ui.example.com", true, http.StatusForbidden},
		{"bare host matches https in compat window", []string{"ui.example.com"}, "https://ui.example.com", true, http.StatusOK},
		{"bare host blocks cleartext http via secure default", []string{"ui.example.com"}, "http://ui.example.com", false, http.StatusForbidden},
		{"unrelated host rejected", []string{"https://ui.example.com"}, "https://evil.example.com", true, http.StatusForbidden},
		{"port exact match allowed", []string{"https://ui.example.com:8443"}, "https://ui.example.com:8443", true, http.StatusOK},
		{"port mismatch rejected", []string{"https://ui.example.com:8443"}, "https://ui.example.com", true, http.StatusForbidden},
		{"trailing slash entry matches origin", []string{"https://ui.example.com/"}, "https://ui.example.com", true, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			var token string
			mux.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				token = Token(r)
			}))

			handler := Protect(testKey, TrustedOrigins(tc.trusted))(mux)

			getRequest := createRequest(http.MethodGet, "/", tc.useTLS)
			getRecorder := httptest.NewRecorder()
			handler.ServeHTTP(getRecorder, getRequest)

			postRequest := createRequest(http.MethodPost, "/", tc.useTLS)
			setCookie(getRecorder, postRequest)
			postRequest.Header.Set("X-CSRF-Token", token)
			postRequest.Header.Set("Origin", tc.origin)

			postRecorder := httptest.NewRecorder()
			handler.ServeHTTP(postRecorder, postRequest)

			if postRecorder.Code != tc.want {
				t.Fatalf("origin %q against trusted %v: got status %d, want %d",
					tc.origin, tc.trusted, postRecorder.Code, tc.want)
			}
		})
	}
}
