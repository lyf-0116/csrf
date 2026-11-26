package csrf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFeedbackValidateCookieNamePrefixes(t *testing.T) {
	tests := []struct {
		name    string
		cookie  string
		secure  bool
		path    string
		domain  string
		wantErr bool
	}{
		{name: "plain", cookie: "_gorilla_csrf", secure: false, path: "/forms", domain: "example.com"},
		{name: "secure prefix valid", cookie: "__Secure-csrf", secure: true},
		{name: "secure prefix requires secure", cookie: "__Secure-csrf", wantErr: true},
		{name: "host prefix valid", cookie: "__Host-csrf", secure: true, path: "/"},
		{name: "host prefix requires secure", cookie: "__Host-csrf", path: "/", wantErr: true},
		{name: "host prefix requires root path", cookie: "__Host-csrf", secure: true, path: "/forms", wantErr: true},
		{name: "host prefix rejects domain", cookie: "__Host-csrf", secure: true, path: "/", domain: "example.com", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCookieName(tt.cookie, tt.secure, tt.path, tt.domain)
			if tt.wantErr && err == nil {
				t.Fatal("expected prefix validation error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected prefix validation error: %v", err)
			}
		})
	}
}

func TestFeedbackHostCookiePrefixRoundTrip(t *testing.T) {
	var token string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	})

	handler := Protect(testKey,
		CookieName("__Host-gorilla_csrf"),
		Path("/"),
	)(mux)

	getRequest := createRequest(http.MethodGet, "/", true)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, getRequest)

	if recorder.Code != http.StatusOK {
		t.Fatalf("GET failed: got %d want %d", recorder.Code, http.StatusOK)
	}

	setCookie := recorder.Header().Get("Set-Cookie")
	if !strings.HasPrefix(setCookie, "__Host-gorilla_csrf=") {
		t.Fatalf("missing __Host cookie name: %q", setCookie)
	}
	for _, attribute := range []string{"Secure", "Path=/", "HttpOnly"} {
		if !strings.Contains(setCookie, attribute) {
			t.Fatalf("Set-Cookie %q does not contain %s", setCookie, attribute)
		}
	}
	if strings.Contains(setCookie, "Domain=") {
		t.Fatalf("__Host cookie must not set Domain: %q", setCookie)
	}

	postRequest := createRequest(http.MethodPost, "/", true)
	postRequest.Header.Set("Cookie", setCookie)
	postRequest.Header.Set(headerName, token)
	postRequest.Header.Set("Referer", "https://www.gorillatoolkit.org/")

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, postRequest)

	if recorder.Code != http.StatusOK {
		t.Fatalf("prefixed cookie/token POST failed: got %d want %d", recorder.Code, http.StatusOK)
	}
}

func TestFeedbackCookiePrefixOptionBuildsHostName(t *testing.T) {
	handler := Protect(testKey, CookiePrefix(HostCookiePrefix))(testHandler).(*csrf)
	if handler.opts.CookieName != HostCookiePrefix+cookieName {
		t.Fatalf("unexpected cookie name: got %q want %q",
			handler.opts.CookieName, HostCookiePrefix+cookieName)
	}
	if handler.opts.Path != "/" {
		t.Fatalf("host prefix did not default Path to /: got %q", handler.opts.Path)
	}
}

func TestFeedbackCookiePrefixInvalidConfigurationPanics(t *testing.T) {
	tests := [][]Option{
		{CookieName("__Host-csrf"), Secure(false), Path("/")},
		{CookieName("__Host-csrf"), Secure(true), Path("/not-root")},
		{CookieName("__Host-csrf"), Secure(true), Path("/"), Domain("example.com")},
		{CookieName("__Secure-csrf"), Secure(false)},
	}

	for i, options := range tests {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("test case %d: expected invalid prefix configuration to panic", i)
				}
			}()
			Protect(testKey, options...)(testHandler)
		}()
	}
}

func TestFeedbackCookieNameFallbackMigratesLegacyCookie(t *testing.T) {
	const legacyName = "legacy_csrf"
	const hostName = "__Host-csrf"

	var token string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	})

	legacyHandler := Protect(testKey, CookieName(legacyName))(mux)
	getRequest := createRequest(http.MethodGet, "/", false)
	legacyRecorder := httptest.NewRecorder()
	legacyHandler.ServeHTTP(legacyRecorder, getRequest)
	if legacyRecorder.Code != http.StatusOK {
		t.Fatalf("legacy GET failed: %d", legacyRecorder.Code)
	}
	legacyCookie := legacyRecorder.Header().Get("Set-Cookie")

	prefixedHandler := Protect(testKey,
		CookieName(hostName),
		Path("/"),
		CookieNameFallback(legacyName),
	)(mux)

	postRequest := createRequest(http.MethodPost, "/", false)
	postRequest.Header.Set("Cookie", legacyCookie)
	postRequest.Header.Set(headerName, token)

	recorder := httptest.NewRecorder()
	prefixedHandler.ServeHTTP(recorder, postRequest)

	if recorder.Code != http.StatusOK {
		t.Fatalf("fallback cookie POST failed: got %d want %d", recorder.Code, http.StatusOK)
	}

	newCookie := recorder.Header().Get("Set-Cookie")
	if !strings.HasPrefix(newCookie, hostName+"=") {
		t.Fatalf("fallback success did not issue primary cookie: %q", newCookie)
	}

	secondPost := createRequest(http.MethodPost, "/", false)
	secondPost.Header.Set("Cookie", newCookie)
	secondPost.Header.Set(headerName, token)
	secondRecorder := httptest.NewRecorder()
	prefixedHandler.ServeHTTP(secondRecorder, secondPost)
	if secondRecorder.Code != http.StatusOK {
		t.Fatalf("primary cookie POST failed after migration: got %d want %d",
			secondRecorder.Code, http.StatusOK)
	}
}

func TestFeedbackCookiePrefixFallbackSwitchAddsUnprefixedName(t *testing.T) {
	handler := Protect(testKey,
		CookieName("__Host-custom_csrf"),
		CookiePrefixFallback(),
	)(testHandler).(*csrf)

	foundUnprefixed := false
	foundDefault := false
	for _, name := range handler.opts.FallbackCookieNames {
		if name == "custom_csrf" {
			foundUnprefixed = true
		}
		if name == cookieName {
			foundDefault = true
		}
	}
	if !foundUnprefixed || !foundDefault {
		t.Fatalf("fallback switch did not add expected names: %#v",
			handler.opts.FallbackCookieNames)
	}
}
