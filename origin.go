package csrf

import (
	"fmt"
	"log"
	"net/url"
	"strings"
)

// TrustedOrigin is a parsed entry of the TrustedOrigins allow-list. An origin
// is defined as the tuple of URL scheme and host, where host includes the
// port (if any). Keeping both components is what allows the middleware to tell
// a secure "https://example.com" origin from a cleartext "http://example.com"
// one.
type TrustedOrigin struct {
	// Scheme is the lower-cased URL scheme, e.g. "https" or "http".
	Scheme string

	// Host is the lower-cased host including the optional port, e.g.
	// "example.com" or "example.com:8443".
	Host string
}

// ParseTrustedOrigin parses a single TrustedOrigins configuration entry into
// its structured scheme + host representation.
//
// Entries should be full origins of the form "scheme://host[:port]", such as
// "https://ui.example.com".
//
// Compatibility window: historical configuration only provided a bare host
// (for example "ui.example.com" or "ui.example.com:3000"). Such entries are
// still accepted and are treated as "https://<host>", the secure default. A
// future major release will reject scheme-less entries at startup instead;
// write them explicitly as "https://..." (or "http://..." for a deliberately
// cleartext/local origin).
//
// Empty entries and entries that do not contain a host are returned as an
// error so that invalid configuration is surfaced at startup rather than
// silently matching nothing.
func ParseTrustedOrigin(entry string) (TrustedOrigin, error) {
	raw := strings.TrimSpace(entry)
	if raw == "" {
		return TrustedOrigin{}, fmt.Errorf("csrf: invalid TrustedOrigins entry %q: origin must not be empty", entry)
	}

	// A bare "host[:port]" has no "://" separator. url.Parse would place such
	// a value in Path (and "host:port" can even be read as scheme:opaque), so
	// parse it in authority position by prefixing "//".
	if !strings.Contains(raw, "://") {
		authority := strings.TrimPrefix(raw, "//")
		parsed, err := url.Parse("//" + authority)
		if err != nil || parsed.Host == "" {
			return TrustedOrigin{}, fmt.Errorf(
				"csrf: invalid TrustedOrigins entry %q: expected host[:port] or scheme://host[:port]", entry)
		}

		log.Printf("gorilla/csrf: TrustedOrigins entry %q is missing a scheme; assuming https://%s for compatibility. "+
			"Set it explicitly; scheme-less hosts will be rejected at startup in a future release.",
			entry, parsed.Host)

		return TrustedOrigin{Scheme: "https", Host: strings.ToLower(parsed.Host)}, nil
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return TrustedOrigin{}, fmt.Errorf(
			"csrf: invalid TrustedOrigins entry %q: expected scheme://host[:port]", entry)
	}

	return TrustedOrigin{
		Scheme: strings.ToLower(parsed.Scheme),
		Host:   strings.ToLower(parsed.Host),
	}, nil
}

// parseTrustedOrigin is the unexported alias of ParseTrustedOrigin used inside
// the package.
func parseTrustedOrigin(entry string) (TrustedOrigin, error) {
	return ParseTrustedOrigin(entry)
}

// matches reports whether the parsed request URL origin is represented by the
// trusted entry. Both the scheme and the host (including port) must match;
// the scheme is never ignored.
func (origin TrustedOrigin) matches(u *url.URL) bool {
	if u == nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return strings.EqualFold(origin.Scheme, u.Scheme) &&
		strings.EqualFold(origin.Host, u.Host)
}

// matchTrustedOrigins reports whether u matches any of the pre-parsed trusted
// origins, comparing both scheme and host.
func matchTrustedOrigins(origins []TrustedOrigin, u *url.URL) bool {
	for _, origin := range origins {
		if origin.matches(u) {
			return true
		}
	}

	return false
}

// trustedOrigin reports whether u matches any entry of a raw TrustedOrigins
// configuration slice. Entries are parsed on each call, so request handling
// uses options.isTrustedOrigin (which reuses the values parsed once at
// startup) instead. This helper is retained as the package-level matching
// entry point for raw configuration and tests.
func trustedOrigin(trusted []string, u *url.URL) bool {
	for _, entry := range trusted {
		if origin, err := parseTrustedOrigin(entry); err == nil && origin.matches(u) {
			return true
		}
	}

	return false
}

// isTrustedOrigin reports whether u is present in the allow-list. It reuses
// the origins parsed when the options were applied and falls back to parsing
// the raw entries when the structured field was not populated (for example
// for an options value constructed directly in tests).
func (opts *options) isTrustedOrigin(u *url.URL) bool {
	if u == nil {
		return false
	}

	if len(opts.trustedOrigins) > 0 {
		return matchTrustedOrigins(opts.trustedOrigins, u)
	}

	return trustedOrigin(opts.TrustedOrigins, u)
}
