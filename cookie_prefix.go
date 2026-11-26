package csrf

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Supported cookie name prefixes defined by RFC 6265bis.
const (
	// HostCookiePrefix marks a host-only cookie requiring Secure, Path=/, and no Domain.
	HostCookiePrefix = "__Host-"
	// SecureCookiePrefix marks a cookie requiring the Secure attribute.
	SecureCookiePrefix = "__Secure-"
)

// ErrInvalidCookiePrefix is returned when a cookie name prefix requires
// attributes that the middleware configuration does not provide.
var ErrInvalidCookiePrefix = errors.New("invalid cookie prefix configuration")

type cookiePrefixRequirements struct {
	secure          bool
	path            string
	domainForbidden bool
}

func cookiePrefixRules(name string) (cookiePrefixRequirements, bool) {
	switch {
	case strings.HasPrefix(name, HostCookiePrefix):
		return cookiePrefixRequirements{
			secure:          true,
			path:            "/",
			domainForbidden: true,
		}, true
	case strings.HasPrefix(name, SecureCookiePrefix):
		return cookiePrefixRequirements{secure: true}, true
	default:
		return cookiePrefixRequirements{}, false
	}
}

// ValidateCookieName checks browser-enforced cookie prefix rules.
//
// A __Host- prefix requires Secure, Path="/", and no Domain. A __Secure-
// prefix requires Secure. Names without a recognized prefix are accepted.
func ValidateCookieName(name string, secure bool, path, domain string) error {
	rules, ok := cookiePrefixRules(name)
	if !ok {
		return nil
	}

	var problems []string
	if rules.secure && !secure {
		problems = append(problems, "Secure must be true")
	}
	if rules.path != "" && path != rules.path {
		problems = append(problems, fmt.Sprintf("Path must be %q", rules.path))
	}
	if rules.domainForbidden && domain != "" {
		problems = append(problems, "Domain must be empty")
	}

	if len(problems) == 0 {
		return nil
	}

	return fmt.Errorf("%w for cookie %q: %s",
		ErrInvalidCookiePrefix, name, strings.Join(problems, "; "))
}

// ValidateCookiePrefix validates name as either a full cookie name or a
// cookie prefix. See ValidateCookieName for the prefix requirements.
func ValidateCookiePrefix(name string, secure bool, path, domain string) error {
	return ValidateCookieName(name, secure, path, domain)
}

func validateCookiePrefix(name string, secure bool, path, domain string) error {
	return ValidateCookieName(name, secure, path, domain)
}

// ValidateOptions applies options to a temporary configuration and checks
// cookie prefix requirements without constructing the middleware handler.
func ValidateOptions(opts ...Option) error {
	cs := parseOptions(nil, opts...)
	return cs.prepareCookieOptions()
}

func (cs *csrf) prepareCookieOptions() error {
	opts := &cs.opts

	if opts.CookieName == "" {
		opts.CookieName = cookieName
	}

	if opts.CookiePrefix != "" && !strings.HasPrefix(opts.CookieName, opts.CookiePrefix) {
		opts.CookieName = opts.CookiePrefix + opts.CookieName
	}

	if strings.HasPrefix(opts.CookieName, HostCookiePrefix) && opts.Path == "" {
		opts.Path = "/"
	}

	if err := ValidateCookieName(opts.CookieName, opts.Secure, opts.Path, opts.Domain); err != nil {
		return err
	}

	names := make([]string, 0, len(opts.FallbackCookieNames)+2)
	seen := map[string]struct{}{opts.CookieName: {}}
	addName := func(name string) {
		if name == "" || name == opts.CookieName {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}

	for _, name := range opts.FallbackCookieNames {
		addName(name)
	}
	if opts.CookieNameFallback != "" {
		addName(opts.CookieNameFallback)
	}
	if opts.FallbackCookieName != "" {
		addName(opts.FallbackCookieName)
	}
	if opts.LegacyCookieName != "" {
		addName(opts.LegacyCookieName)
	}
	if opts.CookiePrefixFallback {
		if opts.CookiePrefix != "" {
			addName(strings.TrimPrefix(opts.CookieName, opts.CookiePrefix))
		}
		if prefix := cookiePrefixForName(opts.CookieName); prefix != "" {
			addName(strings.TrimPrefix(opts.CookieName, prefix))
		}
		addName(cookieName)
	}

	opts.FallbackCookieNames = names
	return nil
}

func cookiePrefixForName(name string) string {
	if strings.HasPrefix(name, HostCookiePrefix) {
		return HostCookiePrefix
	}
	if strings.HasPrefix(name, SecureCookiePrefix) {
		return SecureCookiePrefix
	}
	return ""
}

type fallbackCookieStore struct {
	*cookieStore
	fallbackNames []string
}

func (s *fallbackCookieStore) Get(r *http.Request) ([]byte, error) {
	token, _, err := s.GetWithSource(r)
	return token, err
}

func (s *fallbackCookieStore) GetWithSource(r *http.Request) ([]byte, string, error) {
	token, err := s.cookieStore.Get(r)
	if err == nil {
		return token, s.name, nil
	}

	var decodeErrs []error
	decodeErrs = append(decodeErrs, err)

	for _, name := range s.fallbackNames {
		cookie, cookieErr := r.Cookie(name)
		if cookieErr != nil {
			decodeErrs = append(decodeErrs, cookieErr)
			continue
		}

		candidate := make([]byte, tokenLength)
		if decodeErr := s.sc.Decode(name, cookie.Value, &candidate); decodeErr != nil {
			decodeErrs = append(decodeErrs, decodeErr)
			continue
		}

		return candidate, name, nil
	}

	return nil, "", errors.Join(decodeErrs...)
}
