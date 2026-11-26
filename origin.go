package csrf

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const originPolicyContextKey = "gorilla.csrf.OriginPolicy"

// Origin is the canonical origin tuple used by all source checks. Host is the
// hostname without its port; Port is the port explicitly present in the
// configuration or request URL. Use EffectivePort when a default port is
// relevant.
type Origin struct {
	Scheme string
	Host   string
	Port   string
}

// origin is an internal alias for tests and callers that prefer the
// unexported name.
type origin = Origin

// TrustedOrigin, OriginInfo and OriginTriplet are descriptive aliases for
// Origin.
type (
	TrustedOrigin = Origin
	OriginInfo    = Origin
	OriginTriplet = Origin
)

// OriginPolicy is the single source-checking policy used by request
// validation, token issuance and the middleware.
type OriginPolicy struct {
	// TrustedOrigins contains the normalized allow-list entries.
	TrustedOrigins []Origin

	// ComparePort controls whether the port component is compared. The zero
	// value preserves the historical host-only matching behavior for
	// cross-port deployments.
	ComparePort bool

	// AllowHTTP uses the HTTP scheme when synthesizing the request origin.
	// Protect sets this from Secure(false). It does not replace the explicit
	// PlaintextHTTPContextKey signal used to disable strict Referer checks.
	AllowHTTP bool
}

// OriginPolicyResolver can specialize the base policy for a request or route.
type OriginPolicyResolver func(r *http.Request, policy OriginPolicy) OriginPolicy

func (opts *options) originPolicyForRequest(r *http.Request) OriginPolicy {
	trusted := opts.trustedOrigins
	if len(opts.TrustedOrigins) > 0 && len(trusted) != len(opts.TrustedOrigins) {
		trusted = parseTrustedOriginsLenient(opts.TrustedOrigins)
	}

	policy := OriginPolicy{
		TrustedOrigins: trusted,
		ComparePort:    opts.ComparePort,
		AllowHTTP:      opts.AllowHTTP || !opts.Secure,
	}
	if opts.policyResolver != nil {
		policy = opts.policyResolver(r, policy)
	}
	return policy
}

func parseTrustedOriginsLenient(entries []string) []Origin {
	origins := make([]Origin, 0, len(entries))
	for _, entry := range entries {
		if parsed, err := ParseOrigin(entry); err == nil {
			origins = append(origins, parsed)
		}
	}
	return origins
}

// OriginPolicy installs a complete origin policy, including its normalized
// allow-list and port-comparison setting.
func WithOriginPolicy(policy OriginPolicy) Option {
	return func(cs *csrf) {
		cs.opts.TrustedOrigins = make([]string, 0, len(policy.TrustedOrigins))
		cs.opts.trustedOrigins = append([]Origin(nil), policy.TrustedOrigins...)
		cs.opts.ComparePort = policy.ComparePort
		cs.opts.AllowHTTP = policy.AllowHTTP
		for _, origin := range policy.TrustedOrigins {
			cs.opts.TrustedOrigins = append(cs.opts.TrustedOrigins, origin.String())
		}
	}
}

// WithOriginPolicyResolver installs a hook that can vary the policy by route
// or request. The returned policy is then shared by middleware, validation and
// token access for that request.
func WithOriginPolicyResolver(resolver OriginPolicyResolver) Option {
	return func(cs *csrf) {
		cs.opts.policyResolver = resolver
	}
}

// ResolveOriginPolicy is an alias for WithOriginPolicyResolver.
func ResolveOriginPolicy(resolver OriginPolicyResolver) Option {
	return WithOriginPolicyResolver(resolver)
}

// ParseOrigin normalizes either a bare host[:port] entry or a full
// scheme://host[:port] origin. Bare entries retain compatibility with the
// historical TrustedOrigins format and are interpreted as HTTPS origins.
func ParseOrigin(raw string) (Origin, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Origin{}, fmt.Errorf("csrf: invalid origin %q: origin must not be empty", raw)
	}

	if !strings.Contains(value, "://") {
		authority := strings.TrimPrefix(value, "//")
		parsed, err := url.Parse("//" + authority)
		if err != nil || parsed.Host == "" {
			return Origin{}, fmt.Errorf("csrf: invalid origin %q: expected host[:port] or scheme://host[:port]", raw)
		}

		return fromParsedURL("https", parsed), nil
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return Origin{}, fmt.Errorf("csrf: invalid origin %q: expected scheme://host[:port]", raw)
	}

	return FromURL(parsed), nil
}

// NormalizeOrigin is an alias for ParseOrigin.
func NormalizeOrigin(raw string) (Origin, error) {
	return ParseOrigin(raw)
}

func parseOrigin(raw string) (Origin, error) {
	return ParseOrigin(raw)
}

func normalizeOrigin(raw string) (Origin, error) {
	return ParseOrigin(raw)
}

// ParseOrigins parses and normalizes all raw origin entries.
func ParseOrigins(entries []string) ([]Origin, error) {
	origins := make([]Origin, 0, len(entries))
	for _, entry := range entries {
		parsed, err := ParseOrigin(entry)
		if err != nil {
			return nil, err
		}
		origins = append(origins, parsed)
	}
	return origins, nil
}

// ParseTrustedOrigin is the historical/descriptive name for ParseOrigin.
func ParseTrustedOrigin(raw string) (TrustedOrigin, error) {
	return ParseOrigin(raw)
}

func parseTrustedOrigin(raw string) (TrustedOrigin, error) {
	return ParseOrigin(raw)
}

func parseOrigins(entries []string) ([]Origin, error) {
	return ParseOrigins(entries)
}

// FromURL extracts the scheme, hostname and explicit port from u.
func FromURL(u *url.URL) Origin {
	if u == nil {
		return Origin{}
	}
	return fromParsedURL(u.Scheme, u)
}

func originFromURL(u *url.URL) Origin {
	return FromURL(u)
}

func fromParsedURL(scheme string, u *url.URL) Origin {
	return Origin{
		Scheme: strings.ToLower(strings.TrimSpace(scheme)),
		Host:   strings.ToLower(u.Hostname()),
		Port:   u.Port(),
	}
}

// EffectivePort returns the explicit port or the conventional default for
// http/https schemes.
func (o Origin) EffectivePort() string {
	if o.Port != "" {
		return o.Port
	}

	switch strings.ToLower(o.Scheme) {
	case "http", "ws":
		return "80"
	case "https", "wss":
		return "443"
	default:
		return ""
	}
}

// String returns the canonical scheme://host[:port] representation.
func (o Origin) String() string {
	if o.Host == "" {
		return ""
	}

	host := o.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if o.Port != "" {
		host = host + ":" + o.Port
	}
	return o.Scheme + "://" + host
}

// Matches reports whether o and candidate are equivalent under comparePort.
// Scheme and hostname are always compared case-insensitively.
func (o Origin) Matches(candidate Origin, comparePort bool) bool {
	if !strings.EqualFold(o.Scheme, candidate.Scheme) ||
		!strings.EqualFold(o.Host, candidate.Host) {
		return false
	}

	if comparePort {
		return o.EffectivePort() == candidate.EffectivePort()
	}

	return true
}

func originsMatch(a, b Origin, comparePort bool) bool {
	return a.Matches(b, comparePort)
}

// sameOrigin reports origin equality. When comparePort is omitted it uses the
// compatibility default of ignoring port differences; callers may pass an
// explicit bool to override that behavior.
func sameOrigin(a, b *url.URL, comparePort ...bool) bool {
	compare := false
	if len(comparePort) > 0 {
		compare = comparePort[0]
	}
	return sameOriginWithPortComparison(a, b, compare)
}

func sameOriginWithPortComparison(a, b *url.URL, comparePort bool) bool {
	if a == nil || b == nil {
		return false
	}
	return FromURL(a).Matches(FromURL(b), comparePort)
}

// SameOrigin reports whether a and b have the same scheme and hostname. Port
// comparison is controlled by comparePort.
func SameOrigin(a, b *url.URL, comparePort ...bool) bool {
	compare := false
	if len(comparePort) > 0 {
		compare = comparePort[0]
	}
	return sameOriginWithPortComparison(a, b, compare)
}

// Trusted reports whether u matches an entry in the policy allow-list.
func (p OriginPolicy) Trusted(u *url.URL) bool {
	if u == nil || u.Host == "" {
		return false
	}

	candidate := FromURL(u)
	for _, allowed := range p.TrustedOrigins {
		if allowed.Matches(candidate, p.ComparePort) {
			return true
		}
	}
	return false
}

func (p OriginPolicy) isTrustedOrigin(u *url.URL) bool {
	return p.Trusted(u)
}

// Allows reports whether source is same-origin with target or explicitly
// trusted by the policy.
func (p OriginPolicy) Allows(target, source *url.URL) bool {
	if target == nil || source == nil {
		return false
	}
	return sameOriginWithPortComparison(target, source, p.ComparePort) || p.Trusted(source)
}

// Check applies the package's browser-source rules. Explicit Origin headers
// are always checked. For unsafe methods over TLS, a missing Origin falls back
// to strict Referer validation.
func (p OriginPolicy) Check(r *http.Request) error {
	plaintext := false
	if value := r.Context().Value(PlaintextHTTPContextKey); value != nil {
		if explicit, ok := value.(bool); ok {
			plaintext = explicit
		}
	}

	target := requestOriginURL(r, plaintext || p.AllowHTTP)

	if originHeader := r.Header.Get("Origin"); originHeader != "" {
		source, err := url.Parse(originHeader)
		if err != nil || source.Scheme == "" || source.Host == "" {
			return ErrBadOrigin
		}
		if isCleartextDowngrade(target, source) || !p.Allows(target, source) {
			return ErrBadOrigin
		}
		return nil
	}

	if plaintext || contains(safeMethods, r.Method) {
		return nil
	}

	referer, err := url.Parse(r.Referer())
	if err != nil || referer.String() == "" {
		return ErrNoReferer
	}

	// A TLS response must never accept a cleartext Referer origin.
	if referer.Scheme == "http" || isCleartextDowngrade(target, referer) {
		return ErrBadReferer
	}

	// Relative Referers have no host component and are valid same-origin
	// references.
	if referer.Host != "" && !p.Allows(target, referer) {
		return ErrBadReferer
	}

	return nil
}

// CheckOrigin validates r with the OriginPolicy attached by the middleware.
// Requests without an attached policy use the package default policy. This is
// the shared validation entry for middleware and token access.
func CheckOrigin(r *http.Request) error {
	if value, err := contextGet(r, originPolicyContextKey); err == nil {
		if policy, ok := value.(OriginPolicy); ok {
			return policy.Check(r)
		}
	}
	return (OriginPolicy{}).Check(r)
}

// ValidateOrigin is an alias for CheckOrigin.
func ValidateOrigin(r *http.Request) error {
	return CheckOrigin(r)
}

// Validate is an alias for Check.
func (p OriginPolicy) Validate(r *http.Request) error {
	return p.Check(r)
}

func isCleartextDowngrade(target, source *url.URL) bool {
	return target != nil && strings.EqualFold(target.Scheme, "https") &&
		source != nil && strings.EqualFold(source.Scheme, "http")
}

func requestOriginURL(r *http.Request, isPlaintext bool) *url.URL {
	requestURL := *r.URL
	if isPlaintext {
		requestURL.Scheme = "http"
	} else {
		requestURL.Scheme = "https"
	}
	if requestURL.Host == "" {
		requestURL.Host = r.Host
	}
	return &requestURL
}

// trustedOrigin matches u against raw TrustedOrigins entries. When
// comparePort is omitted it uses the compatibility default of ignoring port
// differences.
func trustedOrigin(trusted []string, u *url.URL, comparePort ...bool) bool {
	compare := false
	if len(comparePort) > 0 {
		compare = comparePort[0]
	}
	policy := OriginPolicy{TrustedOrigins: make([]Origin, 0, len(trusted))}
	for _, entry := range trusted {
		if parsed, err := ParseOrigin(entry); err == nil {
			policy.TrustedOrigins = append(policy.TrustedOrigins, parsed)
		}
	}
	policy.ComparePort = compare
	return policy.Trusted(u)
}

func trustedOriginWithPortComparison(trusted []string, u *url.URL, comparePort bool) bool {
	return trustedOrigin(trusted, u, comparePort)
}

func matchTrustedOrigins(origins []Origin, u *url.URL, comparePort bool) bool {
	return (OriginPolicy{TrustedOrigins: origins, ComparePort: comparePort}).Trusted(u)
}
