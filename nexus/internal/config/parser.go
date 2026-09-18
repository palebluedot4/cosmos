package config

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/exp/constraints"
)

// parser converts one raw environment variable into a typed value. It never
// enforces policy — bounds belong to a rule, orderings to Config.validate.
type parser[T any] func(string) (T, error)

// Connection URL schemes the parsers accept. secureRedisScheme is also the scheme
// Config.validate requires of a deployed environment, so the two live together:
// accepting a scheme here that validate has never heard of is how a plaintext
// Redis connection reaches production.
const (
	postgresScheme    = "postgres"
	postgresqlScheme  = "postgresql"
	redisScheme       = "redis"
	secureRedisScheme = "rediss"
)

// environment parses an APP_ENV value, rejecting any name this build does not
// define. IsDeployed already treats an unknown name as deployed, so this is not
// what keeps the security checks on; it is what stops a typo from booting a
// process running under an environment name nothing else agrees on.
func environment(s string) (Environment, error) {
	env := Environment(s)
	if !slices.Contains(environments, env) {
		names := make([]string, len(environments))
		for i, e := range environments {
			names[i] = string(e)
		}
		return "", fmt.Errorf("unknown environment %q (want one of %s)", s, strings.Join(names, ", "))
	}
	return env, nil
}

// logLevel parses a log level, accepting every spelling slog.Level.UnmarshalText
// does — the level names and offsets from them, such as "INFO+2".
func logLevel(s string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(s)); err != nil {
		return 0, err
	}
	return level, nil
}

// text is the parser for a setting that needs no conversion. It exists so that a
// plain string still reaches the rules by the same path every other setting does.
func text(s string) (string, error) {
	return s, nil
}

// integer parses a signed integer and narrows it to T, which is the width the
// driver's own field uses. A strconv failure is reported through its cause: the
// text strconv produces names ParseInt and the 64-bit width parsed here, neither
// of which is anything the operator wrote.
func integer[T constraints.Signed](s string) (T, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		if e, ok := errors.AsType[*strconv.NumError](err); ok {
			err = e.Err
		}
		return 0, fmt.Errorf("invalid integer %q: %w", s, err)
	}
	v := T(n)
	if int64(v) != n {
		return 0, fmt.Errorf("invalid integer %q: %w", s, strconv.ErrRange)
	}
	return v, nil
}

// allowedPostgresParams is the set of query parameters postgresURL accepts.
// Everything else is rejected, and the list is an allowlist rather than a list of
// known-dangerous parameters because a denylist is always one entry short of
// correct.
//
// Three families of parameter are kept out by it, and none of them has a runtime
// symptom. Parameters that duplicate a setting this package already owns —
// connect_timeout, pgx's pool_max_conns and pool_min_conns — give the process two
// sources for one value, and the URL is the one that wins, so the bounds checked
// here stop describing the running pool. "options" carries arbitrary server
// settings, including "-c statement_timeout=0", which removes the innermost
// deadline the whole chain in Config.validate is layered around. And
// gssencmode=require makes libpq negotiate GSSAPI encryption first and skip TLS
// entirely on success, which leaves requiredSSLMode asserting a parameter the
// connection never used.
//
// Adding an entry here is a deliberate act: it must be a setting that cannot be
// expressed as its own environment variable, which is what makes the TLS files
// and application_name the only ones that qualify today.
var allowedPostgresParams = []string{
	"application_name",
	"sslcert",
	"sslkey",
	"sslmode",
	"sslrootcert",
}

// postgresURL accepts a query string, unlike redisURL, because the TLS settings
// have no other way in: sslmode is the parameter Config.validate requires of a
// deployed environment, and sslrootcert and its siblings can only be carried by
// the URL. It is restricted to allowedPostgresParams, each appearing at most
// once.
func postgresURL(s string) (*url.URL, error) {
	u, err := parseURL(s, postgresScheme, postgresqlScheme)
	if err != nil {
		return nil, err
	}
	// url.ParseQuery rather than URL.Query, which discards its error: a pair
	// that fails to unescape is silently dropped from the result, so a typo
	// in the query could remove sslmode from what this package sees while
	// leaving it in the string the driver parses.
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("malformed query: %w", err)
	}
	// The at-most-once check is what lets Config.validate read sslmode with
	// url.Values.Get. Get returns the first of a repeated parameter, and
	// which one a driver applies is its own business: a URL setting sslmode
	// to verify-full and then to disable must not come down to the two
	// agreeing.
	//
	// Every offending parameter is reported rather than the first, for the
	// reason Load reports every variable at once, and the keys are walked in
	// sorted order so that a URL with several mistakes does not report them in
	// map order.
	var errs []error
	for _, key := range slices.Sorted(maps.Keys(q)) {
		if !slices.Contains(allowedPostgresParams, key) {
			errs = append(errs, fmt.Errorf("unsupported query parameter %q (want one of %s)", key, strings.Join(allowedPostgresParams, ", ")))
		} else if n := len(q[key]); n > 1 {
			errs = append(errs, fmt.Errorf("query parameter %q is set %d times", key, n))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return u, nil
}

// redisURL rejects the query string entirely. Nothing this package needs is
// carried in one — the database number is in the path — while go-redis reads
// skip_verify from there, and that switches off certificate verification behind a
// rediss:// scheme that still satisfies the check in Config.validate. Rejecting
// the whole query is the only form of this with no symptomless hole left in it.
func redisURL(s string) (*url.URL, error) {
	u, err := parseURL(s, redisScheme, secureRedisScheme)
	if err != nil {
		return nil, err
	}
	if u.RawQuery != "" {
		return nil, errors.New("must not carry query parameters")
	}
	return u, nil
}

// parseURL parses a connection URL and requires one of the given schemes and a
// host.
func parseURL(s string, schemes ...string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		// Reported through the cause rather than the *url.Error, which
		// reprints the URL it failed on — credentials included — and
		// this error is on its way to the startup log.
		if e, ok := errors.AsType[*url.Error](err); ok {
			err = e.Err
		}
		return nil, fmt.Errorf("malformed URL: %w", err)
	}
	if !slices.Contains(schemes, u.Scheme) {
		return nil, fmt.Errorf("unsupported scheme %q (want %s)", u.Scheme, strings.Join(schemes, " or "))
	}
	// Hostname rather than Host, because a URL can carry a port and no name —
	// "postgres://:5432/nexus", the shape a template renders when the host
	// variable is unset — and Host is then ":5432", which is not empty. Both
	// drivers fall back to a local default for an empty host, so the process
	// would come up pointed at localhost instead of at the database it was
	// configured for.
	if u.Hostname() == "" {
		return nil, errors.New("missing host")
	}
	return u, nil
}
