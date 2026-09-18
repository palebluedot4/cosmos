// Without these tests, a postgresURL that lets "options" or a repeated sslmode
// through stays green — both produce a URL that connects, and the setting they
// override is one nothing in this process reads back. So does a redisURL that
// allows skip_verify behind a rediss:// scheme, and a parseURL that reports the
// error url.Parse returns, which reprints the URL it failed on with the password
// in it, straight into the startup log.

package config

import (
	"log/slog"
	"net/url"
	"strings"
	"testing"
)

func TestEnvironment(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    Environment
		wantErr string
	}{
		{
			in:   "development",
			want: Development,
		},
		{
			in:   "staging",
			want: Staging,
		},
		{
			in:   "production",
			want: Production,
		},
		{
			in:      "prod",
			wantErr: `unknown environment "prod" (want one of development, staging, production)`,
		},
		{
			in:      "Production",
			wantErr: `unknown environment "Production" (want one of development, staging, production)`,
		},
		{
			in:      " production",
			wantErr: `unknown environment " production" (want one of development, staging, production)`,
		},
	}

	for _, tt := range tests {
		got, err := environment(tt.in)
		if tt.wantErr != "" {
			if err == nil || err.Error() != tt.wantErr {
				t.Errorf("environment(%q) = _, %v, want error %q", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("environment(%q) = %q, %v, want %q, nil", tt.in, got, err, tt.want)
		}
	}
}

func TestLogLevel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    slog.Level
		wantErr string
	}{
		{
			in:   "debug",
			want: slog.LevelDebug,
		},
		{
			in:   "INFO",
			want: slog.LevelInfo,
		},
		{
			in:   "warn",
			want: slog.LevelWarn,
		},
		{
			in:   "error",
			want: slog.LevelError,
		},
		{
			in:   "INFO+2",
			want: slog.LevelInfo + 2,
		},
		{
			in:      "chatty",
			wantErr: `slog: level string "chatty": unknown name`,
		},
		{
			in:      "3",
			wantErr: `slog: level string "3": unknown name`,
		},
	}

	for _, tt := range tests {
		got, err := logLevel(tt.in)
		if tt.wantErr != "" {
			if err == nil || err.Error() != tt.wantErr {
				t.Errorf("logLevel(%q) = _, %v, want error %q", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("logLevel(%q) = %v, %v, want %v, nil", tt.in, got, err, tt.want)
		}
	}
}

func TestInteger(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    int32
		wantErr string
	}{
		{
			in:   "10",
			want: 10,
		},
		{
			in:   "-1",
			want: -1,
		},
		{
			in:   "0",
			want: 0,
		},
		{
			in:   "2147483647",
			want: 2147483647,
		},
		// Narrower than the 64 bits ParseInt reads, so the range check
		// after the conversion is the only thing that catches this.
		{
			in:      "2147483648",
			wantErr: `invalid integer "2147483648": value out of range`,
		},
		{
			in:      "99999999999999999999",
			wantErr: `invalid integer "99999999999999999999": value out of range`,
		},
		{
			in:      "ten",
			wantErr: `invalid integer "ten": invalid syntax`,
		},
		{
			in:      "1.0",
			wantErr: `invalid integer "1.0": invalid syntax`,
		},
		{
			in:      "0x10",
			wantErr: `invalid integer "0x10": invalid syntax`,
		},
		{
			in:      " 10",
			wantErr: `invalid integer " 10": invalid syntax`,
		},
	}

	for _, tt := range tests {
		got, err := integer[int32](tt.in)
		if tt.wantErr != "" {
			if err == nil || err.Error() != tt.wantErr {
				t.Errorf("integer[int32](%q) = _, %v, want error %q", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("integer[int32](%q) = %d, %v, want %d, nil", tt.in, got, err, tt.want)
		}
	}
}

// TestIntegerErrorOmitsStrconvInternals is why integer reports the cause rather
// than the error strconv returns: its text names ParseInt and the 64-bit width
// parsed here, neither of which is anything the operator wrote.
func TestIntegerErrorOmitsStrconvInternals(t *testing.T) {
	t.Parallel()
	_, err := integer[int32]("ten")
	if err == nil {
		t.Fatal(`integer[int32]("ten") = _, nil, want error`)
	}
	for _, leak := range []string{"ParseInt", "strconv", "64"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf(`integer[int32]("ten") = _, %q, want no mention of %q`, err, leak)
		}
	}
}

func TestPostgresURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		wantErr string
	}{
		{
			name: "postgres scheme",
			in:   "postgres://nexus:pw@db:5432/nexus",
		},
		{
			name: "postgresql scheme",
			in:   "postgresql://nexus:pw@db:5432/nexus",
		},
		{
			name: "every allowed parameter",
			in:   "postgres://db/nexus?application_name=api&sslcert=/c&sslkey=/k&sslmode=verify-full&sslrootcert=/r",
		},
		{
			// Removes the innermost deadline the whole chain in
			// validate is layered around, and the connection still
			// works.
			name:    "options",
			in:      "postgres://db/nexus?options=-c%20statement_timeout%3D0",
			wantErr: `unsupported query parameter "options" (want one of application_name, sslcert, sslkey, sslmode, sslrootcert)`,
		},
		{
			// Skips TLS entirely on success, which leaves the sslmode
			// check in validate asserting a parameter the connection
			// never used.
			name:    "gssencmode",
			in:      "postgres://db/nexus?sslmode=verify-full&gssencmode=require",
			wantErr: `unsupported query parameter "gssencmode" (want one of application_name, sslcert, sslkey, sslmode, sslrootcert)`,
		},
		{
			name:    "duplicates a setting this package owns",
			in:      "postgres://db/nexus?pool_max_conns=100",
			wantErr: `unsupported query parameter "pool_max_conns" (want one of application_name, sslcert, sslkey, sslmode, sslrootcert)`,
		},
		{
			// url.Values.Get returns the first; which one pgx applies
			// is its own business, so the two must not be allowed to
			// disagree.
			name:    "repeated sslmode",
			in:      "postgres://db/nexus?sslmode=verify-full&sslmode=disable",
			wantErr: `query parameter "sslmode" is set 2 times`,
		},
		{
			name: "every offending parameter is reported",
			in:   "postgres://db/nexus?options=x&sslmode=a&sslmode=b",
			wantErr: `unsupported query parameter "options" (want one of application_name, sslcert, sslkey, sslmode, sslrootcert)` + "\n" +
				`query parameter "sslmode" is set 2 times`,
		},
		{
			name:    "unescapable query",
			in:      "postgres://db/nexus?sslmode=%zz",
			wantErr: `malformed query: invalid URL escape "%zz"`,
		},
		{
			name:    "redis scheme",
			in:      "redis://db:6379/0",
			wantErr: `unsupported scheme "redis" (want postgres or postgresql)`,
		},
		{
			name:    "no scheme",
			in:      "db:5432/nexus",
			wantErr: `unsupported scheme "db" (want postgres or postgresql)`,
		},
		{
			name:    "no host",
			in:      "postgres:///nexus",
			wantErr: "missing host",
		},
		{
			// url.Host is ":5432" here, which is not empty. This is
			// the shape a template renders when the host variable is
			// unset, and pgx would fall back to a local connection.
			name:    "port but no host",
			in:      "postgres://:5432/nexus",
			wantErr: "missing host",
		},
		{
			name:    "credentials but no host",
			in:      "postgres://nexus:pw@/nexus",
			wantErr: "missing host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := postgresURL(tt.in)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("postgresURL(%q) = %v, %v, want error %q", tt.in, got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("postgresURL(%q) = _, %v, want nil error", tt.in, err)
			}
			if got.String() != tt.in {
				t.Errorf("postgresURL(%q).String() = %q, want %q", tt.in, got, tt.in)
			}
		})
	}
}

func TestRedisURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		wantErr string
	}{
		{
			name: "redis scheme",
			in:   "redis://cache:6379/0",
		},
		{
			name: "rediss scheme",
			in:   "rediss://cache:6379/0",
		},
		{
			// go-redis reads skip_verify from here, and it switches
			// off certificate verification behind a scheme validate
			// still accepts.
			name:    "skip_verify",
			in:      "rediss://cache:6379/0?skip_verify=true",
			wantErr: "must not carry query parameters",
		},
		{
			name:    "any query at all",
			in:      "redis://cache:6379/0?dial_timeout=1h",
			wantErr: "must not carry query parameters",
		},
		{
			name:    "postgres scheme",
			in:      "postgres://cache:6379/0",
			wantErr: `unsupported scheme "postgres" (want redis or rediss)`,
		},
		{
			name:    "no host",
			in:      "redis:///0",
			wantErr: "missing host",
		},
		{
			name:    "port but no host",
			in:      "redis://:6379/0",
			wantErr: "missing host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := redisURL(tt.in)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("redisURL(%q) = %v, %v, want error %q", tt.in, got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("redisURL(%q) = _, %v, want nil error", tt.in, err)
			}
			if got.String() != tt.in {
				t.Errorf("redisURL(%q).String() = %q, want %q", tt.in, got, tt.in)
			}
		})
	}
}

// TestParseURLDoesNotEchoCredentials is the reason parseURL reports the cause
// instead of the error url.Parse returns. *url.Error reprints the URL it failed
// on, password included, and this error is on its way to the startup log. A
// cookie-jar-style check — asserting only that parsing failed — would pass
// against the leaking version, so the assertion is on the password itself.
func TestParseURLDoesNotEchoCredentials(t *testing.T) {
	t.Parallel()
	const password = "s3cr3t-do-not-log"
	in := "postgres://nexus:" + password + "@db:notaport/nexus"
	// The premise: url.Parse really does fail here, and really does echo.
	if _, err := url.Parse(in); err == nil { //nolint:staticcheck
		t.Fatalf("url.Parse(%q) = _, nil, want error; the test no longer exercises the stripping", in)
	} else if !strings.Contains(err.Error(), password) {
		t.Fatalf("url.Parse(%q) no longer echoes the password; the test no longer exercises the stripping", in)
	}
	tests := []struct {
		name  string
		parse func(string) (*url.URL, error)
	}{
		{name: "postgresURL", parse: postgresURL},
		{name: "redisURL", parse: redisURL},
	}

	for _, tt := range tests {
		_, err := tt.parse(in)
		if err == nil {
			t.Errorf("%s(%q) = _, nil, want error", tt.name, in)
			continue
		}
		if strings.Contains(err.Error(), password) {
			t.Errorf("%s(url with password) = _, %q, want an error not containing the password", tt.name, err)
		}
	}
}
