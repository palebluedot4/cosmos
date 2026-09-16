package config

// An Environment names the deployment a process is running in. It is read from
// APP_ENV and, unlike most settings, changes behavior rather than tuning it: see
// IsDeployed for the requirements a deployed environment carries.
type Environment string

// The environments the application recognizes. Any other value of APP_ENV is
// rejected at startup.
const (
	Development Environment = "development"
	Staging     Environment = "staging"
	Production  Environment = "production"
)

// environments lists the constants above, in the order an error message names
// them. The parser matches against this list rather than repeating it, so a
// constant left out is rejected at startup rather than quietly missing from the
// message meant to enumerate it.
var environments = []Environment{Development, Staging, Production}

// IsDeployed reports whether the environment is anything other than Development,
// and so must meet the transport-security requirements Load enforces (verified
// TLS to Postgres and Redis).
//
// It is spelled "not development" rather than "staging or production" so that it
// fails closed: an environment this build has never heard of — including the zero
// Environment — is treated as deployed and held to the stricter rules. The
// opposite spelling would silently exempt every future environment name from
// every security check, which is the failure with no symptom.
func (e Environment) IsDeployed() bool {
	return e != Development
}
