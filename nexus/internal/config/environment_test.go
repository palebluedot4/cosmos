// Without this test, IsDeployed spelled "staging or production" stays green: both
// named deployments still report true, and the only case that changes is an
// environment name this build has never heard of — which would silently skip
// every transport-security check in validate, and has no runtime symptom at all.

package config

import "testing"

func TestEnvironmentIsDeployed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   Environment
		want bool
	}{
		{in: Development, want: false},
		{in: Staging, want: true},
		{in: Production, want: true},
		{in: "", want: true},            // the zero Environment
		{in: "preview", want: true},     // an environment added after this build
		{in: "Development", want: true}, // APP_ENV is matched exactly, not case-folded
		{in: "dev", want: true},
	}

	for _, tt := range tests {
		if got := tt.in.IsDeployed(); got != tt.want {
			t.Errorf("Environment(%q).IsDeployed() = %v, want %v", string(tt.in), got, tt.want)
		}
	}
}
