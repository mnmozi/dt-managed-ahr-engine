package stats

import (
	"reflect"
	"testing"
)

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"env", "envv", 1},
		{"env", "environment", 8},
		{"team", "teem", 1},
		{"team", "owner", 5},
		{"Foo", "foo", 1}, // case differs without normalization
		{"kitten", "sitting", 3},
	}
	for _, c := range cases {
		t.Run(c.a+"_vs_"+c.b, func(t *testing.T) {
			got := Levenshtein(c.a, c.b)
			if got != c.want {
				t.Errorf("Levenshtein(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"abc", "abc"},
		{"ABC", "abc"},
		{"Foo-Bar", "foobar"},
		{"app_name", "appname"},
		{"app.name.v2", "appnamev2"},
		{"Hello, World!", "helloworld"},
		{"prod-web-01", "prodweb01"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := Normalize(c.in)
			if got != c.want {
				t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestNormalizedEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"env", "Env", true},
		{"env", "ENV", true},
		{"app-name", "app_name", true},
		{"app.name", "AppName", true},
		{"env", "envv", false},
		{"team", "Team", true},
		{"", "", true},
	}
	for _, c := range cases {
		got := NormalizedEqual(c.a, c.b)
		if got != c.want {
			t.Errorf("NormalizedEqual(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestTokenSplit(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", []string{}},
		{"foo", []string{"foo"}},
		{"prod-web-01", []string{"prod", "web", "01"}},
		{"PROD_WEB_01", []string{"prod", "web", "01"}},
		{"a.b/c d", []string{"a", "b", "c", "d"}},
		{"  ", []string{}},
		{"single", []string{"single"}},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := TokenSplit(c.in)
			if len(got) == 0 && len(c.want) == 0 {
				return // both empty — match
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("TokenSplit(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestLikelyTypo(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		// Typo cases (return true)
		{"env", "envv", true},
		{"environment", "envirnment", true}, // missing letter
		{"team", "teem", true},
		// Case/separator drift — NOT typo
		{"env", "ENV", false},
		{"app-name", "app_name", false},
		// Same after normalization — NOT typo (different rule covers it)
		{"Env", "env", false},
		// Very different — not typo
		{"team", "owner", false},
		{"env", "environment", false}, // too different in length
		// Too short — skip
		{"a", "b", false},
		{"x", "xy", false},
		// Empty
		{"", "", false},
	}
	for _, c := range cases {
		t.Run(c.a+"_vs_"+c.b, func(t *testing.T) {
			got := LikelyTypo(c.a, c.b)
			if got != c.want {
				t.Errorf("LikelyTypo(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
			}
		})
	}
}

func TestSubstringContainment(t *testing.T) {
	cases := []struct {
		a, b   string
		wantGt float64 // require ratio > this; 0 means "expect exactly 0"
		wantEq bool    // when true, ratio must equal wantGt
	}{
		{"env", "environment", 0.27, false},        // env in environment
		{"env", "envv", 0.0, true},                  // env in envv but normalize-equal so 0
		// Actually env normalized is "env", envv normalized is "envv".
		// They're not equal. env IS contained in envv. ratio = 3/4 = 0.75.
		// Let me fix this test case.
	}
	// Cleaner cases
	c1 := SubstringContainment("env", "environment")
	if c1 < 0.25 || c1 > 0.30 {
		t.Errorf("SubstringContainment(env, environment) = %v, want ~0.27", c1)
	}
	c2 := SubstringContainment("env", "ENV")
	if c2 != 0 {
		t.Errorf("SubstringContainment(env, ENV) = %v, want 0 (normalize-equal)", c2)
	}
	c3 := SubstringContainment("env", "envv")
	if c3 != 0.75 {
		t.Errorf("SubstringContainment(env, envv) = %v, want 0.75", c3)
	}
	c4 := SubstringContainment("env", "completely-different")
	if c4 != 0 {
		t.Errorf("SubstringContainment(env, completely-different) = %v, want 0", c4)
	}
	c5 := SubstringContainment("a", "abc")
	if c5 != 0 {
		t.Errorf("SubstringContainment(a, abc) = %v, want 0 (too short)", c5)
	}

	// unused vars to silence linter on the original cases slice
	_ = cases
}
