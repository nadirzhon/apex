package core

import "testing"

func TestScopeAllowsAndExclusionWins(t *testing.T) {
	scope := Scope{
		InScope:    []string{"*.example.com"},
		OutOfScope: []string{"admin.example.com", "*.dev.example.com"},
	}
	for _, target := range []string{"example.com", "https://api.example.com/v1"} {
		if !scope.Allows(target) {
			t.Fatalf("expected %q in scope", target)
		}
	}
	for _, target := range []string{"https://admin.example.com", "x.dev.example.com", "evil.com"} {
		if scope.Allows(target) {
			t.Fatalf("expected %q outside scope", target)
		}
	}
}

func TestExplicitPortUsesHostname(t *testing.T) {
	scope := Scope{InScope: []string{"127.0.0.1"}}
	if !scope.Allows("http://127.0.0.1:8080/test") {
		t.Fatal("host with port should match")
	}
}
