package main

import "testing"

func TestDemoTargets(t *testing.T) {
	targets := demoTargets()
	if len(targets) == 0 {
		t.Fatal("expected demo targets")
	}
	if targets[0] != "api.example.com" {
		t.Fatalf("unexpected first demo target: %q", targets[0])
	}
}

func TestBrandHeader(t *testing.T) {
	line := brandHeader("ARMUR AI")
	if line == "" {
		t.Fatal("expected branded header")
	}
	if len(line) < 20 {
		t.Fatal("header too short to be useful")
	}
}
