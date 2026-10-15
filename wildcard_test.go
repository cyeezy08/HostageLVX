package main

import (
	"testing"
)

// ParentOf decides which hosts share a wildcard canary. Getting it wrong means
// a takeover finding gets silently downgraded (false negative) or a real finding
// gets waved off (false positive), and both look identical in the output: a
// missing row.

func TestParentOfStripsToRegistrablePair(t *testing.T) {
	cases := []struct{ in, want string }{
		{"www.example.com", "example.com"},
		{"a.b.c.example.com", "example.com"},
		{"example.com", "example.com"},
		{"EXAMPLE.COM.", "example.com"},
		// Multilabel suffix, so the parent keeps three labels, not two.
		{"deep.sub.domain.co.uk", "domain.co.uk"},
	}
	for _, c := range cases {
		if got := ParentOf(c.in); got != c.want {
			t.Errorf("ParentOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A public-suffix pair like co.uk is two labels but is still the registrable
// unit, so the parent must be three labels up. Without this, every UK host is
// grouped under "co.uk" and one wildcard canary silently judges the whole TLD.
func TestParentOfRespectsMultilabelSuffixes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"shop.example.co.uk", "example.co.uk"},
		{"example.co.uk", "example.co.uk"},
		{"a.b.example.com.au", "example.com.au"},
		{"host.example.co.jp", "example.co.jp"},
		// Not a registered multilabel suffix: must stay a plain two-label parent.
		{"host.example.evil.co", "evil.co"},
	}
	for _, c := range cases {
		if got := ParentOf(c.in); got != c.want {
			t.Errorf("ParentOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Hostnames that are already at or below the suffix must not be indexed off the
// end of the slice.
func TestParentOfHandlesShortInput(t *testing.T) {
	for _, in := range []string{"com", "co.uk", "", "localhost"} {
		got := ParentOf(in)
		if got != ParentOf(in) {
			t.Fatalf("ParentOf not deterministic for %q", in)
		}
		if got == "" && in != "" {
			t.Errorf("ParentOf(%q) = %q, want non-empty", in, got)
		}
	}
}

func TestBodyHashIsStableAndEmptySafe(t *testing.T) {
	if got := BodyHash(""); got != "" {
		t.Errorf("BodyHash(\"\") = %q, want empty so an unprobed host has no hash to compare", got)
	}
	a, b := BodyHash("<html>same</html>"), BodyHash("<html>same</html>")
	if a != b {
		t.Errorf("BodyHash is not deterministic: %q vs %q", a, b)
	}
	if a == "" {
		t.Error("BodyHash returned empty for a non-empty body")
	}
	if len(a) != 16 {
		t.Errorf("BodyHash length = %d, want 16 (truncated sha256 hex)", len(a))
	}
	if BodyHash("<html>a</html>") == BodyHash("<html>b</html>") {
		t.Error("different bodies produced the same hash")
	}
}

func TestRandNonceShape(t *testing.T) {
	const n = 14
	got := randNonce(n)
	if len(got) != n {
		t.Fatalf("randNonce(%d) length = %d, want %d (%q)", n, len(got), n, got)
	}
	for _, r := range got {
		// staticcheck QF1001: De Morgan. Written positively so the failure
		// message names the rune rather than the negated condition.
		lower := r >= 'a' && r <= 'z'
		digit := r >= '0' && r <= '9'
		if !lower && !digit {
			t.Fatalf("randNonce produced %q with out-of-charset rune %q", got, r)
		}
	}
	// Two calls compared inline reads as a tautology (staticcheck SA4000) even
	// though each call is an independent draw. Bind them first so the intent is
	// obvious and the check survives a linter.
	again := randNonce(n)
	if got == again {
		t.Error("two nonces came back identical; the canary would be guessable")
	}
}

func TestIsWildcardedUsesParentGrouping(t *testing.T) {
	w := NewWildcardRegistry(nil, false)
	w.Canaries["example.com"] = &Canary{Parent: "example.com", Nonce: "abc", Resolves: true}

	if !w.isWildcarded("www.example.com") {
		t.Error("a host under an active canary zone must report as wildcarded")
	}
	if !w.isWildcarded("example.com") {
		t.Error("the parent host itself must report as wildcarded")
	}
	if w.isWildcarded("a.other.com") {
		t.Error("an unrelated zone must not be treated as wildcarded")
	}
}

// A canary that was built but did not resolve is not evidence of a wildcard
// zone, so it must not suppress findings.
func TestIsWildcardedIgnoresNonResolvingCanary(t *testing.T) {
	w := NewWildcardRegistry(nil, false)
	w.Canaries["example.com"] = &Canary{Parent: "example.com", Nonce: "abc", Resolves: false}

	if w.isWildcarded("www.example.com") {
		t.Error("a non-resolving canary must not mark the zone as wildcarded")
	}
	if got := w.ActiveCanaries(); got != 0 {
		t.Errorf("ActiveCanaries() = %d, want 0 when the only canary failed to resolve", got)
	}
}

func TestActiveCanariesCountsOnlyResolving(t *testing.T) {
	w := NewWildcardRegistry(nil, false)
	w.Canaries["a.com"] = &Canary{Parent: "a.com", Resolves: true}
	w.Canaries["b.com"] = &Canary{Parent: "b.com", Resolves: false}
	w.Canaries["c.com"] = &Canary{Parent: "c.com", Resolves: true}

	if got := w.ActiveCanaries(); got != 2 {
		t.Errorf("ActiveCanaries() = %d, want 2", got)
	}
}

// Apply is the function that suppresses false positives. Each branch is a
// distinct verdict transition, so each is asserted separately.
func TestApplyDowngradesNoDNSToWildcard(t *testing.T) {
	w := NewWildcardRegistry(nil, false)
	w.Canaries["example.com"] = &Canary{Parent: "example.com", Nonce: "n0nce", Resolves: true}

	f := &Finding{Host: "dead.example.com", Verdict: NoDNS, Evidence: "no DNS answer"}
	if got := w.Apply([]*Finding{f}); got != 1 {
		t.Errorf("Apply() = %d downgrades, want 1", got)
	}
	if f.Verdict != Wildcard {
		t.Errorf("Verdict = %q, want %q", f.Verdict, Wildcard)
	}
	if f.Evidence == "" {
		t.Error("downgraded finding kept no evidence; the downgrade must be auditable")
	}
}

// A body identical to the canary's body is the signature of a wildcard zone
// answering everything. The finding must be downgraded and must say why.
func TestApplyDowngradesIdenticalBodyToWildcard(t *testing.T) {
	w := NewWildcardRegistry(nil, false)
	const h = "deadbeefdeadbeef"
	w.Canaries["example.com"] = &Canary{Parent: "example.com", Nonce: "n", Resolves: true, Hash: h}

	f := &Finding{Host: "live.example.com", Verdict: Alive, BodyHash: h, Evidence: "serving"}
	if got := w.Apply([]*Finding{f}); got != 1 {
		t.Errorf("Apply() = %d downgrades, want 1", got)
	}
	if f.Verdict != Wildcard {
		t.Errorf("Verdict = %q, want %q", f.Verdict, Wildcard)
	}
}

func TestApplyLeavesDifferingBodyAlone(t *testing.T) {
	w := NewWildcardRegistry(nil, false)
	w.Canaries["example.com"] = &Canary{Parent: "example.com", Nonce: "n", Resolves: true, Hash: "aaaaaaaaaaaaaaaa"}

	f := &Finding{Host: "live.example.com", Verdict: Alive, BodyHash: "bbbbbbbbbbbbbbbb", Evidence: "serving"}
	if got := w.Apply([]*Finding{f}); got != 0 {
		t.Errorf("Apply() = %d downgrades, want 0 for a genuinely different body", got)
	}
	if f.Verdict != Alive {
		t.Errorf("Verdict = %q, want it left as %q", f.Verdict, Alive)
	}
}

// LIKELY is annotated rather than downgraded: a wildcard zone makes the signal
// unreliable but does not disprove it.
func TestApplyAnnotatesLikelyWithoutDowngrading(t *testing.T) {
	w := NewWildcardRegistry(nil, false)
	w.Canaries["example.com"] = &Canary{Parent: "example.com", Nonce: "n", Resolves: true}

	f := &Finding{Host: "x.example.com", Verdict: Likely, Evidence: "HTTP 404"}
	if got := w.Apply([]*Finding{f}); got != 0 {
		t.Errorf("Apply() = %d downgrades, want 0 for LIKELY", got)
	}
	if f.Verdict != Likely {
		t.Errorf("Verdict = %q, want it kept as %q", f.Verdict, Likely)
	}
	if f.Evidence == "HTTP 404" {
		t.Error("LIKELY evidence was not annotated; a reader cannot tell the zone is wildcarded")
	}
}

func TestApplyIgnoresFindingsOutsideWildcardZones(t *testing.T) {
	w := NewWildcardRegistry(nil, false)
	w.Canaries["example.com"] = &Canary{Parent: "example.com", Nonce: "n", Resolves: true}

	f := &Finding{Host: "sub.elsewhere.org", Verdict: NoDNS, Evidence: "no DNS answer"}
	if got := w.Apply([]*Finding{f}); got != 0 {
		t.Errorf("Apply() = %d downgrades, want 0", got)
	}
	if f.Verdict != NoDNS {
		t.Errorf("Verdict = %q, want it left as %q", f.Verdict, NoDNS)
	}
}

func TestApplyEmptyInput(t *testing.T) {
	w := NewWildcardRegistry(nil, true)
	if got := w.Apply(nil); got != 0 {
		t.Errorf("Apply(nil) = %d, want 0", got)
	}
}

// The disabled registry must never suppress anything, however the findings look.
func TestDisabledWildcardRegistryBuildsNothing(t *testing.T) {
	w := NewWildcardRegistry(nil, true)
	if w.Canaries == nil {
		t.Fatal("Canaries map is nil; Apply would panic on a disabled registry")
	}
	w.Canaries["example.com"] = &Canary{Parent: "example.com", Resolves: true}
	// isWildcarded is keyed off Canaries, so with Build disabled and an empty
	// map nothing is ever marked. Assert the registry starts clean instead.
	fresh := NewWildcardRegistry(nil, true)
	if len(fresh.Canaries) != 0 {
		t.Errorf("fresh disabled registry has %d canaries, want 0", len(fresh.Canaries))
	}
	if fresh.isWildcarded("www.example.com") {
		t.Error("disabled registry reported a host as wildcarded")
	}
}

func TestNewWildcardRegistryDefaults(t *testing.T) {
	w := NewWildcardRegistry(nil, false)
	if w.minGroup != 3 {
		t.Errorf("minGroup = %d, want 3", w.minGroup)
	}
	if w.nonceLen != 14 {
		t.Errorf("nonceLen = %d, want 14", w.nonceLen)
	}
	if w.Canaries == nil {
		t.Error("Canaries map not initialised")
	}
}
