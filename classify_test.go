package main

import (
	"net/http"
	"strings"
	"testing"
)

// sevIndex drives result ordering. A verdict that sorts wrong buries TAKEOVER
// under ALIVE, which is the one ordering bug that costs real money.

func TestSeverityOrderPutsTakeoverFirst(t *testing.T) {
	if sevIndex(Takeover) != 0 {
		t.Errorf("sevIndex(TAKEOVER) = %d, want 0", sevIndex(Takeover))
	}
	prev := -1
	for _, v := range Severity {
		if i := sevIndex(v); i < prev {
			t.Errorf("Severity is not ordered by sevIndex at %q (index %d after %d)", v, i, prev)
		} else {
			prev = i
		}
	}
}

// An unknown verdict must sort last rather than panic or land at 0, otherwise
// a typo'd verdict would outrank a confirmed takeover.
func TestSevIndexUnknownSortsLast(t *testing.T) {
	unknown := Verdict("SOMETHING_NEW")
	if got := sevIndex(unknown); got != len(Severity) {
		t.Errorf("sevIndex(unknown) = %d, want %d (past the end)", got, len(Severity))
	}
	for _, v := range Severity {
		if sevIndex(unknown) <= sevIndex(v) {
			t.Errorf("unknown verdict did not sort after %q", v)
		}
	}
}

func TestTakeoverCapable(t *testing.T) {
	yes := []Verdict{Takeover, Likely}
	no := []Verdict{Dangling, Alive, Wildcard, Error, NoDNS, Verdict("")}
	for _, v := range yes {
		if !(&Finding{Verdict: v}).TakeoverCapable() {
			t.Errorf("Verdict %q should be takeover-capable", v)
		}
	}
	for _, v := range no {
		if (&Finding{Verdict: v}).TakeoverCapable() {
			t.Errorf("Verdict %q should not be takeover-capable", v)
		}
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"truncateme", 4, "trun"},
		{"", 5, ""},
	}
	for _, c := range cases {
		if got := truncate(c.in, c.n); got != c.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

// Classify is the whole tool. Every branch below is a distinct verdict a user
// acts on differently, so each gets its own case.

func dnsRes(mutate func(*DNSResult)) *DNSResult {
	r := &DNSResult{Host: "h.example.com", Resolver: "test"}
	if mutate != nil {
		mutate(r)
	}
	return r
}

func probeOK(status int, body string) *ProbeResult {
	return &ProbeResult{OK: true, Status: status, Headers: http.Header{}, Body: body}
}

func TestClassifyNoDNSOnNXDomain(t *testing.T) {
	f := Classify("dead.example.com", dnsRes(func(r *DNSResult) { r.NXDomain = true }), nil)
	if f.Verdict != NoDNS {
		t.Errorf("Verdict = %q, want %q", f.Verdict, NoDNS)
	}
	if f.Evidence == "" {
		t.Error("NoDNS finding carries no evidence")
	}
}

func TestClassifyNoDNSOnEmptyAnswer(t *testing.T) {
	// No chain, no IPs, not NXDOMAIN, no error: the name exists but answers
	// nothing. That is still "no DNS answer" as far as a scanner is concerned.
	f := Classify("empty.example.com", dnsRes(func(r *DNSResult) {}), nil)
	if f.Verdict != NoDNS {
		t.Errorf("Verdict = %q, want %q", f.Verdict, NoDNS)
	}
}

func TestClassifyAliveWhenServingUnknownContent(t *testing.T) {
	res := dnsRes(func(r *DNSResult) { r.IPs = []string{"1.2.3.4"} })
	f := Classify("ok.example.com", res, probeOK(200, "<html>hello</html>"))
	if f.Verdict != Alive {
		t.Errorf("Verdict = %q, want %q", f.Verdict, Alive)
	}
	if f.Status != 200 {
		t.Errorf("Status = %d, want 200", f.Status)
	}
}

// A CNAME to a known takeover-capable provider whose target does not resolve is
// the classic dangling-subdomain shape and must not report as Alive.
func TestClassifyDanglingOnKnownCNAMENoProbe(t *testing.T) {
	var fp *Fingerprint
	for _, f := range Fingerprints {
		if len(f.CNAMEs) > 0 {
			fp = f
			break
		}
	}
	if fp == nil {
		t.Skip("no fingerprint with CNAME patterns")
	}
	target := probeCNAMETarget(t, fp)

	res := dnsRes(func(r *DNSResult) { r.Chain = []string{target} })
	f := Classify("x.example.com", res, nil)

	if f.Verdict == Alive {
		t.Errorf("Verdict = Alive for CNAME to %s with no probe; want a dangling verdict", target)
	}
	if f.Service != fp.Service {
		t.Errorf("Service = %q, want %q", f.Service, fp.Service)
	}
	if !strings.Contains(f.Evidence, fp.Service) {
		t.Errorf("Evidence %q does not name the provider", f.Evidence)
	}
}

// Classify must never panic on nil pointers, which is what lets ScanHost
// recover instead of taking the process down.
func TestClassifyTolerantOfNilInputs(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Classify panicked: %v", r)
		}
	}()
	_ = Classify("h", dnsRes(nil), nil)
	_ = Classify("h", dnsRes(func(r *DNSResult) { r.IPs = []string{"1.1.1.1"} }), nil)
	_ = Classify("h", dnsRes(func(r *DNSResult) { r.IPs = []string{"1.1.1.1"} }), probeOK(200, ""))
}

func TestClassifyRecordsResolverProvenance(t *testing.T) {
	f := Classify("h", dnsRes(func(r *DNSResult) { r.IPs = []string{"1.1.1.1"} }), probeOK(200, "x"))
	if f.Resolver != "test" {
		t.Errorf("Resolver = %q, want %q so a result can be traced to the resolver that produced it", f.Resolver, "test")
	}
}

func TestHTTPSignatureMatches(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.24.0")
	h.Set("Content-Type", "text/html")

	sig := HTTPSignature{
		Body:   "<h1>there is nothing here</h1>",
		Status: []int{404, 410},
		Header: [][2]string{{"Server", "nginx"}},
	}
	if !sig.Matches(404, h, "page <h1>THERE IS NOTHING HERE</h1>") {
		t.Error("expected a match on status+body+header")
	}
	if sig.Matches(200, h, "<h1>there is nothing here</h1>") {
		t.Error("matched despite an unlisted status")
	}
	if sig.Matches(404, h, "unrelated page") {
		t.Error("matched despite a missing body marker")
	}

	empty := http.Header{}
	if sig.Matches(404, empty, "<h1>there is nothing here</h1>") {
		t.Error("matched despite a missing required header")
	}
}

// An empty signature is a wildcard: it would match every host, which would turn
// the whole run into false positives.
func TestHTTPSignatureEmptyFieldsMatchEverything(t *testing.T) {
	sig := HTTPSignature{}
	if !sig.Matches(0, http.Header{}, "") {
		t.Error("an empty signature should match trivially; if this matters downstream it needs a guard")
	}
	// The guard that matters: BodyFirstMatch only consults Vulnerable entries.
	for _, fp := range Fingerprints {
		for i := range fp.Signatures {
			if fp.Signatures[i].Body == "" && len(fp.Signatures[i].Status) == 0 && len(fp.Signatures[i].Header) == 0 {
				t.Errorf("fingerprint %q has a signature that matches every response", fp.Service)
			}
		}
	}
}

func TestFingerprintCNAMEMatchingIsAnchored(t *testing.T) {
	fp := &Fingerprint{CNAMEs: mustCNAME(`.*\.s3\.amazonaws\.com`)}
	if !fp.MatchesCNAME("bucket.s3.amazonaws.com.") {
		t.Error("expected the anchored pattern to match a normal CNAME")
	}
	if !fp.MatchesCNAME("BUCKET.S3.AMAZONAWS.COM") {
		t.Error("CNAME matching must be case-insensitive")
	}
	// An unanchored match would let an attacker-controlled CNAME that merely
	// contains the provider string claim a takeover.
	if fp.MatchesCNAME("s3.amazonaws.com.evil.test") {
		t.Error("matched a CNAME that only contains the provider string")
	}
	if fp.MatchesCNAME("") {
		t.Error("empty CNAME must not match")
	}
}

func TestContainsInt(t *testing.T) {
	if !containsInt([]int{404, 410}, 410) {
		t.Error("expected 410 to be found")
	}
	if containsInt([]int{404, 410}, 200) {
		t.Error("200 should not be found")
	}
	if containsInt(nil, 200) {
		t.Error("empty slice must not match")
	}
	if containsInt([]int{}, 200) {
		t.Error("empty non-nil slice must not match")
	}
}

func TestDetectTechFromHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx")
	h.Set("Cf-Ray", "abc123")
	h.Set("X-Powered-By", "PHP/8.2")

	got := detectTech(h, "")
	want := map[string]bool{"nginx": true, "PHP/8.2": true, "Cloudflare": true}
	if len(got) != len(want) {
		t.Fatalf("detectTech = %v, want %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected tech %q in %v", g, got)
		}
	}
}

func TestDetectTechFromBody(t *testing.T) {
	got := detectTech(http.Header{}, "<link href='/wp-content/themes/x/style.css'>")
	found := false
	for _, g := range got {
		if g == "WordPress" {
			found = true
		}
	}
	if !found {
		t.Errorf("detectTech = %v, want it to report WordPress from wp-content", got)
	}
}

func TestDetectTechDoesNotDuplicate(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx")
	// The body and header paths can both reach the same label; the result is a
	// set, not a bag.
	if got := detectTech(h, "wp-content"); len(got) != len(dedupe(got)) {
		t.Errorf("detectTech returned duplicates: %v", got)
	}
}

func TestPadAndWriteJSONL(t *testing.T) {
	if got := pad("ab", 4); got != "ab  " {
		t.Errorf("pad(%q, 4) = %q, want %q", "ab", got, "ab  ")
	}
	if got := pad("abcdef", 3); got != "abcdef" {
		t.Errorf("pad must not truncate, got %q", got)
	}

	var sb strings.Builder
	if err := WriteJSONL([]*Finding{{Host: "a.com", Verdict: Takeover}}, &sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if !strings.Contains(out, `"host":"a.com"`) || !strings.Contains(out, `"verdict":"TAKEOVER"`) {
		t.Errorf("JSONL output missing expected fields: %s", out)
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// probeCNAMETarget extracts a CNAME string that the given fingerprint matches.
func probeCNAMETarget(t *testing.T, fp *Fingerprint) string {
	t.Helper()
	if len(fp.CNAMEs) == 0 {
		t.Skip("fingerprint has no CNAME patterns")
	}
	// Strip the ^(?:...)$ wrapper to get the bare pattern, then substitute a
	// label for the wildcard so it forms a real hostname.
	pat := strings.TrimSuffix(strings.TrimPrefix(fp.CNAMEs[0].String(), "^(?:"), ")$")
	pat = strings.ReplaceAll(pat, `\w+`, "probe")
	pat = strings.ReplaceAll(pat, "[^.]+", "probe")
	pat = strings.ReplaceAll(pat, "[^\\.]+", "probe")
	if strings.Contains(pat, "*") {
		pat = strings.ReplaceAll(pat, "*", "probe")
	}
	if !fp.MatchesCNAME(pat) {
		t.Skipf("could not synthesise a matching CNAME from %q", pat)
	}
	return pat
}
