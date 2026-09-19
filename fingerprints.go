package main

import (
    "net/http"
    "regexp"
    "strings"
)

type HTTPSignature struct {
    Body   string
    Status []int
    Header [][2]string
}

func (s HTTPSignature) Matches(status int, h http.Header, body string) bool {
    if len(s.Status) > 0 && !containsInt(s.Status, status) {
        return false
    }
    if s.Body != "" && !strings.Contains(strings.ToLower(body), strings.ToLower(s.Body)) {
        return false
    }
    for _, pair := range s.Header {
        v := h.Get(pair[0])
        if v == "" || !strings.Contains(strings.ToLower(v), strings.ToLower(pair[1])) {
            return false
        }
    }
    return true
}

type Fingerprint struct {
    Service        string
    Vulnerable     bool
    CNAMEs         []*regexp.Regexp
    Signatures     []HTTPSignature
    DanglingStatus []int
    Note           string
}

func (f *Fingerprint) MatchesCNAME(target string) bool {
    if target == "" || len(f.CNAMEs) == 0 {
        return false
    }
    t := strings.ToLower(strings.TrimSuffix(target, "."))
    for _, re := range f.CNAMEs {
        if re.MatchString(t) {
            return true
        }
    }
    return false
}

func (f *Fingerprint) SignatureMatch(status int, h http.Header, body string) *HTTPSignature {
    for i := range f.Signatures {
        if f.Signatures[i].Matches(status, h, body) {
            return &f.Signatures[i]
        }
    }
    return nil
}

func mustCNAME(patterns ...string) []*regexp.Regexp {
    outs := make([]*regexp.Regexp, len(patterns))
    for i, p := range patterns {
        outs[i] = regexp.MustCompile("^(?:" + p + ")$")
    }
    return outs
}

func containsInt(xs []int, x int) bool {
    for _, v := range xs {
        if v == x {
            return true
        }
    }
    return false
}

var Fingerprints = []*Fingerprint{
    {
        Service: "GitHub Pages", Vulnerable: true,
        CNAMEs:         mustCNAME(`.*\.github\.io`),
        Signatures:     []HTTPSignature{{Body: "There isn't a GitHub Pages site here.", Status: []int{404}}},
        DanglingStatus: []int{404},
        Note:           "claim by creating a repo named <user>.github.io and pushing a CNAME file",
    },
    {
        Service: "AWS S3", Vulnerable: true,
        CNAMEs: mustCNAME(
            `.+\.s3\.amazonaws\.com`,
            `.+\.s3\.[a-z0-9-]+\.amazonaws\.com`,
            `.+\.s3-website([.-][a-z0-9-]+)*\.amazonaws\.com`,
        ),
        Signatures:     []HTTPSignature{{Body: "NoSuchBucket", Status: []int{404}}},
        DanglingStatus: []int{404, 307},
        Note:           "claim by creating a bucket with the same name in the same region",
    },
    {
        Service: "Azure Web Apps", Vulnerable: true,
        CNAMEs:         mustCNAME(`.*\.azurewebsites\.net`),
        Signatures:     []HTTPSignature{{Body: "404 Web Site not found.", Status: []int{404}}},
        DanglingStatus: []int{404},
        Note:           "claim by creating an App Service with the same name",
    },
    {
        Service: "Heroku", Vulnerable: true,
        CNAMEs: mustCNAME(`.*\.herokuapp\.com`),
        Signatures: []HTTPSignature{
            {Body: "No such app", Status: []int{404}},
            {Body: "There's nothing here, yet.", Status: []int{404}},
        },
        DanglingStatus: []int{404},
        Note:           "claim by creating a Heroku app with the same name (verify account required)",
    },
    {
        Service: "Fastly", Vulnerable: true,
        CNAMEs:         mustCNAME(`.*\.fastly\.net`),
        Signatures:     []HTTPSignature{{Body: "Fastly error: unknown domain:"}},
        DanglingStatus: []int{500, 404},
        Note:           "claim by registering the domain on a Fastly service",
    },
    {
        Service: "Shopify", Vulnerable: true,
        CNAMEs:         mustCNAME(`.*\.myshopify\.com`),
        Signatures:     []HTTPSignature{{Body: "Sorry, this shop is currently unavailable."}},
        DanglingStatus: []int{404},
        Note:           "claim by creating a Shopify store with the same myshopify subdomain",
    },
    {
        Service: "Tumblr", Vulnerable: true,
        CNAMEs:         mustCNAME(`.*\.domains\.tumblr\.com`, `.*\.tumblr\.com`),
        Signatures:     []HTTPSignature{{Body: "Whatever you were looking for doesn't currently exist at this address.", Status: []int{404}}},
        DanglingStatus: []int{404},
        Note:           "claim by registering a blog with the same name and setting the custom domain",
    },
    {
        Service: "Zendesk", Vulnerable: true,
        CNAMEs:         mustCNAME(`.*\.zendesk\.com`),
        Signatures:     []HTTPSignature{{Body: "Help Center Closed"}},
        DanglingStatus: []int{404},
        Note:           "claim by creating a Zendesk account and requesting the subdomain",
    },
    {
        Service: "Bitbucket Cloud", Vulnerable: true,
        CNAMEs:         mustCNAME(`.*\.bitbucket\.io`),
        Signatures:     []HTTPSignature{{Body: "Repository not found", Status: []int{404}}},
        DanglingStatus: []int{404},
        Note:           "claim by creating a repo <account>.bitbucket.io under the matching workspace",
    },
    {
        Service: "Surge.sh", Vulnerable: true,
        CNAMEs:         mustCNAME(`.*\.surge\.sh`),
        Signatures:     []HTTPSignature{{Body: "project not found"}},
        DanglingStatus: []int{404},
        Note:           "claim by running 'surge --domain <subdomain>.surge.sh'",
    },
    {
        Service: "Readme.io", Vulnerable: true,
        CNAMEs:         mustCNAME(`.*\.readme\.io`),
        Signatures:     []HTTPSignature{{Body: "Project doesnt exist... yet!"}},
        DanglingStatus: []int{404},
        Note:           "claim by creating a readme.io project with the same subdomain",
    },
    {
        Service: "Pantheon", Vulnerable: true,
        CNAMEs:         mustCNAME(`.*\.pantheonsite\.io`),
        Signatures:     []HTTPSignature{{Body: "The gods are wise, but do not know of the site which you seek.", Status: []int{404}}},
        DanglingStatus: []int{404},
        Note:           "claim by creating a Pantheon site with the same name",
    },
    {
        Service: "Ghost", Vulnerable: true,
        CNAMEs:         mustCNAME(`.*\.ghost\.io`),
        Signatures:     []HTTPSignature{{Body: "The thing you were looking for is no longer here, or never was.", Status: []int{404}}},
        DanglingStatus: []int{404},
        Note:           "verify signup gating for the target tier before reporting",
    },
    {
        Service: "Helpjuice", Vulnerable: true,
        CNAMEs:         mustCNAME(`.*\.helpjuice\.com`),
        Signatures:     []HTTPSignature{{Body: "We could not find what you're looking for.", Status: []int{404}}},
        DanglingStatus: []int{404},
        Note:           "claim by creating a Helpjuice account with the same subdomain",
    },
    {
        Service: "CloudFront", Vulnerable: false,
        CNAMEs:         mustCNAME(`.*\.cloudfront\.net`),
        Signatures:     []HTTPSignature{{Body: "ERROR: The request could not be satisfied", Status: []int{403}}},
        DanglingStatus: []int{403, 404},
        Note:           "dangling distribution; not claimable, flag for cleanup",
    },
    {
        Service: "Netlify", Vulnerable: false,
        CNAMEs:         mustCNAME(`.*\.netlify\.app`, `.*\.netlify\.global\.ssl\.fastly\.net`),
        Signatures:     []HTTPSignature{{Body: "Request origin cannot be verified"}},
        DanglingStatus: []int{404},
        Note:           "domain verification blocks claiming; orphan worth cleaning up",
    },
    {
        Service: "Vercel", Vulnerable: false,
        CNAMEs:         mustCNAME(`.*\.vercel\.app`, `.*\.vercel-dns\.com`),
        Signatures:     []HTTPSignature{{Body: "DEPLOYMENT_NOT_FOUND", Status: []int{404}}},
        DanglingStatus: []int{404},
        Note:           "domain verification blocks claiming; orphan worth cleaning up",
    },
}

func FingerprintByCNAME(target string) *Fingerprint {
    for _, fp := range Fingerprints {
        if fp.MatchesCNAME(target) {
            return fp
        }
    }
    return nil
}

func BodyFirstMatch(status int, h http.Header, body string) (*Fingerprint, *HTTPSignature) {
    for _, fp := range Fingerprints {
        if !fp.Vulnerable {
            continue
        }
        if sig := fp.SignatureMatch(status, h, body); sig != nil {
            return fp, sig
        }
    }
    return nil, nil
}