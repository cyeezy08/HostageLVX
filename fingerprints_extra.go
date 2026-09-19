package main

// Additional fingerprints. Sourced from public takeover research;
// only stable, documented signatures ship. Verify before reporting.

func init() {
    Fingerprints = append(Fingerprints,
        &Fingerprint{
            Service: "Google Cloud Storage", Vulnerable: true,
            CNAMEs:         mustCNAME(`.*\.storage\.googleapis\.com`, `.*\.storage\.goog`),
            Signatures:     []HTTPSignature{{Body: "The specified bucket does not exist", Status: []int{404}}},
            DanglingStatus: []int{404},
            Note:           "claim by creating a bucket with the same name (CNAME to <bucket>.storage.googleapis.com)",
        },
        &Fingerprint{
            Service: "DigitalOcean Spaces", Vulnerable: true,
            CNAMEs:         mustCNAME(`.*\.digitaloceanspaces\.com`),
            Signatures:     []HTTPSignature{{Body: "The specified bucket does not exist", Status: []int{404}}},
            DanglingStatus: []int{404},
            Note:           "claim by creating a Space with the same name in the same region",
        },
        &Fingerprint{
            Service: "Firebase Hosting", Vulnerable: true,
            CNAMEs:         mustCNAME(`.*\.web\.app`, `.*\.firebaseapp\.com`),
            Signatures:     []HTTPSignature{{Body: "Why am I seeing this?", Status: []int{404}}},
            DanglingStatus: []int{404},
            Note:           "claim by creating a Firebase project with the same site name and deploying Hosting",
        },
        &Fingerprint{
            Service: "Webflow", Vulnerable: true,
            CNAMEs:         mustCNAME(`.*\.proxy-ssl\.webflow\.com`, `.*\.webflow\.io`),
            Signatures:     []HTTPSignature{{Body: "The page you are looking for doesn't exist or has been moved", Status: []int{404}}},
            DanglingStatus: []int{404},
            Note:           "claim via a Webflow project on the same subdomain / custom domain slot",
        },
    )
}