package bundle_test

// bundle_test.go — bundle verification tests.
// TODO: rewrite for ExternalDSREnvelope format once test fixture helpers are available.
// The old tests referenced dsr.Receipt, dsr.CanonicalContent, dsr.Version, etc.
// which no longer exist. See internal/verify/parity_test.go for end-to-end coverage.
//
// RSA-PSS and ECDSA manifest signature tests (G-4) also need porting to
// use bundle.Manifest directly — they don't depend on receipt format but
// the helper functions that built test bundles used dsr.Receipt.
// Track: port TestVerifyBYOKBundleRSAPSS / TestVerifyBYOKBundleECDSA.
