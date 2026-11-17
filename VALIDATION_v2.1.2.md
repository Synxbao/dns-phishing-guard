# Validation — DNS Phishing Guard v2.1.2

## Automated checks

- JavaScript/MJS syntax: PASS
- JSON parsing: PASS
- Manifest paths: PASS
- Risk Engine tests: PASS
- OAuth/SSO auth-flow tests: PASS
- Typosquat tests: PASS
- Content Safety tests: PASS
- Parent Control tests: PASS
- Public Suffix tests: PASS
- URL model Python/JavaScript parity cases: PASS

## New regression case

A Google account chooser URL reached from `feid.fpt.edu.vn` is modeled with:

- current host `accounts.google.com`
- one cross-domain redirect
- official Google OAuth/OIDC endpoint
- relying party `fpt.edu.vn`
- raw URL-ML probability forced to 100% in the test

Expected and observed result:

- network redirect score: 0
- hybrid level: SAFE
- binary prediction: SAFE
- total score: at most 8

## Not validated automatically

Chrome/Edge service-worker lifecycle, actual `webNavigation` event qualifiers, popup rendering, DNR behavior, and the exact live FPT-to-Google flow were not executed in a real browser by this validation run. Reload the extension and refresh existing tabs before browser testing.
