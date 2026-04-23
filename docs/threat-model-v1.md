# Threat Model v1

## In Scope Attackers

- passive network observer
- active man-in-the-middle attacker
- mutation replay attacker
- unauthorized writer
- namespace race attacker
- malicious subscriber
- storage exhaustion attacker
- malformed parser input attacker
- path confusion attacker
- cross-tenant confidentiality attacker
- KMS or wrapped-key misuse attacker

## Security Objectives

- never expose plaintext object data to the storage server in the public profile
- never persist plaintext chunks, manifests, namespace state, audit data, event
  logs, or backup material to disk
- prevent cross-tenant equality leakage through plaintext deduplication
- bind public authorization to the active transport channel
- provide deterministic, testable authorization decisions for native and gateway
  paths

## Release Gates

- fuzzing for CBOR, frames, tokens, bootstrap, and path parsers
- dependency review and SBOM publication
- static analysis and lint baselines
- external or independent internal security review

