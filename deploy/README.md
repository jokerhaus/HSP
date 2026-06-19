# Deploy

This directory contains hardened deployment examples for the public multi-tenant
profile. The manifests are intentionally conservative:

- rootless execution
- read-only root filesystem
- dropped Linux capabilities
- runtime default seccomp
- isolated admin surface
- KMS/HSM integration via workload identity

The distribution layer adds two more deployable services:

- `deploy/kubernetes/hsp-s3-deployment.yaml`
- `deploy/kubernetes/hsp-cdn-deployment.yaml`

Operational workers for lifecycle and durability tasks:

- `deploy/kubernetes/hsp-replication-worker.yaml`
- `deploy/kubernetes/hsp-lifecycle-worker.yaml`
- `deploy/kubernetes/hsp-object-lock-worker.yaml`

These services are intended to share the same encrypted storage root, issuer
registry, namespace-authority signer, and workload identity used by the HSP
core services. The public profile remains ciphertext-only at the storage and
edge layers.

## Image Digest Policy

The Kubernetes manifests use digest-form image references. The checked-in
`ghcr.io/example/...@sha256:000...` values are placeholders for release
templates; replace them with the actual image digests produced by your registry
before applying the manifests.

Do not deploy mutable tag-only references such as `:latest` or `:0.1.x` in
production. Keep the image digest, SBOM, and release review bundle together for
the deployed commit.
