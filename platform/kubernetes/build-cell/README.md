# Build cell and durable BuildService deployment

The build cell is a dedicated execution boundary. The base manifests are intentionally not a complete site configuration: they reference site-owned endpoints, public assignment keys, trust roots, and object-store credentials that must be supplied by an overlay.

## Prerequisites

- dedicated build nodes labeled `lrail.dev/pool=build` and `lrail.dev/kata=true`
- build-node taint `lrail.dev/build=true:NoSchedule`
- hardware virtualization and a working `kata-qemu` RuntimeClass
- Kata shared-file-system extended attributes enabled (for virtio-fs, include `--xattr` in `virtio_fs_extra_args`)
- Cilium with `CiliumNetworkPolicy` support
- Kyverno and cert-manager CRDs
- a `lrail-internal-ca` cert-manager ClusterIssuer
- HTTPS OpenBao and S3-compatible endpoints
- an OpenBao Transit Ed25519 key and dedicated Kubernetes-auth role for evidence signing
- a separate OpenBao Transit Ed25519 key and five-minute Kubernetes-auth role for build-assignment signing
- an RWX storage class; the example selects `rook-cephfs` for the versioned Trivy database
- an RWO storage class; the example selects `rook-ceph-block` for singleton broker state
- a site-owned, anonymous-read Harbor mirror of the Trivy vulnerability database
- the anonymous-read, digest-pinned LayerRail curated toolchain bases declared by the broker catalog
- the final published, digest-pinned build broker, controller, worker, egress-proxy, registry-broker, evidence-signer, Trivy DB updater, and residue-agent images
- an HTTPS Harbor origin with token expiry no greater than 15 minutes

The example overlay contains only non-authentic placeholders. Replace its public keys, CAs, endpoints, object credentials, Harbor administrator credential, storage-class names, and `lrail-build-images` Docker config through the production secret/configuration workflow. The component package token needs read-only access to these eight private packages and no repository or write scope. Never commit real credentials or private key material.

`lrail-s3-ca` is an explicit PEM trust bundle for BuildCell object storage. Include every CA root needed by that endpoint; the controller enforces TLS 1.3 and does not fall back to ambient host roots. The broker uses the equivalent site bundle for both split S3 identities, and that bundle may contain distinct roots when source and cell endpoints differ.

## Durable BuildService boundary

`lrail-build-broker` is a singleton because generation fencing, exact signed-assignment checkpoints, and retained events use one Bolt volume. `Recreate` plus a `ReadWriteOnce` claim prevents concurrent writers. It runs as UID/GID 65532 with a read-only root filesystem and no Kubernetes API, PostgreSQL, source-provider, Harbor-administration, or evidence-signing authority.

A production overlay must supply two different object identities:

- `lrail-build-broker-source-s3` may only `GetObject` under the finalized source snapshot prefix;
- `lrail-build-broker-cell-s3` may only `GetObject` and `PutObject` under exactly one selected cell content prefix.

The IAM JSON files under `base/policies` are scope templates. Replace `cell-example` with the selected cell's exact prefix before installing the cell-write policy. Never combine these identities. The broker site ConfigMap owns the immutable build policy, base catalog, exact cell identity, TLS S3 origins, OpenBao assignment identity, and BuildCell mTLS endpoint. The broker image is pinned by registry digest and its GHCR package is private; do not replace the digest with a mutable tag. Curated build bases are separately public for tokenless workers, pinned by catalog and policy digest, limited to their actual platform, and preserve an exact pinned upstream root filesystem in one OCI layer.

Mount `lrail-control-worker-build-client-tls` into the control-worker workload and configure:

```text
LRAIL_BUILD_SERVICE_ENDPOINT=https://lrail-build-broker.lrail-control.svc.cluster.local:9444
LRAIL_BUILD_SERVICE_CA_FILE=/run/lrail-build-service/ca.crt
LRAIL_BUILD_SERVICE_CLIENT_CERT=/run/lrail-build-service/tls.crt
LRAIL_BUILD_SERVICE_CLIENT_KEY=/run/lrail-build-service/tls.key
```

The broker accepts only `spiffe://lrail.internal/control-worker`. BuildCell accepts only `spiffe://lrail.internal/build-broker`. Certificates rotate every 24 hours. Go services reload certificate files; the Ruby client creates a fresh verified TLS 1.3 connection for each activity request.

Provision the dedicated Transit key and Kubernetes-auth role using [the assignment signer runbook](../../openbao/build-assignment-signer.md). Publish its public key to BuildCell before starting the broker. Startup fails closed unless a live preflight signature verifies under the pinned key ID, algorithm, and PKIX public-key digest.

Roll out BuildCell dependencies first, then the broker, and then control workers. A broker restart must reopen the original Bolt volume, enumerate nonterminal generations, and reuse the exact signed assignment bytes. If the volume is unavailable or an OpenBao/BuildCell preflight fails, leave the broker unavailable; never start an empty replacement against an active cell. M-B stops at Rails `artifact_ready` truth and must not create a release, target bundle, route, Kubernetes runtime workload, or runtime process.

## Render and validate

```sh
kubectl kustomize platform/kubernetes/build-cell/base
kubectl kustomize platform/kubernetes/build-cell/overlays/example
```

The standard Kubernetes policies establish namespace default deny and endpoint identity. Workers can resolve only the fixed `lrail-build-egress` Service and connect only to its TLS port. Every networked LLB vertex is pinned to a loopback CONNECT bridge; the bridge presents a short-lived client certificate whose signed extension contains the exact assignment lock. The worker Job, ephemeral worker mTLS, and egress certificate derive their deadline directly from the signed assignment, never from the shorter OpenBao acquisition-token TTL. The owned proxy resolves each declared domain again for every connection, validates every returned IP, dials only the numeric validated address, and emits domain-level canonical JSON audit metadata before opening the socket. Audit write failure denies the connection.

Public destinations are limited to exact base registries and package/allowlist hosts. Private mappings accept only explicit RFC1918/CGNAT/ULA CIDRs, TCP ports, and optional exact domains; every private-domain answer must remain inside its mapped CIDRs. A site overlay must add matching proxy egress policy for those exact private CIDR/port pairs. Worker policy never grants direct access to customer destinations.

Harbor administrator and generated robot secrets exist only in `lrail-build-registry-broker`. The broker reconciles one private immutable Harbor project per organization, creates a one-day project robot internally, exchanges it for a Harbor JWT limited to one deterministic repository and at most 15 minutes, and returns only that JWT to the controller over mTLS. The controller verifies every config/layer/manifest digest while publishing, reads the manifest back by digest, revokes the robot lease, and reports success only after revocation. Static outputs become deterministic OCI artifacts and also receive an immutable S3 publication manifest. Retention deletion requires reference removal, replication convergence, protected-set denial, metadata backup, and immutable authorization/tombstone records. Regional replication requests remain durable `requested` records; they do not claim availability before a later regional verifier exists.

## Supply-chain evidence

The signed assignment lock fixes Syft 1.46.0, Trivy 0.72.0, the accepted evidence-signing key digests, and the minimum policy thresholds. To preserve those tool APIs after upstream release binaries acquired fixed HIGH vulnerabilities, the production Dockerfiles checksum-pin the release source commits and rebuild both tools with Go 1.26.5; Trivy also pins security-fixed ORAS 2.6.2. The published controller/updater image digests identify those exact remediated builds. The controller validates and scans the local OCI export without registry credentials. Image and static outputs both receive SPDX 2.3, normalized Trivy findings, SLSA provenance v1, a Cosign simple-signing signature, and a signed policy decision. Secrets, denied vulnerabilities, denied configuration findings, or forbidden licenses stop the flow before Harbor capability issuance.

`lrail-build-evidence-signer` is the only process allowed to use the Transit signing path. Its OpenBao role must issue tokens for no more than five minutes and permit only `read` on `transit/keys/build-evidence`, `update` on `transit/sign/build-evidence`, and self-revocation. The key must be Ed25519, non-derived, non-exportable, non-backupable, non-deletable, and signing-capable. Put the SHA-256 digest of its PKIX public key in the signed supply-chain policy. The signer authenticates for each call with its projected `openbao.lrail.internal` audience token; it never mounts a private key.

The Trivy updater uses the exact FQDN in `trivy-db-repository`; do not point it at a customer-authenticated project. The six-hour job downloads into a unique generation, computes the database digest, and atomically moves the `current` symlink while retaining one previous generation. Controller bootstrap uses the same locked script. The controller mounts the claim read-only and fails scans when metadata is stale. Size the RWX claim for two full databases plus one in-progress refresh; 10 GiB is the current floor, not a permanent capacity promise.

Evidence manifests stay in the subject repository and point to the exact subject digest. Native OCI Referrers discovery is preferred. Registries returning 404 use the OCI 1.1 referrers-index fallback, and the image signature also receives the conventional Cosign `.sig` alias. Worker, controller, and durable-store checks all require five complete, unique, trusted references before success.

The reproducible local conformance commands are `task build-evidence:test:real`, `task build-evidence:test:openbao-real`, `task build-evidence:test:database-real`, and `task build-registry:test:real`. These prove real pinned tool behavior but do not substitute for production Harbor HA, OpenBao Kubernetes-auth, CephFS, backup, or regional verification tests.

## Required production gate

A rendered manifest is not Kata, Harbor, OpenBao, or CephFS evidence. Before a cell becomes schedulable, run the malicious host/API/socket/token fixture, DNS-rebinding/private-endpoint proxy corpus, worker-kill retry, cache round trip, forced cancellation, exact CRI/mount/cgroup residue cleanup, node-quarantine tests, Transit key-policy and token-revocation checks, two-generation Trivy refresh, secret-seeded publication denial, referrer/Cosign verification, backup/restore, and RWX failover on the production environment. The current gVisor/rootless Docker, Distribution, local OpenBao, and local-volume results are functional evidence only.
