# Build cell deployment

The build cell is a dedicated execution boundary. The base manifests are intentionally not a complete site configuration: they reference site-owned endpoints, public assignment keys, trust roots, and object-store credentials that must be supplied by an overlay.

## Prerequisites

- dedicated build nodes labeled `lrail.dev/pool=build` and `lrail.dev/kata=true`
- build-node taint `lrail.dev/build=true:NoSchedule`
- hardware virtualization and a working `kata-qemu` RuntimeClass
- Cilium with `CiliumNetworkPolicy` support
- Kyverno and cert-manager CRDs
- a `lrail-internal-ca` cert-manager ClusterIssuer
- HTTPS OpenBao and S3-compatible endpoints
- the final published, digest-pinned controller, worker, egress-proxy, registry-broker, and residue-agent images
- an HTTPS Harbor origin with token expiry no greater than 15 minutes

The example overlay contains only non-authentic placeholders. Replace its public key, CA, endpoint, object credential, Harbor administrator credential, and `lrail-build-images` Docker config through the production secret/configuration workflow. The component package token needs read-only access to these five private packages and no repository or write scope. Never commit real credentials or private key material.

## Render and validate

```sh
kubectl kustomize platform/kubernetes/build-cell/base
kubectl kustomize platform/kubernetes/build-cell/overlays/example
```

The standard Kubernetes policies establish namespace default deny and endpoint identity. Workers can resolve only the fixed `lrail-build-egress` Service and connect only to its TLS port. Every networked LLB vertex is pinned to a loopback CONNECT bridge; the bridge presents a short-lived client certificate whose signed extension contains the exact assignment lock. The owned proxy resolves each declared domain again for every connection, validates every returned IP, dials only the numeric validated address, and emits domain-level canonical JSON audit metadata before opening the socket. Audit write failure denies the connection.

Public destinations are limited to exact base registries and package/allowlist hosts. Private mappings accept only explicit RFC1918/CGNAT/ULA CIDRs, TCP ports, and optional exact domains; every private-domain answer must remain inside its mapped CIDRs. A site overlay must add matching proxy egress policy for those exact private CIDR/port pairs. Worker policy never grants direct access to customer destinations.

Harbor administrator and generated robot secrets exist only in `lrail-build-registry-broker`. The broker reconciles one private immutable Harbor project per organization, creates a one-day project robot internally, exchanges it for a Harbor JWT limited to one deterministic repository and at most 15 minutes, and returns only that JWT to the controller over mTLS. The controller verifies every config/layer/manifest digest while publishing, reads the manifest back by digest, revokes the robot lease, and reports success only after revocation. Static outputs become deterministic OCI artifacts and also receive an immutable S3 publication manifest. Retention deletion requires reference removal, replication convergence, protected-set denial, metadata backup, and immutable authorization/tombstone records. Regional replication requests remain durable `requested` records; they do not claim availability before a later regional verifier exists.

## Required production gate

A rendered manifest is not Kata evidence. Before a cell becomes schedulable, run the malicious host/API/socket/token fixture, DNS-rebinding/private-endpoint proxy corpus, worker-kill retry, cache round trip, forced cancellation, exact CRI/mount/cgroup residue cleanup, and node-quarantine tests on the production node image with `/dev/kvm` and `kata-qemu`. The current gVisor/rootless Docker results are local functional evidence only.
