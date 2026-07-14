# M-B build-cell lab

This lab drives the real local and exact-Git source-to-artifact journeys required by M-B. It is deliberately separate from the production overlay because lab credentials, a single-node storage class, and local dependency topology are not production material.

The supported cluster context is `lrail-alpha`. Before applying any mutation, the setup script checks that exact context and the expected minikube node. It installs only pinned dependency versions and records every immutable image/chart digest in `versions.json`.

## Gate

A successful lab run must prove all of the following from externally observable state:

- the CLI uploads a deterministic local snapshot and creates a deployment;
- a signed exact Git delivery resolves one commit and creates one deployment;
- NATS starts a generation-bound Temporal workflow;
- the broker runs detector → owned Starlark → Build IR → locked LLB;
- BuildCell executes a real BuildKit worker under `kata-qemu`;
- Harbor returns an immutable manifest digest and five complete signed evidence references;
- retained events reconnect from a persisted cursor;
- Rails reaches `artifact_ready` with a Revision and all attestations;
- cleanup is `clean`, no worker resources remain, and no Release, TargetBundle, route, or runtime workload exists.

`task mb:lab:up` installs dependencies and produces a generated, gitignored runtime overlay under `.work/mb-lab`. `task mb:lab:local` and `task mb:lab:git` execute the journeys. `task mb:lab:verify` reruns the negative/recovery assertions without mutating successful artifact truth. `task mb:lab:down` removes only resources labeled `dev.lrail/lab=mb`; it does not delete the shared `lrail-alpha` cluster.

## Kata prerequisite

Kata 3.32.0 is installed from the checksum-verified official chart. The lab refuses to continue until a tokenless probe prints `kata-qemu-ok`. A RuntimeClass object or `/dev/kvm` alone is not evidence.

On Docker Desktop/WSL2, nested KVM may create qemu successfully but fail to boot the guest agent, observed as `timed out connecting to vsock ...:1024`. That host failure is fail-closed: do not relabel gVisor or runc as Kata, and do not claim M-B complete. Move the same generated overlay to a nested-virtualization-capable Linux node or repair the host runtime, then rerun the probe.

## Functional gVisor cell

`task mb:lab:functional-cell` deploys the same controller, durable broker, disposable BuildKit worker, Harbor, and evidence plumbing with the `gvisor` RuntimeClass. This is a separately labeled functional lab path for continuing end-to-end integration while the host cannot boot Kata. It does not satisfy or waive the Kata prerequisite, and its success must never be reported as M-B completion.

The functional overlay is intentionally narrow: it changes the worker RuntimeClass and node selector, removes AppArmor fields because Docker Desktop does not expose host AppArmor enforcement, selects the single-node storage class, grants the controller/updater HTTPS access only to the Trivy database registry and blob redirect host, and permits the controller to reach minikube's API backend only on port 8443 when Cilium classifies it as either the local host or the remote `kube-apiserver` identity. gVisor does not honor the rootless mapping helpers under Restricted Pod Security, so this namespace enforces Baseline while Kyverno requires non-root execution, no API token, all capabilities dropped, then adds exactly `SETGID` and `SETUID` for rootlesskit's subordinate-ID mapping and permits that helper elevation. The two capabilities exist only inside the gVisor sandbox. Because gVisor cannot create rootlesskit's nested PID namespace, the functional worker disables only that nested namespace; signed DSL execution still requires a non-root uid/gid, while the quota peer runs under a separate rootless user namespace and the outer supervisor remains a different uid. The overlay also issues lab-only loopback TLS names and allows node-originated traffic to the broker port so a local Linux control-worker container can traverse a Kubernetes port-forward; the broker still requires the exact control-worker SPIFFE client certificate. Production manifests retain the nested PID namespace, Restricted Pod Security, zero added capabilities, disabled privilege escalation, Kata, AppArmor, service-DNS-only certificates, and pod-identity ingress requirements; their one-ID mapping path never executes the privileged mapping helpers.

## Secrets

The setup script generates short-lived lab-only CA, mTLS, S3, Harbor, OpenBao, and API credentials directly into `.work/mb-lab`. It never writes credential values into tracked files or terminal output. The repository secret scanner includes untracked, non-ignored text; generated runtime material is ignored by `.gitignore` and must be destroyed with the teardown task.
