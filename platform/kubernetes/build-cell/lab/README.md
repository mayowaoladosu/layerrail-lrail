# M-B build-cell lab

This lab drives the real local and exact-Git source-to-artifact journeys required by M-B. It is deliberately separate from the production overlay because lab credentials, a single-node storage class, and local dependency topology are not production material.

The supported cluster context is `lrail-kata`. Before applying any mutation, the setup script checks that exact context and the expected control node. The cluster joins the dedicated nested-KVM `lrail-kata-worker`; immutable dependency and platform image identities remain recorded in `versions.json`.

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

`task mb:lab:dependencies` verifies the pinned platform dependencies, `task mb:lab:kata` runs the tokenless Kata guest gate, and `task mb:lab:runc` runs a short admission-conformant worker Job that proves exact nested `10001 → 0` UID/GID maps plus final UID/GID `10001:10001`, `CapEff=0`, and `NoNewPrivs=1`. Run all three before an expensive source-to-artifact journey. Local-upload and exact-Git CLI journeys use ignored fixtures under `.work/mb-lab`; `task mb:lab:git:configure` binds a fixture to one repository-scoped GitHub App installation, `task mb:lab:git:matrix` runs the source-policy matrix, and `task mb:lab:verify` verifies final Rails artifact truth. Teardown is deliberately explicit because the nested-KVM cluster is shared lab infrastructure; never delete it as a side effect of one fixture.

The Git configuration task consumes `LRAIL_MB_FIXTURE_FILE`, `LRAIL_MB_GITHUB_INSTALLATION_ID`, `LRAIL_MB_GITHUB_ACCOUNT_LOGIN`, `LRAIL_MB_GITHUB_ACCOUNT_ID`, `LRAIL_MB_GITHUB_REPOSITORY`, and optional `LRAIL_MB_GITHUB_BRANCH`/`LRAIL_MB_GITHUB_ROOT`. The matrix task consumes the same fixture plus `LRAIL_MB_GIT_FIRST_COMMIT`, `LRAIL_MB_GIT_FORCED_COMMIT`, `LRAIL_MB_GIT_SUBMODULE_COMMIT`, and `LRAIL_MB_GIT_LFS_COMMIT`. It performs real provider acquisition for the valid commits, proves duplicate delivery creates no second fetch, records force-push supersession, rejects submodule and LFS commits before deployment creation, and prints only resource IDs and content digests. `task mb:lab:verify` consumes `LRAIL_MB_FIXTURE_FILE` and optional `LRAIL_MB_DEPLOYMENT_ID`.

On the Kata lab, run `task mb:lab:git:provider` to reconcile only the provider broker, its exact GitHub egress policy, and the ignored runtime Secret. This command never applies the functional gVisor overlay and never changes RuntimeClass, worker capabilities, controller isolation, or the strict worker image.

## Kata prerequisite

Kata 3.32.0 is installed from the checksum-verified official chart. The lab refuses to continue until a tokenless probe prints `kata-qemu-ok`. The build node's active Kata configuration must also enable virtio-fs extended attributes with `--xattr`; the strict worker fails closed before BuildKit startup when its disposable state volume cannot set, list, read, and remove a user xattr. The patched native snapshot path skips only redundant `lchown(0,0)` calls for already-flattened strict copies and rejects any other ownership; the ordinary path remains unchanged. A RuntimeClass object or `/dev/kvm` alone is not evidence.

On Docker Desktop/WSL2, nested KVM may create qemu successfully but fail to boot the guest agent, observed as `timed out connecting to vsock ...:1024`. That host failure is fail-closed: do not relabel gVisor or runc as Kata, and do not claim M-B complete. Move the same generated overlay to a nested-virtualization-capable Linux node or repair the host runtime, then rerun the probe.

## Functional gVisor cell

`task mb:lab:functional-cell` deploys the same controller, durable broker, disposable BuildKit worker, Harbor, and evidence plumbing with the `gvisor` RuntimeClass. This is a separately labeled functional lab path for continuing end-to-end integration while the host cannot boot Kata. It does not satisfy or waive the Kata prerequisite, and its success must never be reported as M-B completion.

The functional overlay is intentionally narrow: it changes the worker RuntimeClass and node selector, removes AppArmor fields because Docker Desktop does not expose host AppArmor enforcement, selects the single-node storage class, grants the controller/updater HTTPS access only to the Trivy database registry and blob redirect host, and permits the controller to reach minikube's API backend only on port 8443 when Cilium classifies it as either the local host or the remote `kube-apiserver` identity. gVisor does not honor the rootless mapping helpers under Restricted Pod Security, so this namespace enforces Baseline while Kyverno requires non-root execution, no API token, all capabilities dropped, then adds exactly `SETGID` and `SETUID` for rootlesskit's subordinate-ID mapping and permits that helper elevation. The two capabilities exist only inside the gVisor sandbox. Because gVisor cannot create rootlesskit's nested PID namespace, the functional worker disables only that nested namespace; signed DSL execution still requires a non-root uid/gid, while the quota peer runs under a separate rootless user namespace and the outer supervisor remains a different uid. The overlay also issues lab-only loopback TLS names and allows node-originated traffic to the broker port so a local Linux control-worker container can traverse a Kubernetes port-forward; the broker still requires the exact control-worker SPIFFE client certificate. Production manifests retain the nested PID namespace, Restricted Pod Security, zero added capabilities, disabled privilege escalation, Kata, AppArmor, service-DNS-only certificates, and pod-identity ingress requirements; their one-ID mapping path never executes the privileged mapping helpers.

## Secrets

The setup script generates short-lived lab-only CA, mTLS, S3, Harbor, OpenBao, and API credentials directly into `.work/mb-lab`. It never writes credential values into tracked files or terminal output. The repository secret scanner includes untracked, non-ignored text; generated runtime material is ignored by `.gitignore` and must be destroyed with the teardown task.

Real exact-Git acquisition additionally reads `.work/mb-lab/github-app.json` with only `app_id`, canonical lowercase `slug`, and an RSA `private_key`. `tools/mb_lab.py` rejects symlinks, oversized files, malformed identities, and non-RSA PEM before creating the isolated runtime Secret. The provider broker alone mounts that key; Rails, BuildCell, customer workers, source objects, fixture output, and command logs must never receive it.
