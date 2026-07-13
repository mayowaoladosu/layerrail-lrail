# Local development profile

The lightweight profile is a contract-compatible development environment, not a claim that one Docker Compose host is production architecture.

## Start

1. Install the pinned tools with mise.
2. Run `task bootstrap`.
3. Run `task lab:up`.
4. Prepare the Rails databases with `task db:prepare`.
5. Start the control plane from `apps/control-plane` with `bin/dev`.

All host ports bind to `127.0.0.1`:

| Dependency      | Host endpoint            |
| --------------- | ------------------------ |
| PostgreSQL      | `127.0.0.1:55432`        |
| Temporal gRPC   | `127.0.0.1:57233`        |
| NATS            | `127.0.0.1:54222`        |
| NATS monitoring | `127.0.0.1:58222`        |
| Valkey          | `127.0.0.1:56379`        |
| Object API      | `http://127.0.0.1:59000` |
| Object console  | `http://127.0.0.1:59001` |
| Source gateway  | `http://127.0.0.1:58080` |
| Mail SMTP       | `127.0.0.1:51025`        |
| Mail UI         | `http://127.0.0.1:58025` |

The literal `local-only-not-a-secret` is intentionally public, accepted only by this loopback development stack, and prohibited in any production configuration.

`bin/dev` also starts the Solid Queue supervisor that processes durable GitHub source deliveries. Real GitHub acquisition is disabled unless a separately isolated provider-token broker is configured with a GitHub App ID, private-key secret file, controlled egress proxy, and matching source grant key. Those credentials are runtime secrets and must never be written to this repository or Rails. Hermetic provider conformance uses fake installations and fixed cryptographic fixtures; it does not require a real GitHub credential.

## Reset

`docker compose down --volumes` destroys all local dependency state. Never run this against a non-development Compose project.

## Production differences

Production requires separate networks and credentials, HA PostgreSQL/Temporal/NATS/OpenBao, short-lived workload identities, encrypted remote backups, policy-controlled infrastructure, and measured recovery evidence. No Compose credential or topology is reusable there.
