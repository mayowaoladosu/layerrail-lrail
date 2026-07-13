# Build assignment signer

The build broker signs only generation-bound BuildCell assignments. It authenticates with the projected token for ServiceAccount `lrail-build-broker` in namespace `lrail-control`; no static OpenBao token belongs in Kubernetes or this repository.

Provision the dedicated authority from an authenticated operator terminal:

```sh
bao secrets enable -path=transit transit
bao write transit/keys/build-assignment type=ed25519 derived=false exportable=false allow_plaintext_backup=false
bao write transit/keys/build-assignment/config deletion_allowed=false
bao policy write build-assignment-signer platform/openbao/policies/build-assignment-signer.hcl
bao write auth/kubernetes/role/build-assignment-signer \
  bound_service_account_names=lrail-build-broker \
  bound_service_account_namespaces=lrail-control \
  audience=openbao.lrail.internal \
  token_policies=build-assignment-signer \
  token_no_default_policy=true \
  token_ttl=5m \
  token_max_ttl=5m \
  token_explicit_max_ttl=5m
```

If the Transit mount already exists, the first command must report that fact and the operator must verify the existing mount rather than replacing it. The key must remain Ed25519, non-derived, non-exportable, non-backupable, non-deletable, and signing-capable.

Read the latest public key from `transit/keys/build-assignment`, decode the canonical base64 Ed25519 bytes, encode them as PKIX SubjectPublicKeyInfo, and pin its SHA-256 digest in `assignment-public-key-digest`. Put the same raw 32-byte public key under key ID `lrail-build-assignment` in the BuildCell assignment-key ConfigMap. The broker performs a signed preflight and refuses startup if the key ID, algorithm, signature, or public-key digest differs.

Rotation is additive: publish the new public key to every target BuildCell first, update the broker key ID/digest second, retain the prior public key longer than the maximum one-hour assignment lifetime, and remove it only after all old assignments are terminal. OpenBao audit logging must be enabled before this role is admitted.
