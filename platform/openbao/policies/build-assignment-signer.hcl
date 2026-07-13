path "transit/keys/build-assignment" {
  capabilities = ["read"]
}

path "transit/sign/build-assignment" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}
