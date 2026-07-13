path "transit/keys/build-evidence" {
  capabilities = ["read"]
}

path "transit/sign/build-evidence" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}
