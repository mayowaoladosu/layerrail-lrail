#!/bin/sh
set -eu

root=/var/lib/lrail-trivy
exec /usr/bin/flock -x "${root}/update.lock" /bin/sh -ec '
  root=/var/lib/lrail-trivy
  next=""
  name=""
  current_link="${root}/.current-$$"
  previous_link="${root}/.previous-$$"
  valid_version() {
    [ "${#1}" -eq 12 ] || return 1
    case "$1" in
      .db-[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) return 0 ;;
      *) return 1 ;;
    esac
  }
  prune_unreferenced() {
    keep_current="$1"
    keep_previous="$2"
    for candidate in "${root}"/.db-*; do
      [ -d "${candidate}" ] || continue
      [ ! -L "${candidate}" ] || exit 1
      candidate_name="$(basename "${candidate}")"
      valid_version "${candidate_name}" || exit 1
      if [ "${candidate_name}" != "${keep_current}" ] && [ "${candidate_name}" != "${keep_previous}" ]; then
        rm -rf "${candidate}"
      fi
    done
  }
  cleanup() {
    rm -f "${current_link}" "${previous_link}"
    if [ -n "${next:-}" ] && [ -d "${next}" ]; then
      rm -rf "${next}"
    fi
  }
  trap cleanup EXIT HUP INT TERM
  rm -f "${current_link}" "${previous_link}"
  old_current=""
  old_previous=""
  if [ -L "${root}/current" ]; then
    old_current="$(readlink "${root}/current")"
  fi
  if [ -L "${root}/previous" ]; then
    old_previous="$(readlink "${root}/previous")"
  fi
  if [ -n "${old_current}" ]; then
    valid_version "${old_current}" || exit 1
    test ! -L "${root}/${old_current}"
    test -d "${root}/${old_current}"
  fi
  if [ -n "${old_previous}" ]; then
    valid_version "${old_previous}" || exit 1
    test ! -L "${root}/${old_previous}"
    test -d "${root}/${old_previous}"
  fi
  prune_unreferenced "${old_current}" "${old_previous}"
  next="$(mktemp -d "${root}/.db-XXXXXXXX")"
  name="$(basename "${next}")"
  /usr/local/bin/trivy image \
    --download-db-only \
    --cache-dir "${next}" \
    --db-repository "${TRIVY_DB_REPOSITORY}" \
    --disable-telemetry \
    --no-progress
  test -s "${next}/db/metadata.json"
  test -s "${next}/db/trivy.db"
  set -- $(sha256sum "${next}/db/trivy.db")
  printf "sha256:%s\n" "$1" > "${next}/db/trivy.db.sha256"
  test "$(wc -c < "${next}/db/trivy.db.sha256")" -eq 72
  ln -s "${name}" "${current_link}"
  mv -fT "${current_link}" "${root}/current"
  next=""
  if [ -n "${old_current}" ]; then
    ln -s "${old_current}" "${previous_link}"
    mv -fT "${previous_link}" "${root}/previous"
  fi
  prune_unreferenced "$(readlink "${root}/current")" "$(readlink "${root}/previous" 2>/dev/null || true)"
'
