#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
status=0

patterns=(
  '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----'
  'github_pat_[A-Za-z0-9_]{20,}'
  'gh[pousr]_[A-Za-z0-9]{30,}'
  'AKIA[0-9A-Z]{16}'
  'AIza[0-9A-Za-z_-]{35}'
  'xox[baprs]-[0-9A-Za-z-]{10,}'
)

for pattern in "${patterns[@]}"; do
  if grep -RInE \
    --exclude-dir=.git \
    --exclude='*.png' --exclude='*.jpg' --exclude='*.jpeg' --exclude='*.gif' \
    -- "$pattern" "$root"; then
    status=1
  fi
done

while IFS= read -r path; do
  case "$(basename "$path")" in
    .env|.env.*|id_rsa|id_ed25519|credentials.json)
      printf 'suspicious secret-bearing filename: %s\n' "$path"
      status=1
      ;;
  esac
done < <(find "$root" -type f -not -path '*/.git/*')

if [[ "$status" -ne 0 ]]; then
  echo "secret-pattern scan failed" >&2
  exit 1
fi

echo "secret-pattern scan passed"
