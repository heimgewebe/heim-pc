#!/usr/bin/env bash
# Rebuild a passwordless-for-the-user recovery path from the existing PC key.
# Neither logs nor argv contain password bytes. Does NOT change repository keys.
set -euo pipefail
src=/persist/secrets/restic/heim-pc-password
dir=/var/lib/heimberry/restic-recovery
dest="$dir/heim-pc.key"
tmp="$dir/.heim-pc-key.pending"
host=heimberry
ssh_args=(-o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10)
sudo -n test -s "$src"
ssh "${ssh_args[@]}" "$host" sudo -n install -d -m 0700 -o root -g root "$dir"
# Existing source key never traverses stdout/stderr of this script.
sudo -n cat "$src" | ssh "${ssh_args[@]}" "$host" "sudo -n tee '$tmp' >/dev/null"
ssh "${ssh_args[@]}" "$host" sudo -n chmod 0600 "$tmp"
ssh "${ssh_args[@]}" "$host" sudo -n mv -f -T "$tmp" "$dest"
# Actual byte equality is validated across SSH without emitting contents or hashes.
sudo -n cat "$src" | ssh "${ssh_args[@]}" "$host" sudo -n cmp -s - "$dest"
ssh "${ssh_args[@]}" "$host" sudo -n test -s "$dest"
echo "RECOVERY_KEY_ON_INDEPENDENT_HOST_MATCHES_SOURCE (contents not exposed)"
