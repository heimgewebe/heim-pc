#!/usr/bin/env bash
set -euo pipefail
OUT_ROOT="$HOME/.local/share/heim-utilities/program-inventory"
OUT="${1:-$(readlink -f "$OUT_ROOT/latest")}"
if [[ ! -d "$OUT" ]]; then
  echo "missing inventory dir: $OUT" >&2
  exit 2
fi
TMP="$(mktemp)"
ERR="$OUT/executables_full_rootfs_sudo.stderr"
CSV="$OUT/executables_full_rootfs_sudo.csv"
JSON="$OUT/full-rootfs-sudo-scan-result.json"
DELTA="$OUT/sudo-delta-summary.json"
ADDED="$OUT/executables_added_by_sudo.csv"
START_TS="$(date -Is)"
START_EPOCH="$(date +%s)"

# Metadata-only scan: no file contents are read. Pseudo/runtime mounts are excluded.
sudo find / -xdev \
  \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp -o -path /mnt -o -path /media -o -path /lost+found \) -prune -o \
  -type f -perm /111 -printf '%p\t%s\t%T@\n' \
  > "$TMP" 2> "$ERR" || FIND_RC=$?
FIND_RC="${FIND_RC:-0}"
python3 - "$TMP" "$CSV" "$JSON" "$ERR" "$FIND_RC" "$START_TS" "$START_EPOCH" "$OUT/executables_full_rootfs.csv" "$ADDED" "$DELTA" <<'PY'
import csv, json, sys, time
from collections import Counter
from pathlib import Path
src=Path(sys.argv[1]); csv_path=Path(sys.argv[2]); json_path=Path(sys.argv[3]); err_path=Path(sys.argv[4])
find_rc=int(sys.argv[5]); start_ts=sys.argv[6]; start_epoch=int(sys.argv[7])
non_sudo_csv=Path(sys.argv[8]); added_csv=Path(sys.argv[9]); delta_json=Path(sys.argv[10])
rows=[]
for line in src.read_text(errors='replace').splitlines():
    try:
        path,size,mtime=line.split('\t',2)
    except ValueError:
        continue
    rows.append({'name':Path(path).name, 'path':path, 'size':size, 'mtime':mtime})
rows=sorted(rows, key=lambda d:(d['name'].lower(), d['path']))
with csv_path.open('w', newline='', encoding='utf-8') as f:
    w=csv.DictWriter(f, fieldnames=['name','path','size','mtime'])
    w.writeheader(); w.writerows(rows)
err_lines=err_path.read_text(errors='replace').splitlines() if err_path.exists() else []
summary={
    'started_at': start_ts,
    'finished_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
    'duration_sec': int(time.time())-start_epoch,
    'find_rc': find_rc,
    'count': len(rows),
    'csv': str(csv_path),
    'stderr_file': str(err_path),
    'stderr_tail': err_lines[-50:],
    'note': 'sudo metadata-only executable scan; no file contents read',
}
json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
non_paths=set()
if non_sudo_csv.exists():
    with non_sudo_csv.open(newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            non_paths.add(row.get('path',''))
added=[row for row in rows if row['path'] not in non_paths]
with added_csv.open('w', newline='', encoding='utf-8') as f:
    w=csv.DictWriter(f, fieldnames=['name','path','size','mtime'])
    w.writeheader(); w.writerows(added)
def prefix(path: str) -> str:
    parts=Path(path).parts
    return '/'.join(parts[:3]).replace('//','/') if len(parts) > 3 else path
delta={
    'inventory': str(csv_path.parent),
    'non_sudo_count': len(non_paths),
    'sudo_count': len(rows),
    'added_by_sudo': len(added),
    'top_added_prefixes': Counter(prefix(row['path']) for row in added).most_common(30),
    'top_added_names': Counter(row['name'] for row in added).most_common(40),
}
delta_json.write_text(json.dumps(delta, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
print(json.dumps(summary, indent=2, ensure_ascii=False))
PY
rm -f "$TMP"
ls -lh "$CSV" "$JSON" "$ERR" "$ADDED" "$DELTA"
