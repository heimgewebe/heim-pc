# Input: one findmnt JSON, one lsblk JSON, one losetup JSON (jq --slurp).
# Output: block paths whose raw accessibility must be tested as the live user.
# Observation only; this filter cannot authorize or perform storage effects.
def text: type == "string" and length > 0 and (test("[\u0000-\u001f\u007f]") | not);
def rows($key):
  if type == "object" and (.[$key] | type) == "array" then .[$key]
  else error("missing or invalid inventory array: " + $key) end;
def devpath: text and test("^/dev/[A-Za-z0-9_+./:-]+$") and (contains("/../") | not);
def number: text and test("^[0-9]+:[0-9]+$");

if length != 3 then error("three inventories are required") else . end
| (.[0] | rows("filesystems")) as $mounts
| (.[1] | rows("blockdevices")) as $blocks
| (.[2] | rows("loopdevices")) as $loops
| if ($mounts | length) == 0
    or (all($mounts[]; type == "object" and (.target | text)
      and (.source | text) and (.fstype | text) and (.options | text)
      and (.["maj:min"] | number)) | not)
    or (all($blocks[]; type == "object" and (.path | devpath)
      and (.type | text) and (.["maj:min"] | number)) | not)
    or (all($loops[]; type == "object" and (.name | devpath)
      and (.["back-file"] | text)) | not)
  then error("incomplete inventory fields") else . end
| if ([$mounts[] | select(.target == "/" and .fstype == "tmpfs")] | length) != 1
    or ([$mounts[] | select(.target == "/iso" and .fstype == "tmpfs")] | length) != 1
  then error("root and copied ISO must be RAM backed") else . end
# The sole block mount exception is the pinned ISO module's read-only store.
# Merely being named /dev/loop* is never sufficient.
| [ $mounts[] as $m
    | $blocks[] as $b
    | $loops[] as $l
    | select($m.target == "/nix/.ro-store" and $m.fstype == "squashfs"
      and ($m.options | split(",") | index("ro")) != null
      and $m["maj:min"] == $b["maj:min"] and $b.type == "loop"
      and $l.name == $b.path
      and ($l.name | test("^/dev/loop[0-9]+$"))
      and $l["back-file"] == "/iso/nix-store.squashfs"
      and ($m.source == $b.path or $m.source == $l["back-file"]))
    | {target: $m.target, device: $b.path, number: $b["maj:min"]}
  ] as $allowed
| if ($allowed | length) != 1 then error("unproven live store loop backing") else . end
| if any($mounts[]; . as $m |
    ((.["maj:min"] | startswith("0:")) | not) or (.source | startswith("/dev/"))
    | . and (any($allowed[]; .target == $m.target and .number == $m["maj:min"]) | not))
  then error("persistent or unrecognized block-backed mount") else . end
| [ $blocks[] | . as $b
    | select((any($allowed[]; .device == $b.path) | not)
      and ((.type == "disk" and (.path | test("^/dev/zram[0-9]+$"))) | not))
    | .path
  ] | unique
