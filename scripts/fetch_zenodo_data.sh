#!/usr/bin/env bash
# fetch_zenodo_data.sh — download data/ablation/ (the raw run outputs) from Zenodo and verify it.
#
# The GitHub repository omits data/ablation/ (132 run directories, 3,024 files, 2.8 GB). This script
# downloads the archived package msfv-replication-package-v1.0.tar.gz from Zenodo record 22704663
# (24 parts of ≤ 20 MiB), verifies every part and the reassembled archive against the published
# SHA-256 sums, extracts data/ablation/ into this repository and verifies the extracted files against
# CHECKSUMS.sha256. It is safe to re-run: parts that are already present and verified are not fetched again.
#
# Usage:  scripts/fetch_zenodo_data.sh [--keep-archive]
# Needs:  curl or wget, tar, sha256sum or shasum; ~3.3 GB free (485 MB download + 2.8 GB extracted).
set -euo pipefail

RECORD=22704663                                   # Zenodo record of package version 1.0 (the data archive)
BASE="https://zenodo.org/records/${RECORD}/files"
ARCHIVE="msfv-replication-package-v1.0.tar.gz"
ARCHIVE_SHA256="e948413aba7d7ad193a3170cd0d5792079c7cf578d3a08d6df67e9a1525fc3cc"
NPARTS=24

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${REPO}/data/.zenodo"                       # download area, ignored by git
KEEP=0
[ "${1:-}" = "--keep-archive" ] && KEEP=1

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
  sha256_check() { sha256sum -c --quiet "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
  sha256_check() { shasum -a 256 -c --quiet "$1"; }
else
  echo "error: need sha256sum or shasum" >&2; exit 1
fi

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fL --retry 5 --retry-delay 3 -C - -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -c -O "$2" "$1"; }
else
  echo "error: need curl or wget" >&2; exit 1
fi

[ -f "${REPO}/CHECKSUMS.sha256" ] || { echo "error: run this script from a checkout of msfv-replication" >&2; exit 1; }
mkdir -p "$WORK"
cd "$WORK"

echo "== SHA256SUMS.txt"
rm -f SHA256SUMS.txt
fetch "${BASE}/SHA256SUMS.txt?download=1" SHA256SUMS.txt
grep -q "^${ARCHIVE_SHA256}  ${ARCHIVE}\$" SHA256SUMS.txt \
  || { echo "error: SHA256SUMS.txt does not list the expected archive checksum" >&2; exit 1; }

i=0
while [ "$i" -lt "$NPARTS" ]; do
  part=$(printf '%s.part%02d' "$ARCHIVE" "$i")
  want=$(awk -v f="$part" '$2 == f { print $1 }' SHA256SUMS.txt)
  [ -n "$want" ] || { echo "error: no checksum listed for $part" >&2; exit 1; }
  if [ -f "$part" ] && [ "$(sha256 "$part")" = "$want" ]; then
    echo "== $part: present, checksum OK"
  else
    echo "== $part: downloading"
    fetch "${BASE}/${part}?download=1" "$part"
    if [ "$(sha256 "$part")" != "$want" ]; then
      echo "error: checksum mismatch for $part (removed; re-run to download it again)" >&2
      rm -f "$part"; exit 1
    fi
  fi
  i=$((i + 1))
done

echo "== reassembling $ARCHIVE"
if [ -f "$ARCHIVE" ] && [ "$(sha256 "$ARCHIVE")" = "$ARCHIVE_SHA256" ]; then
  echo "   archive present, SHA-256 OK"
else
  cat "${ARCHIVE}".part?? > "$ARCHIVE"
  [ "$(sha256 "$ARCHIVE")" = "$ARCHIVE_SHA256" ] \
    || { echo "error: reassembled archive does not match SHA-256 ${ARCHIVE_SHA256}" >&2; exit 1; }
  echo "   SHA-256 OK: $ARCHIVE_SHA256"
fi

echo "== extracting msfv-replication/data/ablation into ${REPO}/data/ablation"
tar -xzf "$ARCHIVE" -C "$REPO" --strip-components=1 msfv-replication/data/ablation

echo "== verifying extracted files against CHECKSUMS.sha256"
cd "$REPO"
grep '  data/ablation/' CHECKSUMS.sha256 > "$WORK/ablation.sha256"
sha256_check "$WORK/ablation.sha256"
echo "   $(wc -l < "$WORK/ablation.sha256" | tr -d ' ') files OK"

if [ "$KEEP" -eq 0 ]; then
  rm -f "$WORK/${ARCHIVE}".part?? "$WORK/$ARCHIVE"
  echo "== removed the downloaded parts and archive (pass --keep-archive to keep them in data/.zenodo/)"
fi
echo "== done. data/ablation/ is in place; regenerate the tables with:  cd analysis && sh make_tables.sh"
