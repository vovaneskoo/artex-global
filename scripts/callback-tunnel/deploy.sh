#!/usr/bin/env bash
# Copy callback-tunnel assets into the bench VM (host side).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
vm="${ARTEX_MISSION_VM:-artex-bench}"
dest="${ARTEX_OAST_GUEST_DIR:-artex-oast}"
limactl shell "$vm" -- bash -lc "mkdir -p ~/$dest"
limactl cp "$here/oastd.py" "$here/oast.sh" "$vm:$dest/"
limactl shell "$vm" -- bash -lc "chmod +x ~/$dest/oast.sh"
echo "deployed to ~/$dest on $vm"
