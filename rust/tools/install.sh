#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 John Crispin <john@phrozen.org>
# Install tgend: binaries, config and unit.
set -eu

PREFIX=/opt/traffic-generator
CONFIG_DIR=/etc/traffic-generator
SOURCE=$(cd "$(dirname "$0")/.." && pwd)

[ "$(id -u)" = 0 ] || { echo "install.sh: must run as root" >&2; exit 1; }

# Deliberately does not build. Building as root leaves a root-owned target
# directory that breaks every later developer build, and cargo is usually only
# on the invoking user's PATH anyway.
for binary in tgend tgen; do
    [ -x "$SOURCE/target/release/$binary" ] && continue
    echo "install.sh: $SOURCE/target/release/$binary is missing." >&2
    echo "            run 'cargo build --release' first, as your normal user." >&2
    exit 1
done

echo "==> binaries in $PREFIX/bin"
install -d "$PREFIX/bin"
install -m 755 "$SOURCE/target/release/tgend" "$PREFIX/bin/tgend"
install -m 755 "$SOURCE/target/release/tgen" "$PREFIX/bin/tgen"
ln -sf "$PREFIX/bin/tgen" /usr/local/bin/tgen

echo "==> config at $CONFIG_DIR/config.json"
install -d "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    install -m 600 "$SOURCE/../configs/example.json" "$CONFIG_DIR/config.json"
    echo "    example installed, mode 600 because it carries the bearer token."
    echo "    EDIT IT: set your own ports and replace the placeholder token,"
    echo "    or tgend will refuse to start."
else
    echo "    already present, left alone"
fi

echo "==> unit"
install -m 644 "$SOURCE/systemd/tgend.service" /etc/systemd/system/tgend.service
systemctl daemon-reload

echo
echo "Done. Next:"
echo "  systemctl restart tgend"
echo "  tgen ports"
