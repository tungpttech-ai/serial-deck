#!/usr/bin/env bash
# Build serial-deck_<ver>_amd64.deb from a PyInstaller onedir bundle.
# usage: build-deb.sh <bundle-dir> <version> <out-dir>
set -euo pipefail
bundle=$1 version=$2 out=$3
here=$(cd "$(dirname "$0")" && pwd)
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

# dpkg replaces package files itself, so files a running Serial Deck still
# uses cannot be preserved; preinst/prerm refuse while any process runs from
# /opt/serial-deck (dpkg runs as root and does not stop users' hubs).
app="opt/serial-deck"
install -d -m 0755 "$root/DEBIAN" "$root/$app" "$root/usr/bin" \
    "$root/usr/share/applications" "$root/usr/share/doc/serial-deck"
cp -a "$bundle/." "$root/$app/"
ln -s "/$app/serial-deck" "$root/usr/bin/serial-deck"
ln -s "/$app/serial-deck-cli" "$root/usr/bin/serial-deck-cli"
install -m 0644 "$here/serial-deck.desktop" "$root/usr/share/applications/serial-deck.desktop"
for size in 16 32 48 64 128 256 512; do
    install -D -m 0644 "$here/../icons/serial-deck-$size.png" \
        "$root/usr/share/icons/hicolor/${size}x${size}/apps/serial-deck.png"
done
install -m 0644 "$here/../../LICENSE" "$root/usr/share/doc/serial-deck/copyright"
install -m 0755 "$here/deb-preinst" "$root/DEBIAN/preinst"
install -m 0755 "$here/deb-prerm" "$root/DEBIAN/prerm"

# Modes: dirs 0755, executables and shared objects 0755, data 0644.
find "$root/opt" -type d -exec chmod 0755 {} +
find "$root/opt" -type f -exec chmod 0644 {} +
chmod 0755 "$root/$app/serial-deck" "$root/$app/serial-deck-cli"
find "$root/opt" -type f \( -name '*.so' -o -name '*.so.*' \) -exec chmod 0755 {} +

# Versioned shared-library dependencies from the ELF files themselves.
mkdir -p "$root/debian"
printf 'Source: serial-deck\n\nPackage: serial-deck\nArchitecture: amd64\n' > "$root/debian/control"
mapfile -t elves < <(find "$root/opt" -type f -exec sh -c 'head -c 4 "$1" | grep -q "ELF" && echo "$1"' _ {} \;)
# Libraries inside the bundle resolve to themselves (-l); anything else must map
# to a Debian package, or the build fails rather than shipping a guess.
shlibs=$(cd "$root" && dpkg-shlibdeps -O -l"$root/$app/_internal" -e "${elves[@]}" \
    | sed -n 's/^shlibs:Depends=//p')
[ -n "$shlibs" ] || { echo "dpkg-shlibdeps found no dependencies" >&2; exit 1; }
rm -rf "$root/debian"
depends="$shlibs, xdg-utils"

size=$(du -sk "$root/opt" | cut -f1)
cat > "$root/DEBIAN/control" <<CONTROL
Package: serial-deck
Version: $version
Architecture: amd64
Maintainer: Serial Deck contributors <noreply@github.com>
Installed-Size: $size
Depends: $depends
Section: electronics
Priority: optional
Homepage: https://github.com/tungpttech-ai/serial-deck
Description: shared serial console, UART hub and ESP32 flashing
 One per-user hub owns the UARTs while a Web dashboard, Tk desktop, CLI and
 an MCP server for AI agents use the same ports at once. The app opens the
 dashboard in your browser. Add yourself to the dialout group for port access.
CONTROL

mkdir -p "$out"
fakeroot dpkg-deb --root-owner-group --build "$root" "$out/serial-deck_${version}_amd64.deb" 2>/dev/null \
    || dpkg-deb --root-owner-group --build "$root" "$out/serial-deck_${version}_amd64.deb"
echo "built $out/serial-deck_${version}_amd64.deb (Depends: $depends)"
