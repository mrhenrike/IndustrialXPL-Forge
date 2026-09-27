#!/usr/bin/env bash
# IXF — install Mirai uClibc cross-compilers (lab use).
set -euo pipefail

IXF_CROSS="${IXF_CROSS_ROOT:-$HOME/.ixf/cross-compilers}"
FORGE_CROSS="$(cd "$(dirname "$0")/.." && pwd)/.ixf/cross-compilers"
mkdir -p "$IXF_CROSS" "$FORGE_CROSS"
cd "$IXF_CROSS"

MIRROR="${IXF_CROSS_MIRROR:-https://github.com/Hexoral/Cross-Compilers/raw/main}"

ARCHIVES=(
  cross-compiler-armv4l.tar.bz2:armv4l
  cross-compiler-armv5l.tar.bz2:armv5l
  cross-compiler-armv6l.tar.bz2:armv6l
  cross-compiler-i586.tar.bz2:i586
  cross-compiler-m68k.tar.bz2:m68k
  cross-compiler-mips.tar.bz2:mips
  cross-compiler-mipsel.tar.bz2:mipsel
  cross-compiler-powerpc.tar.bz2:powerpc
  cross-compiler-sh4.tar.bz2:sh4
  cross-compiler-sparc.tar.bz2:sparc
)

for entry in "${ARCHIVES[@]}"; do
  file="${entry%%:*}"
  dest="${entry##*:}"
  if [[ -x "$IXF_CROSS/$dest/bin/${dest%-*}-gcc" ]] || [[ -x "$IXF_CROSS/$dest/bin/${dest}-gcc" ]]; then
    echo "[ok] $dest already installed"
    continue
  fi
  echo "[dl] $file"
  wget -q --show-progress -O "$file" "$MIRROR/$file" || curl -fsSL -o "$file" "$MIRROR/$file"
  tar -xjf "$file"
  rm -f "$file"
  extracted="cross-compiler-${dest#arm}"
  extracted="cross-compiler-$dest"
  if [[ -d "cross-compiler-$dest" ]]; then
    rm -rf "$dest"
    mv "cross-compiler-$dest" "$dest"
  elif [[ -d "cross-compiler-${dest}" ]]; then
    rm -rf "$dest"
    mv "cross-compiler-${dest}" "$dest"
  else
    # armv4l → cross-compiler-armv4l
    for d in cross-compiler-*; do
      [[ -d "$d" ]] && mv "$d" "$dest" && break
    done
  fi
  echo "[done] $dest"
done

# Symlink into forge .ixf for IXF compiler discovery
for d in */; do
  name="${d%/}"
  ln -sfn "$IXF_CROSS/$name" "$FORGE_CROSS/$name"
done

# Optional system-wide PATH hook
PROFILE_SNIPPET="# IXF Mirai cross-compilers
export PATH=\"\$PATH:$IXF_CROSS/armv4l/bin:$IXF_CROSS/armv5l/bin:$IXF_CROSS/armv6l/bin:$IXF_CROSS/i586/bin:$IXF_CROSS/m68k/bin:$IXF_CROSS/mips/bin:$IXF_CROSS/mipsel/bin:$IXF_CROSS/powerpc/bin:$IXF_CROSS/sh4/bin:$IXF_CROSS/sparc/bin\""
if ! grep -q "IXF Mirai cross-compilers" "$HOME/.bashrc" 2>/dev/null; then
  echo "$PROFILE_SNIPPET" >> "$HOME/.bashrc"
fi

export PATH="$PATH:$IXF_CROSS/armv4l/bin:$IXF_CROSS/armv5l/bin:$IXF_CROSS/armv6l/bin:$IXF_CROSS/i586/bin:$IXF_CROSS/m68k/bin:$IXF_CROSS/mips/bin:$IXF_CROSS/mipsel/bin:$IXF_CROSS/powerpc/bin:$IXF_CROSS/sh4/bin:$IXF_CROSS/sparc/bin"

echo "=== Toolchain check ==="
for p in i586 mips mipsel armv4l armv5l armv6l powerpc sparc m68k sh4; do
  if command -v "${p}-gcc" >/dev/null 2>&1; then
    echo "  OK ${p}-gcc"
  else
    echo "  MISSING ${p}-gcc"
  fi
done
