#!/usr/bin/env bash
# ci/frida_server.sh <version> — download a version-matched frida-server for the
# emulator's ABI, push it, and start it detached. Shared by both workflows.
set -uo pipefail
VER="${1:-17.18.0}"
adb wait-for-device
ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
echo "  device ABI = ${ABI}, frida-server ${VER}"

URL="https://github.com/frida/frida/releases/download/${VER}/frida-server-${VER}-android-${ABI}.xz"
if ! curl -fsSL "$URL" -o /tmp/fs.xz; then
  echo "  exact asset missing; resolving from release API"
  ALT=$(curl -fsSL "https://api.github.com/repos/frida/frida/releases/tags/${VER}" \
        | grep -o "https[^\"]*frida-server-[^\"]*android-${ABI}[^\"]*" | head -1)
  [ -n "${ALT:-}" ] || { echo "  ERROR: no frida-server for ${ABI}"; exit 3; }
  curl -fsSL "$ALT" -o /tmp/fs.xz
fi
xz -d /tmp/fs.xz || unxz /tmp/fs.xz
chmod +x /tmp/fs
adb root >/dev/null 2>&1 || true
adb push /tmp/fs /data/local/tmp/frida-server >/dev/null
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "su 0 /data/local/tmp/frida-server -D &" 2>/dev/null \
  || adb shell "/data/local/tmp/frida-server -D &" 2>/dev/null \
  || adb shell "nohup /data/local/tmp/frida-server >/data/local/tmp/fs.log 2>&1 &"
sleep 4
echo "  frida-server started; frida-ps -U:"
frida-ps -U 2>&1 | head -12 | sed 's/^/    /'
