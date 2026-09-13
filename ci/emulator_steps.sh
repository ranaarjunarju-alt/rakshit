#!/usr/bin/env bash
# ============================================================================
# ci/emulator_steps.sh — runs INSIDE reactivecircus/android-emulator-runner,
# after the emulator has booted and `adb` is live. Installs the APK, starts a
# version-matched frida-server, drives ci/frida_runner.py, and pulls the app's
# sandbox. Every step echoes what it did so the CI log is itself evidence.
#
#   $1 = seconds to run the instrumented app (default 90)
# ============================================================================
set -uo pipefail

SECONDS_TO_RUN="${1:-90}"
PKG="com.nivaroid.topfollow"
FRIDA_VERSION="17.18.0"          # MUST match the host frida python package
APK="TopFollow_v845-Beta (1).apk"

echo "==================== 0. device state ===================="
adb wait-for-device
adb shell getprop ro.build.version.sdk   | sed 's/^/  sdk=/'
adb shell getprop ro.product.cpu.abi     | sed 's/^/  abi=/'
adb shell getprop ro.build.fingerprint   | sed 's/^/  fingerprint=/'
ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
echo "  emulator ABI = ${ABI}  (this is the libtopfollow.so build that will load)"

echo "==================== 1. install the APK ===================="
# -g grants runtime perms; the APK is the original signed build, so the app's
# own signature self-check passes and we are analysing the shipping code.
adb install -g -r "$APK" || { echo "  install failed"; adb install -g "$APK"; }
adb shell pm path "$PKG" | sed 's/^/  /'

echo "==================== 2. fetch matching frida-server ===================="
# resolve the exact asset name from the GitHub release API (no hard-coded guess)
ASSET="frida-server-${FRIDA_VERSION}-android-${ABI}.xz"
URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${ASSET}"
echo "  trying $URL"
if ! curl -fsSL "$URL" -o fs.xz; then
  echo "  exact asset not found; listing release assets:"
  curl -fsSL "https://api.github.com/repos/frida/frida/releases/tags/${FRIDA_VERSION}" \
    | grep -o '"name": *"frida-server-[^"]*android-[^"]*"' | sed 's/^/    /'
  # fall back to any android asset for this abi
  ALT=$(curl -fsSL "https://api.github.com/repos/frida/frida/releases/tags/${FRIDA_VERSION}" \
        | grep -o "https[^\"]*frida-server-[^\"]*android-${ABI}[^\"]*" | head -1)
  echo "  fallback URL: ${ALT:-<none>}"
  [ -n "${ALT:-}" ] && curl -fsSL "$ALT" -o fs.xz
fi
if [ -f fs.xz ]; then
  xz -d fs.xz || unxz fs.xz
  chmod +x fs
  echo "  frida-server binary ready: $(ls -l fs | awk '{print $5}') bytes"
else
  echo "  ERROR: could not download frida-server for ${ABI}"; exit 3
fi

echo "==================== 3. push + start frida-server ===================="
adb root || echo "  (adb root unavailable on a google_apis image — trying su)"
adb push fs /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
# start detached; on a non-root image this needs su
adb shell "su 0 /data/local/tmp/frida-server -D &" 2>/dev/null \
  || adb shell "/data/local/tmp/frida-server -D &" 2>/dev/null \
  || adb shell "nohup /data/local/tmp/frida-server >/data/local/tmp/fs.log 2>&1 &"
sleep 4
echo "  frida-ps over USB:"
frida-ps -U | head -20 | sed 's/^/    /'

echo "==================== 4. run the dynamic-lab scripts ===================="
# spawn mode is mandatory: JNI_OnLoad runs the signature check + Retrofit build.
python ci/frida_runner.py \
  --device usb \
  --package "$PKG" \
  --seconds "$SECONDS_TO_RUN" \
  --out frida_logs.txt \
  --scripts \
    dynamic-lab/00_common.js \
    dynamic-lab/01_anti_tamper_killer.js \
    dynamic-lab/02_ssl_pinning_bypass.js \
    dynamic-lab/03_instagram_api_intercept.js \
    dynamic-lab/04_credential_theft.js \
    dynamic-lab/05_coin_economy_bypass.js \
    dynamic-lab/06_task_verification_bypass.js \
    dynamic-lab/07_native_jni_dumper.js \
    dynamic-lab/08_backend_traffic_and_servercheck.js \
    dynamic-lab/09_native_aes_dump.js \
    dynamic-lab/10_java_crypto_layer.js
echo "  frida_runner exit=$?"

echo "==================== 5. pull the app sandbox (post-run dump) ===================="
mkdir -p ci/dump
adb shell "su 0 run-as $PKG ls -R /data/data/$PKG" > ci/dump/sandbox_listing.txt 2>&1 \
  || adb shell "run-as $PKG ls -R /data/data/$PKG" > ci/dump/sandbox_listing.txt 2>&1
for d in shared_prefs datastore databases files; do
  adb shell "su 0 run-as $PKG tar -c $d 2>/dev/null" > "ci/dump/$d.tar" 2>/dev/null || true
done
adb shell "su 0 cat /proc/$(adb shell pidof -s $PKG 2>/dev/null || echo 1)/maps" \
  > ci/dump/maps.txt 2>&1 || true
echo "  sandbox dump:"; ls -l ci/dump | sed 's/^/    /'

echo "==================== 6. which libtopfollow.so actually loaded ===================="
grep -i "libtopfollow" ci/dump/maps.txt 2>/dev/null | head -3 | sed 's/^/  /' \
  || echo "  (maps not captured — needs root)"

echo "==================== done ===================="
echo "  primary log: frida_logs.txt ($(wc -l < frida_logs.txt 2>/dev/null || echo 0) lines)"
