# Runtime analysis on a REAL device (arm64-v8a / x64)

This folder turns the 11 `dynamic-lab/` Frida scripts into **genuine runtime
logs** on a real rooted device — you run it against the device you actually have
(a rooted arm64-v8a phone, or an arm64/x64 Nox instance).

| File | Role |
|---|---|
| `frida_server.sh` | Downloads the frida-server that matches the **device's own ABI** (`ro.product.cpu.abi` → `arm64-v8a`, etc.), pushes it to `/data/local/tmp`, and starts it. Version is pinned to the host `frida` package. |
| `frida_runner.py` | Spawns `com.nivaroid.topfollow`, injects the scripts in order, routes every `send()`/`console.log()` to a log file. **Fails loudly (exit≠0) if no device is present — it never simulates output.** |

## Prerequisites

- A **rooted** Android device (arm64-v8a) or arm64/x64 Nox — the app's own
  signature self-check and root/Frida detection run inside `JNI_OnLoad`, so you
  need root to start frida-server and `01_anti_tamper_killer.js` to neutralise the
  checks at spawn time.
- `adb` on PATH and the device authorized (`adb devices` shows it).
- Host Python with **frida == the frida-server version** (this repo uses
  `17.18.0`): `pip install "frida==17.18.0" "frida-tools==14.10.4"`. A version
  mismatch makes the device reject the connection.

## Run

```bash
# 1. install the original signed APK (so the app's signature check passes)
adb install -g -r "TopFollow_v845-Beta (1).apk"

# 2. start a version-matched frida-server on the device
bash device/frida_server.sh 17.18.0

# 3. spawn the app under the scripts and capture for 60s
python device/frida_runner.py --device usb --seconds 60 --out frida_logs.txt \
    --scripts dynamic-lab/00_common.js \
              dynamic-lab/01_anti_tamper_killer.js \
              dynamic-lab/02_ssl_pinning_bypass.js \
              dynamic-lab/03_instagram_api_intercept.js \
              dynamic-lab/07_native_jni_dumper.js \
              dynamic-lab/09_native_aes_dump.js \
              dynamic-lab/10_java_crypto_layer.js
```

- Over TCP instead of USB (e.g. Nox / wireless): `adb forward tcp:27042 tcp:27042`
  then `--device 127.0.0.1:27042`.
- Add the remaining scripts (`04`–`06`, `08`) to `--scripts` for the full
  sweep; `00_common.js` must always be first. (Scripts 02–10 also self-arm a
  minimal anti-tamper/SSL bypass if loaded alone, but the full `01`+`02`
  baseline is always recommended.)

## What a successful run shows (real, not simulated)

In `frida_logs.txt`:
- the resolved `RegisterNatives` table for the 22 `helper.q` natives (`07`),
- the de-obfuscated XOR `0x55`/`0x5A` and base64 strings (`07`),
- live backend POSTs with headers/bodies and the ServerCheck pin/URL (`08`),
- the `q8.t1.f` password-blob dissection and `Cipher.init` raw keys (`10`),
- if the cipher is exercised during the run, the AES S-box location and any
  recoverable round-key schedule (`09`).

Whatever it prints is the truth **for the arm64-v8a build on that device** — this
is the path that settles the arm64-specific AES / block-cipher questions that a
static sandbox cannot.

## Honesty guardrails

- `frida_runner.py` exits non-zero with a `FATAL: no device` line if nothing is
  connected — it will not print fake `[STALKER]`/`[TEST]` output.
- frida-server is resolved from the release API for the device's real ABI rather
  than a guessed filename, and pinned to the host frida version.
- The APK installed is the **original signed build**, so the app's signature
  self-check passes; `01_anti_tamper_killer.js` handles maps/root/Frida checks.
