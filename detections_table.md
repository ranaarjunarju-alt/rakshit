# DETECTIONS — claimed vs. actually present in `libtopfollow.so` (arm64-v8a)

Method: every claimed detection was searched for as raw bytes, XOR-0x55 and
XOR-0x5A, and as an imported symbol; the present ones were located in `.rodata`
and cross-referenced to the bootstrap function. "Bypass" is the Frida approach
that defeats each **real** detection — these are the hooks `01_anti_tamper_killer.js`
and `08_backend_traffic_and_servercheck.js` already implement. There is no device
in this workspace, so "Test result" is the **static verdict** (PRESENT/ABSENT),
not a fabricated live BYPASSED/BLOCKED badge.

## The prompt claims "20+ native detections". Reality: 4 families present, ~13 claimed ones absent.

| # | Claimed detection | Status | Where / evidence | Frida bypass (if present) |
|---|---|---|---|---|
| 1 | `/proc/self/maps` scan for hooks | **PRESENT** | keyword `/proc/self/maps` (XOR 0x5A); bootstrap reads the file and string-matches | hook `open/openat/fopen` → return a sanitized maps, or hook `fgets`/`strstr` to drop matches (`01_anti_tamper_killer.js`) |
| 2 | EdXposed marker | **PRESENT** | keyword `edxposed` (XOR 0x5A) in the maps-match list | same maps-sanitizing hook |
| 3 | Substrate marker | **PRESENT** | keyword `substrate` (XOR 0x5A) | same |
| 4 | Riru marker | **PRESENT** | keyword `riru` (XOR 0x5A) | same |
| 5 | `(deleted)` libart/libc mappings | **PRESENT** | maps-match keyword | same |
| 6 | `rwxp` regions | **PRESENT** | maps-match keyword | same |
| 7 | su binary probe (9 paths) | **PRESENT** | `/system/app/Superuser.apk`, `/sbin/su`, `/system/bin/su`, `/system/xbin/su`, `/data/local/xbin/su`, `/data/local/bin/su`, `/system/sd/xbin/su`, `/system/bin/failsafe/su`, `/su/bin/su` (XOR 0x5A) | hook `access/stat/fopen` on those paths → ENOENT (`01`) |
| 8 | Frida markers (base64 set) | **PRESENT (partial)** | a small base64-encoded Frida marker set in `.rodata`; note the literal ASCII `Frida` at `0x15e68` is **`Friday`** from the C++ locale weekday table (`strftime_l`), **not** a detection | hook the marker decode / the compare, or rename the frida thread + gadget (`01`) |
| 9 | APK signature self-check | **PRESENT** | bootstrap calls `getPackageInfo(...signatures)` → reflective `MessageDigest("SHA-256")` → compares to `d845591e…` (the signing-cert digest, which is also the TLS pin) | hook `MessageDigest.digest` / the comparison to return the expected constant (`01`) |
| 10 | Installer-package ("Play") gate | **PRESENT (Java)** | checks the installer package name; a software check, **not** hardware attestation | spoof `getInstallerPackageName` → `com.android.vending` (`01`) |
| — | Magisk | **ABSENT** | no bytes raw / XOR55 / XOR5A | n/a |
| — | Zygisk | **ABSENT** | no bytes | n/a |
| — | Shamiko | **ABSENT** | no bytes | n/a |
| — | LSPosed (as such) | **ABSENT** | only `riru`/`edxposed` markers exist, no `LSPosed` string | n/a |
| — | `ptrace` anti-debug | **ABSENT** | not imported, not a string | n/a |
| — | `TracerPid` (/proc/self/status) | **ABSENT** | no string, no status parse | n/a |
| — | `property_get` / `__system_property_get` (Nox/QEMU props) | **ABSENT** | not imported | n/a |
| — | Emulator props (goldfish/qemu/nox/genymotion/vbox/IMEI) | **ABSENT** | no such strings | n/a |
| — | `clock_gettime` Frida-overhead timing | **ABSENT** | not imported | n/a |
| — | `isDebuggerConnected` | **ABSENT** | no symbol/string | n/a |
| — | SafetyNet / Play Integrity **hardware** (StrongBox, DroidGuard VM) | **ABSENT** | no strings; there is no native hardware attestation at all | n/a |
| — | dex CRC tamper check (native) | **ABSENT** | no native CRC over classes.dex; the only integrity check is the APK-signature digest compare (#9) | n/a |
| — | inline-hook detection via SVC | **ABSENT** | no SVC-based hook-integrity check; `svc` not present | n/a |
| — | Frida default port 27042 | **ABSENT** | no such constant | n/a |
| — | VirtualApp / island / work-profile | **ABSENT** | no such strings | n/a |

## Why the anti-analysis is weak even where present

Every one of the present detections is **file-read + string-compare** executed by
calling back into Java (`open`, `getPackageInfo`, `MessageDigest`) or libc
(`fopen`/`fgets`/`access`). The library imports **no** `ptrace`, `prctl`,
`property_get`, `dlopen`, `clock_gettime` or syscall-number anti-debug primitive,
and contains **no** hardware attestation. That places the whole protection
surface on the Java/libc side of the JNI boundary, where Frida operates natively:
`01_anti_tamper_killer.js` defeats all of it without patching a single byte of
the `.so`. (Report findings INTE-14, INTE-01, CRYP-05.)

## Reproduce

```
.venv/bin/python work/native_string_decrypt.py     # -> work/out/43_native_decrypted_strings.{txt,json}
grep -a -o -E 'magisk|zygisk|shamiko|ptrace|TracerPid|clock_gettime' work/apk/lib/*/libtopfollow.so   # all empty
```
