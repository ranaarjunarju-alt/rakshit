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
| 1 | `/proc/self/maps` scan for hooks | **PRESENT** | keyword `/proc/self/maps` (XOR 0x5A @ `0x17470`, base64 @ `0x15db5`); the scanner reads the file via **`__open_2` + `read`/`__read_chk`** (the library imports no `fopen`/`fgets`/`strstr` — verified against the 88-entry import table) and string-matches with inlined byte loops | hook `open/openat/__open_2` → sanitized maps, and scrub the `read()` buffer (`01_anti_tamper_killer.js` does both) |
| 2 | EdXposed marker | **PRESENT** | keyword `edxposed` (XOR 0x5A) in the maps-match list | same maps-sanitizing hook |
| 3 | Substrate marker | **PRESENT** | keyword `substrate` (XOR 0x5A) | same |
| 4 | Riru marker | **PRESENT** | keyword `riru` (XOR 0x5A) | same |
| 5 | `(deleted)` libart/libc mappings | **PRESENT** | maps-match keyword | same |
| 6 | `rwxp` regions | **PRESENT** | maps-match keyword | same |
| 7 | su binary probe (9 paths) | **PRESENT** | `/system/app/Superuser.apk`, `/sbin/su`, `/system/bin/su`, `/system/xbin/su`, `/data/local/xbin/su`, `/data/local/bin/su`, `/system/sd/xbin/su`, `/system/bin/failsafe/su`, **`/data/local/su`** — all XOR 0x5A, reached through a (ptr,len) table in `.data.rel.ro @ 0x1b63a8` (9 relocations). *Corrected 2026-09-14: the 9th path is `/data/local/su` @ `0x1741a`, not `/su/bin/su` — that string exists under no encoding.* | hook `open/openat/__open_2/access/stat` on those paths → ENOENT (`01`) |
| 8 | Frida markers (XOR-0x37 blob + base64 set) | **PRESENT** | XOR-**0x37** packed blob @ `0x17365` = `gum-js-loop` + `libfrida-gadget` + `re.frida.server` (`func#99`); base64 layer `frida` @ `0x15be1`, `re.frida.server` @ `0x1607f`, `gum-js-loop` @ `0x161eb`, `libfrida-gadget` @ `0x16d97`. Note the literal ASCII `Frida` at `0x15e68` is **`Friday`** from the C++ locale weekday table (`strftime_l`), **not** a detection | hook the marker decode / the compare, scrub the maps read, or rename the frida thread + gadget (`01`) |
| 8b | Xposed-family markers incl. **LSPosed + Zygisk** | **PRESENT** | XOR-0x5A blob @ `0x1746f`: `xposed` (`0x1747f`), **`lsposed`** (`0x17485`), `edxposed` (`0x1748c`), `riru` (`0x17494`), `substrate` (`0x17498`), `libcso_substrate` (`0x174a1`), `libbridge.so` (`0x174b1`), **`zygisk`** (`0x174bd`); base64 copies incl. `lsposed` @ `0x167a9`, `ygsik` @ `0x16f60`, `rwxp` @ `0x16336`, `libart.so (deleted)` @ `0x16b75`, `libc.so (deleted)` @ `0x16f69`. *Corrected 2026-09-14: earlier table listed LSPosed/Zygisk as ABSENT — the markers are present (Analysis B was right); what is absent is any Magisk/Shamiko binary detector.* | same maps-sanitizing hook (`01`) |
| 9 | APK signature self-check | **PRESENT** | bootstrap calls `getPackageInfo(...signatures)` → reflective `MessageDigest("SHA-256")` → compares to `d845591e…` (the signing-cert digest, which is also the TLS pin) | hook `MessageDigest.digest` / the comparison to return the expected constant (`01`) |
| 10 | Installer-package ("Play") gate | **PRESENT (Java)** | checks the installer package name; a software check, **not** hardware attestation | spoof `getInstallerPackageName` → `com.android.vending` (`01`) |
| — | Magisk | **ABSENT** | no bytes raw / XOR55 / XOR5A | n/a |
| — | Zygisk *(detector suite)* | **MARKERS PRESENT** | the `zygisk` + `ygsik` map-scan markers exist (row 8b); there is no standalone Zygisk process/module detector beyond the maps scan | covered by the maps hook |
| — | Shamiko | **ABSENT** | no bytes | n/a |
| — | LSPosed | **MARKERS PRESENT** | `lsposed` maps-scan marker exists (row 8b); no LSPosed-specific syscall/ptrace detector | covered by the maps hook |
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
(`__open_2`/`read`/`__read_chk`/`access` — *not* `fopen`/`fgets`; those are not
imported at all). The library imports **no** `ptrace`, `prctl`,
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
