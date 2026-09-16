# TopFollow v8.4.5-Beta — instrumented repack (no Frida, non-rooted)

**Artifact:** `TopFollow_v845-Beta_RE-logger.apk`
SHA-256 `786994bbb16cb146f5f0e992d3232246aa86ceacf3fed611820ea50054ca2480` (10,373,342 B)
Signed: APK Signature Scheme **v2**, RSA-2048 PKCS#1v1.5-SHA256, research cert
`CN=TopFollow RE Logger / OU=Security Research / O=RE / C=IN`
(cert SHA-256 `348f02d7d9bc76d2dcd76360085e37a67a5d1b84c8f810ca2f5dedcfcc62a774`)

> **Revision 2026-09-16 (dex dialect fix):** the first build's `classes2.dex` was
> rejected by the device runtime at class-load time — the dex magic was
> `dex\n035` while this app's runtime dialect requires `dex\n037` (the stock
> `classes.dex` in the app is `037`; the map list in this dialect uses
> 12-byte entries `[u32 type][u32 size][u32 off]`, proto items are 12 bytes,
> type-lists carry a u32 size, and 35C invokes list BOTH registers of a wide
> argument). The dex emitter was fixed (magic `037`; 12-byte map entries) and
> the pin blobs were re-patched for the regenerated research key pair, so the
> **signature changed again — uninstall the previous repack before installing**.
> All code/tables are otherwise byte-identical to the first build.

Built 100 % offline in pure Python (no Java/apktool/apksigner available in the
sandbox). Everything below is byte-level verified, nothing assumed.

## What changed vs. the stock APK

| Component | Change | Evidence |
|---|---|---|
| `AndroidManifest.xml` | +`WRITE_EXTERNAL_STORAGE` (maxSdk 29), +`READ_EXTERNAL_STORAGE` (maxSdk 32), +`MANAGE_EXTERNAL_STORAGE`, +`requestLegacyExternalStorage="true"`, +`<provider com.tf.lab.RTLogProvider>` (authorities `com.nivaroid.topfollow.rtlog`, exported=false) | androguard re-parse of edited binary AXML |
| `classes2.dex` (new) | `com.tf.lab.RTLog` + `RTLogProvider` + `RTLog$CrashH` — embedded runtime logger (hand-assembled Dalvik, 429 insns) | androguard full decode of every instruction |
| `lib/<abi>/libtopfollow.so` ×3 | pin-blob replaced with `Base64(Base64(hex(SHA-256(research cert))))` — arm64 @`0x15084`, x86 @`0x97e7`, x86_64 @`0x10319` | blob search before/after; cert fingerprint matches |
| ZIP layout | rebuilt; `.so` STORED + 16384-byte aligned (Android-15 16 KB pages), everything else same methods/order | per-entry offset audit |
| Signature | original v2 sig replaced by research v2 sig | `apksigtool verify` → `v2 verified` |

### Why the pin-blob patch is the complete native bypass

`REPORT_libtopfollow_so.md` §6.5/§6.6 (B-analysis, byte-verified): the native
signature check (func#226, reachable from the JNI hub #57) compares the
PackageManager-reported signer SHA-256 against the expected digest returned by
the blob getter (func#245) — the 120-byte Base64(Base64(hex)) string patched
here. The TLS CertificatePinner is built from **server-supplied** strings via
`q.k(String,Z)` (§6.6), not from `.rodata`, so no other native patch is needed
for the repack to run. No Magisk/ptrace/TracerPid/Frida-generic checks exist in
the binary (Phase-1 verdict), so nothing else blocks a plain install.

## What the logger does (from process start, no Frida, no root)

`RTLogProvider` is a ContentProvider: Android instantiates it **before
`Application.onCreate()`**, so logging starts the moment the app process boots.

1. **Sink resolution** — `/sdcard/runtime_logs.txt` if usable; on SDK ≥ 30
   without All-Files-Access it falls back to the app-specific external dir and
   auto-opens the *All files access* settings page once (one-tap grant).
   The resolved path is the first logged line.
2. **Boot dump** — model/manufacturer/fingerprint/SDK, pid, package
   name/version, **signer certificate** (proves the pin check will pass),
   dataDir/sourceDir, storage state.
3. **Background thread** — `TrafficStats` uid tx/rx every 5 s; every 60 s a
   listing of `databases/` and a read-only probe of the coin DB
   `t_f_d_b_f_v_c` (`SELECT * FROM t_f_d_b_f_v_c LIMIT 5`).
4. **Crash capture** — global `UncaughtExceptionHandler` writes
   `FATAL CRASH …` + stack trace, then chains to the previous handler.
5. Every log line: `MM-dd HH:mm:ss.SSS LEVEL tag: message`. File capped at
   25 MB. All logger paths are try/catch-all — the logger can never crash
   the host app.

## Install & run (non-rooted device)

```bash
adb uninstall com.nivaroid.topfollow        # signature changed — MUST uninstall first
adb install TopFollow_v845-Beta_RE-logger.apk
adb shell am start -n com.nivaroid.topfollow/<main activity>   # or tap the icon
```

* When the *All files access* settings page opens → enable it for TopFollow
  (one tap). Then restart the app; logs land in `/sdcard/runtime_logs.txt`.
* If you skip the grant, logs fall back to
  `/sdcard/Android/data/com.nivaroid.topfollow/files/runtime_logs.txt`
  (the fallback path is printed at boot).

```bash
adb pull /sdcard/runtime_logs.txt
# or watch live:
adb shell "run-as com.nivaroid.topfollow cat /sdcard/Android/data/com.nivaroid.topfollow/files/runtime_logs.txt"
```

## Reproducing the build

```bash
.venv/bin/python work/repack/build_logger.py work/repack/classes2.dex   # hand-assembled DEX
.venv/bin/python work/repack/axml_edit.py work/apk/AndroidManifest.xml work/repack/AndroidManifest_new.xml
.venv/bin/python work/repack/apk_build.py "TopFollow_v845-Beta (1).apk" work/repack/unsigned.apk
.venv/bin/python work/repack/v2sign.py work/repack/unsigned.apk work/repack/TopFollow_v845-Beta_RE-logger.apk
.venv/bin/apksigtool verify work/repack/TopFollow_v845-Beta_RE-logger.apk   # -> v2 verified
```

(`work/repack/lib/<abi>/libtopfollow.so` are the pin-patched natives; the key
pair is in `work/repack/keys/` — private key deliberately NOT committed.)

## Caveats / honesty box

* Bytecode was validated by full androguard decode + manual audit of all 22
  methods; **no emulator or device was available in this sandbox**, so the
  on-device run itself is untested. All failure paths in the logger are
  catch-all guarded, worst case the logger is silent.
* `/sdcard/runtime_logs.txt` on SDK ≥ 30 requires the All-Files-Access grant;
  before granting, expect the fallback path (logged at boot).
* DB probe is read-only; if Room holds the DB exclusively the probe logs
  `DB probe failed` and retries on the next minute tick.
