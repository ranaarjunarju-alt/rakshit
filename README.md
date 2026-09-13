# TopFollow v8.4.5-Beta — deep security analysis

Complete reverse-engineering of `com.nivaroid.topfollow`, an Instagram
follower-exchange manipulation app that advertises anti-tamper, anti-Frida,
SSL pinning and Play Integrity protection.

**Result: 63 vulnerabilities (11 Critical, 22 High, 21 Medium, 9 Low), 8 Frida
proof-of-concept scripts, every claimed protection located and defeated.**

---

## Read this first

👉 **[`TopFollow_Security_Analysis.html`](TopFollow_Security_Analysis.html)** —
a single self-contained 425 KiB HTML report. No external assets, no network
requests. Open it in any browser; use **Print → Save as PDF** for an offline
copy (print styles strip the interactive chrome and expand every code block).

It contains the threat model, the full architectural reconstruction, the
Instagram login flow, the private-API layer, the task-verification logic, the
coin economy, all 26 backend endpoints, all 22 native JNI functions, the
cryptographic analysis, the complete vulnerability register with evidence and
remediation, and the source of all 8 Frida scripts.

Interactive features: sticky table of contents with scroll-spy, a global
search across all 63 findings, per-severity and per-category filters, and
filterable data tables.

## Headline findings

| # | Finding | Why it matters |
|---|---------|----------------|
| 1 | **Instagram password stored on-device** (`instagram_accounts.u_w`) behind a *keyless* cipher | Full account takeover; the password, not just a session |
| 2 | **TOTP 2FA seed stored** (`two_factors.s_k`) | Permanently defeats two-factor authentication |
| 3 | **WebView cookie harvester** synthesises `Bearer IGT:2:<base64>` from `sessionid` + `ds_user_id` | Account takeover with no password at all |
| 4 | **Instagram session token sent to the vendor backend** in a plaintext `Token:` header | Mass account takeover by the operator, by design |
| 5 | **`get_coin="true"` is client-asserted** on `order/syncOrder.php` | Unbounded coin generation — the core fraud |
| 6 | **`order_value` (the payout) also comes from the client** | The attacker chooses the reward amount |
| 7 | **Backend base URL *and* certificate pin are downloaded at runtime** from ServerCheck | One MITM'd response redirects the whole fleet, credentials included |
| 8 | **`allowBackup=true` with completely empty exclusion rules** | The unencrypted credential DB lands in Google cloud backup |
| 9 | **The "pin" is the APK signing-certificate digest**, and doubles as the tamper-check constant | Pins nothing about the server's TLS key |
| 10 | **`libtopfollow.so` contains no crypto or TLS code** — pinning is executed via JNI in Java | One Frida hook on `CertificatePinner.check` defeats it |

## Repository layout

```
TopFollow_Security_Analysis.html     ← the deliverable: single-file HTML report
THREAT_MODEL.md                      ← standalone threat model (assets, actors,
                                        trust boundaries, attack trees)
dynamic-lab/                         ← 8 Frida PoC scripts + shared helper
  00_common.js                         helpers: class resolver, RegisterNatives
                                       capture, prefs dumper, overload tracer
  01_anti_tamper_killer.js             signature check, maps scan, anti-Frida,
                                       root paths, emulator, Phonesky, SND/RID
  02_ssl_pinning_bypass.js             OkHttp pinner + trust-all TrustManager
  03_instagram_api_intercept.js        all 3 IG Retrofits, headers, signed_body
  04_credential_theft.js               passwords, bearers, 2FA seeds, cookies
  05_coin_economy_bypass.js            wallet inflation + order rewriting
  06_task_verification_bypass.js       get_coin / order_value forgery
  07_native_jni_dumper.js              22 JNI fns + XOR/base64 string recovery
  08_backend_traffic_and_servercheck.js  all 26 endpoints + pin/URL hijack
report/
  build_report.py                    ← regenerates the HTML report
  vulns_data.py                      ← the 63-finding register (source of truth)
  cipher_poc.py                      ← Python re-implementation of glide.d.p()/q()
work/
  README.md                          ← the RE toolchain, stage by stage,
                                        including the dead ends and why
  *.py                               ← 20 analysis scripts (androguard, lief,
                                        capstone, raw DEX/ARSC/signing parsers)
  out/                               ← curated evidence files backing findings
```

## Quick start — dynamic analysis

Spawn mode is **required**: the signature self-check and the Retrofit
construction both run inside `JNI_OnLoad`, so attaching after start misses them.

```bash
# baseline: boot past every protection
frida -U -f com.nivaroid.topfollow \
      -l dynamic-lab/00_common.js \
      -l dynamic-lab/01_anti_tamper_killer.js \
      -l dynamic-lab/02_ssl_pinning_bypass.js

# add the layer you are investigating (03 … 08), or load all nine
```

Section 17 of the HTML report is a step-by-step reproduction guide, including
a no-device static recovery path (signing-block parse, XOR sweep, base64
endpoint decode) that only needs Python.

## Target fingerprint

| | |
|---|---|
| File | `TopFollow_v845-Beta (1).apk` — 10,379,650 bytes |
| SHA-256 | `a60bcf064d0907072712a16398968d2f50c6802fc0d56fb60139030a98701a04` |
| MD5 | `662029d6c75ea6afa195a7ad4805310c` |
| Package | `com.nivaroid.topfollow` — 8.4.5-Beta (versionCode 845) |
| SDK | minSdk 24 · targetSdk 35 |
| DEX | single `classes.dex`, 3,881,636 bytes, 4,146 classes, **scrambled `map_list`** |
| Native | `lib/{arm64-v8a,x86_64,x86}/libtopfollow.so` — sole export `JNI_OnLoad`, 22 `RegisterNatives` entries, OLLVM control-flow flattening |
| Backend | `https://top.nivafollower.app/v840/` (server-rotatable) |
| Signing cert | self-signed RSA-2048, `CN=Maryam Ahmadi, O=NivaRoid, L=Shiraz, ST=Fars, C=IR`, serial 1, 2023→2048, SHA-256 `d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e` |

## How the native hardening was broken

`libtopfollow.so` is OLLVM control-flow-flattened across all 22 JNI functions,
which makes static CFG tracing impractical. The **data** path is not flattened,
so that was attacked instead:

1. Detect every position-independent thunk of the form
   `call $+5; pop reg; add reg, K` — **943 found**.
2. Compute a **per-function** `.rodata` base from each thunk (a single global
   GOT base produces mis-aligned strings — this was the key correction).
3. Resolve `.rodata` references — **760 resolved**, attributing every secret
   string to the function that uses it. The bootstrap `x0018d3f7` alone
   resolves 622.
4. Run an exhaustive single-byte XOR sweep over keys 1–127 across every
   printable run. **Two keys crack everything**: `0x55` (backend URL, IG URLs,
   pin, UUID) and `0x5A` (anti-Frida keywords, root paths).

`report/cipher_poc.py` re-implements the Java-layer cipher
(`glide.d.p()` / `q()`): XOR `0x6C` → rotate-left 3 → reverse → XOR
`(i*37)^0xA5`. It is **keyless** and round-trips perfectly, which is why every
locally stored credential is recoverable offline.

## Scope & ethics

Defensive research on a single APK supplied for analysis. **No requests were
sent** to `top.nivafollower.app`, to any Instagram endpoint, or to any third
party. No real user data appears in this repository. The private-API detail is
documented because it *is* the vulnerability surface — not as a recipe. See
section 20 of the report for the full statement, including guidance for users
of the app (change your Instagram password and revoke sessions).
