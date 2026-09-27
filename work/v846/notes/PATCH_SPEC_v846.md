# PATCH SPEC — TopFollow v846 `libtopfollow.so` (arm64-v8a)
### "Data-capture unblocker" binary patch — self-contained hand-off document
> Audience: another AI (or human) with no prior context. Everything needed is here.
> Target: **non-rooted** device (realme RMX3491, Android 13). Goal: app must keep working
> normally AND stop blocking traffic/data capture (Frida gadget, inline hooks, modified/re-signed APK).
> Hard constraint: **app must install cleanly and never crash** → every patch below only
> forces an *already-existing clean execution path*; no new code, no new state, no buffer-init skipped.

---

## 0. Premise correction (read first — changes what you patch)

| Assumption | Reality (evidence) |
|---|---|
| "App has SSL pinning" | **NO SSL PINNING EXISTS.** (a) `.so` dynamic imports contain **zero** TLS/network symbols (`readelf --dyn-syms`: only access, open, read, syscall, clock, abort, zlib inflate, ctype, pthread, syslog — no `SSL_*`/`connect`/`send`/`socket`/`getifaddrs`). (b) No static TLS inside the `.so` (no OpenSSL/BoringSSL strings). (c) The `.so` *does* contain OkHttp/CertificatePinner JNI strings, but an ADRP+ADD cross-reference scan of all of `.text` proves **zero references** to them → dead build residue. (d) DEX: the app package `com.nivaroid.*` never calls `CertificatePinner`, no `sha256/…` pin strings, no custom `TrustManager`/`X509` subclass. ⇒ TLS is stock HTTPS with default system-CA trust. |
| "App has VPN/proxy detection" | **NO VPN DETECTION EXISTS.** No `vpn/tun/route/fib/resolv` strings in the `.so` (all network-looking strings are XOR-obfuscated and none decode to route-check paths), no `ConnectivityManager`/`NetworkInfo`/`VpnService` usage in DEX, and the complete native detection map (Part 1) contains no route/interface check. The only dex hit for "VPN" is a Kotlin debug constant. |

**What actually blocks data capture on a non-rooted device** (the real patch targets):
1. **Frida/anti-debug detection** → hang/kill (blocks Frida-gadget capture)
2. **APK file SHA-256 re-verification** (2 flavors) → hang (blocks ANY modified/re-signed APK)
3. **Signer-pin blob verify** → hang (blocks re-signed APK — already handled by our pin-blob data rewrite)
4. **delmaps** (post-response maps-tamper detector) → catches runtime map rewriting
5. *(TLS note for MITM without Frida: Android 7+/targetSdk 35 apps do NOT trust user-installed CAs by default. Fix is an APK **resource** patch — add `network-security-config` with `<certificates src="user"/>` — not a binary patch.)*

---

## 1. The detection surface (what the .so checks, verified by disassembly)

| ID | Check | Function (VA) | Called from (VA) | When |
|---|---|---|---|---|
| R1 | Frida scan #1 (`/proc/self/maps` + frida/gadget/linjector/frida-agent tokens @0x92798 + `dl_iterate_phdr`) | `0xa4054` | `0x4c814` (fn x0012e5a1) | before every request |
| R2 | APK file SHA-256 re-verify (compare via `0x85a4c`) | `0x7c08c` | `0x4c87c` (fn x0012e5a1) | before every request |
| R3 | Frida scan #2 | `0xa4054` | `0x6498c` (fn x0014b4f3) | every string transform |
| R4 | delmaps (maps-integrity tamper) | `0xb88d8` | `0x711f4` | after every response |
| R5 | frida_tokens (24× `gum-js-loop` thread-name scan via `/proc/self/task/<tid>/comm`) | `0x92798` | `0x7276c` | after every response |
| R6 | APK SHA-256 variant #2 | `0xbdb68` | `0x72e14` | after every response |
| R7 | signer-pin blob verify (120B blob @`0x14ce4` = b64(b64(hex(sha256))) of original NivaRoid cert) | `0xc7c90` | `0x72e1c` | after every response |
| R8 | hooktokens + frida_tokens (internal) | `0xaf774`, `0x92798` | `0xa5368`, `0xa5370` | after response (internal) |
| R9 | Root: 9× `access(path, F_OK)` su checks + Xposed/LSposed/EdXposed/Riru/Zygisk maps scan | fn @`0xa8c80+` | payload/scan native | periodic |
| L3 | APK SHA-256 #1 (init, periodic re-verify loop) | `0x7c08c` | `0x3fe80`, `0x3fed4` (init native x0011a4c2) | app startup loop |

**Detection return convention (uniform):** detect-fn returns a word in `w0`; **bit0 = 1 ⇒ detected, bit0 = 0 ⇒ clean**.
The caller runs a counter "gate" (MBA-obfuscated, `A·(A−1)+B ∈ {9,10}` tautology — proven pass-through in earlier Unicorn emulation), then branches on that bit:
`tbz/tbnz wN, #0, <clean_or_trap>`. Detected path = generate decoy token via `0x923c0` + jump to hang/flag cluster.
**Failure behavior:** flag set → later `b .` self-loop hang (146 trap sites) or syslog+abort cluster.

Key helper: `0x85a4c` = string compare (bit0=1 ⇒ strings differ). `0x923c0` = runtime token generator (input is a decoy; output = f(len, clock)) — obfuscation, not the actual kill.

---

## 2. Patch strategy (why this is crash-safe)

**We do NOT patch the detection functions** (they may init buffers the caller later reads; and their MBA mazes hide flag-writes).
**We patch the caller's branch** that routes detected-vs-clean, replacing the conditional with an unconditional branch to the **verified clean target** (or NOP where the clean path is the fall-through). The detect-fn still executes fully, so every side effect/buffer-init happens exactly as in a normal clean run. The clean path is the path the app *already takes* on an unmodified clean device → zero new states → no crash.

---

## 3. THE PATCHES (12 code patches — verified byte-exact)

Input file: `libtopfollow.so` (arm64-v8a), **sha256 `2b2a9eeda016465adcdb0b18bf6c51ec9efa50effc14a664b93a7516cba5787b`**, 1,101,352 bytes.
Layout fact (assert before patching): **file offset == virtual address** (`.text` VA 0x2c734 = file off 0x2c734). All sites are inside `.text`.

| # | VA / file off | before (4 bytes LE) | before (asm) | after (4 bytes LE) | after (asm) | what it forces |
|---|---|---|---|---|---|---|
| 1 | `0x4c86c` | `36 00 c7 9c` | `tbz w28, #0, #0x4e15c` | `14 00 06 3c` | `b #0x4e15c` | R1 frida-scan #1 → clean |
| 2 | `0x4e11c` | `36 00 02 00` | `tbz w0, #0, #0x4e15c` | `14 00 00 10` | `b #0x4e15c` | R2 APK-SHA compare → clean |
| 3 | `0x64994` | `36 00 00 a0` | `tbz w0, #0, #0x649a8` | `14 00 00 05` | `b #0x649a8` | R3 frida-scan #2 → clean |
| 4 | `0x71268` | `37 00 0d 18` | `tbnz w24, #0, #0x71408` | `d5 03 20 1f` | `nop` | R4 delmaps → clean (fallthrough) |
| 5 | `0x72770` | `36 00 00 a0` | `tbz w0, #0, #0x72784` | `14 00 00 05` | `b #0x72784` | R5 frida_tokens → clean |
| 6 | `0x3ff98` | `36 00 02 15` | `tbz w21, #0, #0x3ffd8` | `14 00 00 10` | `b #0x3ffd8` | L3 APK-SHA init compare → clean (returns 0) |
| 7 | `0xa536c` | `37 00 00 60` | `tbnz w0, #0, #0xa5378` | `d5 03 20 1f` | `nop` | R8 hooktokens → clean (falls to next check) |
| 8 | `0xa5374` | `36 00 17 40` | `tbz w0, #0, #0xa565c` | `ba 00 00 14` | `b #0xa565c` | R8 frida_tokens → clean |
| 9 | `0x72f88` | `98 0b 00 36` | `tbz w24, #0, #0x730f8` | `5c 00 00 14` | `b #0x730f8` | **R6/R7 post-response verdict** (APK-SHA#2 compare result `w24` from `0x85a4c`; pin channel `x22` proven unused) → clean |
| 10 | `0x5f2f8` | `36 00 00 a0` | `tbz w0, #0, #0x5f30c` | `14 00 00 05` | `b #0x5f30c` | hooktokens, call site @`0x5f2f4` → clean |
| 11 | `0xa5ba4` | `36 07 be 60` | `tbz w0, #0, #0xa5370` | `f3 fd ff 17` | `b #0xa5370` (back-branch) | hooktokens, call site @`0xa5ba0` → clean |
| 12 | `0x44c60` | `36 00 00 a0` | `tbz w0, #0, #0x44c74` | `14 00 00 05` | `b #0x44c74` | frida_tokens, call site @`0x44c0c` → clean |

(Byte column = little-endian word bytes; manifest `v846_patch_manifest.json` stores the full 32-bit word in hex. Row 11 is a **backwards** branch — imm26 is signed two's-complement; the patcher's round-trip disassembly assert guarantees correctness.)

**Encoding rules (so you can recompute instead of trusting the table):**
- `b #tgt` from `pc`: `word = 0x14000000 | (((tgt - pc) / 4) & 0x3FFFFFF)`.
  ⚠ ARM64 stores **imm26 raw in bits [25:0]**; the decoder multiplies by 4. Do **not** shift imm26. (Common bug: `<<2` → lands 4× too far.)
- `NOP` = `0xD503201F` (LE bytes `1f 20 03 d5`).
- Verify by round-trip disassembly: encoded word at `pc` must disassemble to `b #tgt` exactly.

**Verification protocol (non-negotiable before shipping):**
1. Read the 4 original bytes at each VA; disassemble; must equal the "before (asm)" column exactly — else ABORT (file changed / wrong build).
2. Write new bytes; disassemble again; must equal "after (asm)" exactly (and for `b`: decoded target == intended target).
3. `diff` old vs new file: **only** the 12 patch sites may differ (48 bytes max; in practice 35 bytes because same-opclass edits touch fewer byte lanes).
4. `readelf -h` / `readelf -S` still parse; size unchanged (1,101,352 B).

**Deliverable of the patcher run** (already generated in this repo):
- Patched file: `work/v846/apkx/lib/arm64-v8a/libtopfollow_patched.so`
- sha256: `5d98fc764914312854e56133a14319c5c0457fe37cddae622f4293280cf99251`
- Manifest: `work/v846/notes/v846_patch_manifest.json` (per-site before/after hex + asm + label)
- Patcher: `work/v846/patch_topfollow.py` (pure Python + capstone; refuses to run if any "before" bytes don't match; writes output + manifest)

---

## 4. What the 12 code patches leave to the data layer (and how to finish it)

### 4a. R6 — APK-SHA variant #2 (`0xbdb68`, call @ `0x72e14`) — **CLOSED by patch #9**
The post-response function (x0015e49c) runs a **gate-controlled re-verify loop**: two `0x85a4c` string compares (computed-vs-expected, at `0x72efc` and `0x72f70`) repeat while the counter-gate says "keep going"; the first compare's verdict is held in `w24`. When the gate times out, flow lands on **`0x72f88: tbz w24, #0, #0x730f8`** — bit0=0 (strings equal) → `0x730f8` normal continuation; bit0=1 → trap block. **Patch #9 forces that branch to the clean target**, which also kills the R6+R7 verdict channel.
Proven unused side channel: the `0xc7c90` pin-verdict (call @`0x72e1c`) is parked in `x22` at `0x7324c: mov x22, x0` but is **overwritten at `0x73b08: mov w22, #0xdc27`** before any use (only a frame spill at `0x73af4` in between) — so no branch ever consumes it. (If you re-derive this on a different build, scan for `tbz/tbnz/cbz/cbnz` on the held verdict register *after* the gate ladder, and remember capstone `op_str` does NOT include the mnemonic.)

### 4b. Expected-digest data layer (why it exists)
The init loop (L3) decodes a **64-byte raw SHA-256 digest stored XOR-0x52 at file/VA `0x16e90..0x16edf`** (transform at `0x3ff24`: `(0x52 & ~byte) | (byte & 0xab)` = `byte ^ 0x52`, since 0x52 and 0xab are bit-complements). Decoded value today:
`e3bfb3b2 b2beb6e2 b7bfb1b7 b4b4e6be b7b4b2e1 e3b1e5b1 b1e4b4e4 b4e3b0b4 e6e6b4b4 e6e1beb7 b0beb3e3 b1e5bebfb1 e2b1b3b0 b0bee2e2 e6b1e5e2 e4b2e2`
It does **not** equal `sha256(v846_new.apk)` (`ac0b993e…`) nor of: APK minus signature block, APK up-to-EOCD, the `.so`, or `classes.dex` (all tested). The exact input span is undetermined.
Calibration recipe (only if you ever need the digest checks alive): on the first install (with Frida), hook `0x85a4c` (args x0=computed, x1=expected, both growable-strings); capture the expected string once; you'll see exactly what the app hashes. Then: `new_blob = (new_expected_64bytes XOR 0x52)` written at `0x16e90` (64 bytes) for your final APK bytes.
**With the full 12-patch set all three SHA-compare consumptions (#2, #6, #9) are code-disabled — the digest data layer is NOT needed for capture builds.** It's documented for completeness and for any build that must keep SHA integrity alive for other reasons.

### 4c. R7 — signer-pin blob (defense in depth: keep the data rewrite)
Blob @ `0x14ce4` (120 B) = `b64(b64(hex(sha256)))`-style hash chain of the **original NivaRoid signing cert** (cert DER extracted: `work/v846/notes/v846_orig_cert.der`). With patch #9, the verdict channel is dead, so a mismatch can no longer hang the app via that path. **Keep the pin-blob rewrite in the resign pipeline anyway** (byte-verified in builds #8/#9): `0xc7c90` still *runs* on every response, and we have only proven its return value is unused at this call site — the data rewrite makes the check itself pass, which is strictly safer.

### 4d. R9 — root/su + Xposed scan (leave as-is on non-rooted)
9 su checks call `access()` via PLT stub `0x106060` (GOT slot `0x110260`) at:
`0xa998c, 0xa99c4, 0xa99fc, 0xa9a34, 0xa9a6c, 0xa9aa4, 0xa9adc, 0xa9b14, 0xa9b4c`.
On a **non-rooted** device none of the 9 paths exist → checks pass naturally → **no patch needed**.
Optional hardening (e.g. if device gains Magisk later): replace each `bl #0x106060` with `mov w0, #-1` (word `0x52FFFF00`, LE `00 ff ff 52`) — `access` returning −1 (ENOENT) = "no su found" = clean. The Xposed part of R9 scans `/proc/self/maps` for xposed/lsposed/edxposed/riru/substrate/libbridge.so/zygisk (XOR-0x5a string cluster) — only fires if such framework is present.

### 4e. TLS for plain-MITM capture (no Frida) — **SOLVED, see `SSL_BYPASS_DEX_PATCH.md`**
No pinning to remove (proven: 0 `certificatePinner`/`sslSocketFactory`/`hostnameVerifier`/`proxy` calls at any of the 5 client-construction sites; no network-security-config; no VPN detection in native or Java). The single real TLS blocker = targetSdk-35 default policy not trusting user CAs (HTTPCanary's). Complete fix = **trust-all injection at `OkHttpClient$Builder.build()`** (3 new smali files + 2 injected lines, code-only, covers all 5 clients) or the network-security-config resource patch (fallback). That doc also explains the "IG captured but C2 not" observation: C2's base URL is native-provided (`helper.q.e()`) and the native kill-flag state (triggered by any APK modification via APK-SHA re-verify) suppresses the C2 path — the 12 .so patches are what fix that.

### 4f. The `b .` hang sites (146 of them) — deliberately NOT patched
They are only reached through the detection paths disabled above. Globally converting `b .` (word `0x14000000`) to `ret` is dangerous: some self-loops are legitimate counter-gate spins (`b #self` right before gate-exit ladders). Leave them; they're now unreachable on clean flow.

---

## 5. Step-by-step: how these patches were found (the method, to reproduce on any build)

1. **Extract** `lib/arm64-v8a/libtopfollow.so` from the APK (zip entry, no root needed: `unzip` or any zip tool).
2. **Imports first:** `readelf --dyn-syms libtopfollow.so | grep -E "SSL|connect|send|recv|socket|ioctl|getifaddrs"` → empty ⇒ no native TLS ⇒ no native SSL pinning possible. (Also kills the "VPN detection via network ioctl" hypothesis.)
3. **String sweep** of `.rodata` for tells: `okhttp3/CertificatePinner`, `certificatePinner`, `vpn`, `tun`, `route`, `/proc/`. Found OkHttp JNI strings — suspicious, keep.
4. **Cross-reference strings to code:** disassemble all of `.text` (capstone, ARM64 LE); for each string VA, scan for `adrp xN, #page` + next-insn `add xN, xN, #off` (and `adr`/pointer-table/relocation variants). Build the ref list. **If a string has zero references ⇒ dead residue.** (Scanner sanity check: it MUST find known-live refs like `/proc/self/maps` → 3 hits, alphabet @0x16f27 → 1 hit; if it finds those but not your target, the target is dead.)
5. **DEX side** (androguard): list classes of the app package; search bytecode for `CertificatePinner`, `TrustManager`, `sslSocketFactory`, `hostnameVerifier`, `ConnectivityManager`, `Vpn*`; search all dex strings for `sha256/` pins. Empty ⇒ Java layer doesn't pin and doesn't detect VPN.
6. **Disassemble the detection functions** (from the existing detection map, or find them fresh: they're the only fns that read `/proc/self/maps`, call `dl_iterate_phdr`, call `access()` 9×, or compare 64-byte digests). Note each one returns its verdict in `w0` bit0.
7. **Find every call site:** scan `.text` for `bl <fn>`. For each: disassemble ~40 insns after the `bl`; find where `w0` is consumed — either directly (`tbz/tbnz w0, #0, T`) or after `mov wN, w0` (`tbz/tbnz wN, #0, T`), often behind a counter-gate ladder (recognize the pattern: `sub w, w, #1; mul w, w, w; mvn; orr w, w, #0xfffffffe; cmn w, #1; cset…cmp #9/#10…`). The gate is a pass-through (proven by emulation) — ignore it, look at the branch **after** the gate.
8. **Determine direction:** `tbz wN,#0,T` ⇒ "bit zero (clean) → T"; `tbnz` ⇒ "bit one (detected) → T". Confirm which side is clean by reading the other side: the trap side runs `mov w0, #<len>; bl 0x923c0` (decoy token) and/or jumps to a flag-set/hang cluster.
9. **Write the patch:**
   - if clean side is a taken-branch (`tbz … → T_clean`): overwrite with `b T_clean`.
   - if clean side is the fall-through (`tbnz … → T_trap`): overwrite with `NOP`.
   - encode per §3 rules; round-trip verify by disassembly.
10. **Verify the whole file:** byte-diff (only patched words changed), `readelf` parses, size identical.
11. **Data layer:** rewrite pin blob `0x14ce4` for the new signer (existing pipeline formula); if 0xbdb68's compare isn't code-patched, compute its expected-digest rewrite (XOR-0x52 64-byte blob; calibrate input span via one runtime capture).
12. **Integrate into APK** (§6) → install → functional test: app opens, Instagram flow works, no freeze; then retest with capture active (Frida gadget / proxy) — app must stay alive and traffic visible.

---

## 6. APK integration (after the .so is patched)

1. Replace `lib/arm64-v8a/libtopfollow.so` inside the APK with the patched file (keep 4-byte zip alignment for uncompressed entries; `zipalign -p -f 4` semantics — our pure-Python writer already handles this).
2. **Resign** the APK (apksigner) with the working cert.
3. **Rewrite the pin blob** `0x14ce4` inside the *installed* .so (post-sign hash chain of the new cert) — existing pipeline step, byte-verified formula in builds #8/#9. (Order: sign first, then compute blob, then write the blob into the .so inside the APK before the final zip write. All three APK-SHA compare consumptions are code-disabled by patches #2/#6/#9, so no digest data-patch is required for this final form.)
4. `extractNativeLibs=true` stays (required for Frida-gadget coexistence, frida issue #3689).
5. Install on the non-rooted device; verify: clean launch, no freeze on first request, no syslog/abort.

## 7. Known follow-ups (ranked)
1. ~~R6 consume-branch~~ — **done (patch #9)**.
2. Runtime-calibrate the SHA input span (hook `0x85a4c`) only if a SHA check must stay alive for other purposes.
3. Optional su-access hardening (§4d) if the device gets rooted later.
4. network-security-config resource patch (§4e) if capture method is plain MITM instead of Frida.
5. On-device acceptance test of the 12-patch .so (clean launch, no freeze, capture alive) — static verification is complete; this is the one remaining gate before shipping a build.

## 8. Repo pointers (this workspace)
- Patcher: `work/v846/patch_topfollow.py` · Manifest: `work/v846/notes/v846_patch_manifest.json`
- Original .so: `work/v846/apkx/lib/arm64-v8a/libtopfollow.so` (sha256 2b2a9eed…)
- Patched .so: `work/v846/apkx/lib/arm64-v8a/libtopfollow_patched.so` (sha256 5d98fc764914312854e56133a14319c5c0457fe37cddae622f4293280cf99251)
- Detection-map source: `REPORT_v846_5x_DEEPEST.md` §6 · 100× evidence: `work/v846/notes/v846_100x_findings.json`
- Original signing cert: `work/v846/notes/v846_orig_cert.der`
