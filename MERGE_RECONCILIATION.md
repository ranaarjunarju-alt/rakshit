# MERGE RECONCILIATION — Analysis A × Analysis B × the binary

**Target:** `TopFollow_v845-Beta (1).apk` (SHA-256 `a60bcf06…98701a04`), `lib/arm64-v8a/libtopfollow.so`
(1,805,400 B, SHA-256 `675b9050…c23cfd`) · reconciled **2026-09-14** on branch `arena/01a09ff5-rakshit`.

**Inputs**

| | Analysis A (this repo's prior session) | Analysis B (independent) |
|---|---|---|
| Patch | `01a09b40-….patch` (carries nested `rakshit_full.patch`) | `01a0948a-… (4).patch` |
| Main docs | `TopFollow_Security_Analysis.html`, `README.md`, `THREAT_MODEL.md`, `detections_table.md`, `report/vulns_data.py` (73 findings), `unicorn_decrypted_strings.txt` | `REPORT_libtopfollow_so.md` (revision 7), `work/analysis/*` (models, KAT harness, `verify_all.txt`), `frida/*` |
| Method | static + Capstone + Unicorn (keyexp trace, round structure) | static + Capstone + Unicorn **executing** the cipher functions (known-answer tests) |

**Rule applied:** where A and B differ, the binary decides. Every row below was re-verified
in this session (2026-09-14) with LIEF/Capstone/Unicorn in `.venv` — not inherited from either
patch. Unicorn suites were **re-executed**: A's `work/unicorn_aes.py`, `unicorn_key_trace.py`,
`unicorn_round_structure.py`; B's `work/analysis/verify_all.py` (regenerated `verify_all.txt`, exit 0).

---

## 1. Inventory of claims

| Domain | Analysis A | Analysis B |
|---|---|---|
| `.so` size | 1,805,400 B (1.72 MiB) | 1,805,400 B |
| `.rodata` | AES tables at `0x128b0` / `0x139b0` / `0x13b10` | `0x0118b0–0x01ab5b`, 37,547 B; Te0..3/Td0..3 identified |
| AES functions | 5 table-referencing: `0x2dc00`, `0x2eb94`, `0x2fdcc` (enc), `0x30f18` (dec), `0x32158` (keyexp) | `func#14 @0x32158` (rijndael_setup), `#85 @0x10c470` / `#94 @0x110b70` (ECB enc/dec), `#30 @0x38fa4` (CBC), `#36 @0x3a838` (ECB-dec path) |
| Crypto primitives | native AES-256-shaped keyexp; Java AES-GCM + RSA-PKCS1; keyless glide.d cipher; no white-box | AES (LibTomCrypt), SHA-256, SHA-1, Base64 ×2 engines, XOR-0x5A strings, ECB/CBC/ECB-dec ciphers proven by KAT |
| Secrets | pin digest `d845591e…6bec5e`; URLs/sitekey/UUID under XOR-0x55 | literal key `0123456789abcdef`; AES-192 key + 2 GCM nonces (`0x17428/48/58`); 4 × 12-byte getters; pin blob encoding |
| Detections | maps scan, 9 su paths, base64 Frida markers, signature digest, installer gate | maps via `__open_2`+`read` (func#200/#225), anti-Frida (#99/#162), root (#169), sig pin (#226/#73), `clock()` (#98) |
| Endpoints | backend `top.nivafollower.app/v840/` (26 PHP endpoints), ServerCheck, IG api/v1 (XOR-0x55) | IG `api/v2` + `graphql/query` + `www.instagram.com` + `create_note/v2/` + `seen/` + `/save/` (nested b64) |
| JNI surface | 22 natives, none `([B)[B`, dead `digest([B)[B` bridge | 22 natives = `func#51..#72`, full slot→cipher→detection call map |
| Vulns | 73 registered (11C/25H/25M/12L) | 8 weaknesses in §8 + corrections log; no formal register |

## 2. DIFF table — where A and B differ, and what the binary says

| # | Claim | Analysis A | Analysis B | Binary evidence (re-verified 2026-09-14) | Verdict |
|---|---|---|---|---|---|
| 1 | `.so` size | 1,805,400 B | 1,805,400 B | `stat`: 1,805,400 B | **both right** |
| 2 | `.rodata` extent | tables in `0x128xx` region | `0x118b0–0x1ab5b` = 37,547 B | LIEF: `.rodata` va `0x118b0`, size **37,547** | **both right** (B gives extent; kills any 2 MB white-box-table claim) |
| 3 | AES S-box / inv / rcon | `0x128b0` / `0x139b0` / `0x13b10` | same + Te0 `0x118b0` … Td3 `0x135b0` | FIPS-197 S-box bytes @`0x128b0` ✓, inverse @`0x139b0` ✓, rcon @`0x13b10` ✓; B's T-tables regenerated bit-for-bit by re-run `verify_all.py` §11.8 | **both right**; B more complete |
| 4 | "`0x13b30` = 549-byte whitening table" | asserted (key derivation source) | `0x13b10`+256 B = LibTomCrypt **extended Rcon** (powers of 3) | bytes @`0x13b10` = `01 02 04 08 10 20 40 80 1b 36 6c d8 ab 4d 9a 2f…` = 3^i in GF(2⁸) ✓; `0x13b30` is offset +0x20 **inside** that table | **B right; A disproven** (the keyexp reads there are rcon reads — real reads, wrong interpretation) |
| 5 | key expansion | `0x32158`, AES-256-shaped, 14 rcon reads, period-14 | `func#14 @0x32158` = LibTomCrypt `rijndael_setup`, FIPS-197 schedules | re-run Unicorn: 89,148 insns, SBOX×112, RCON×14, 8 IPs × 14 reads ✓; B re-run §11.7: round keys at `ctx+0xc` stride 32 = FIPS-197 for keylen 16/24/32 (11/13/15 rows) | **both right**; same function, B proved the standard |
| 6 | where the key comes from | runtime-derived; RK0 `1742e227063cdfce2c2b4cbd71f1297a` absent from the whole file | standard setup expands the caller's key when driven through the cipher pipeline | re-run `unicorn_key_trace.py` verdict reproduced (RK0 not file-backed) ✓; B §11.7 reproduces verbatim-key expansion via `func#85` ✓ | **both right in scope**: direct-call harness derives an internal key; the `#85/#30/#36` pipelines feed literal/internal keys. No white-box table either way |
| 7 | block-cipher mode | **inconclusive statically** (enc/dec blocks early-exit or spin without exact ctx) | proven by execution: `#85`=AES-ECB+PKCS#7→hex, `#30`=AES-128-CBC key 0¹⁶/IV 0¹⁶, `#36`=AES-ECB-decrypt path | re-run B KATs: **27/27 exact** vs FIPS-197 ECB; zero-key CBC matches for every key argument on pt ≤ 220 B; ECB block-equality leak reproduced | **B right** (executed proof); A's "inconclusive" was honest for its direct-drive harness and is superseded |
| 8 | how `/proc/self/maps` is read | "bootstrap reads via `fopen`/`fgets`" (`detections_table.md`) | `__open_2` + `read`/`__read_chk`; **no** `fopen`, `fgets`, `strstr`, `stat` imported | LIEF import table: 88 unique imports — `fopen/fgets/strstr/stat/lstat` **absent**; `__open_2`, `read`, `__read_chk` present | **B right; A disproven** on this row (A's bypass still works: it also hooks `__open_2`/`read`) |
| 9 | Zygisk / LSPosed markers | **ABSENT** (`detections_table.md`, `unicorn_decrypted_strings.txt`) | present (anti-Xposed/LSPosed/EdXposed/Riru/Zygisk/Substrate) | XOR-0x5A decode @`0x174bd` = `zygisk` ✓, @`0x17485` = `lsposed` ✓; base64 layer `bGliZnJpZGEtZ2FkZ2V0`/`bHNwb3NlZA==` @`0x167a9`, `eWdzaWs=` ("ygsik") @`0x16f60` ✓ | **B right; A wrong** (A's own decode region contains both; they were dropped from its table) |
| 10 | the 9th su path | `/su/bin/su` | `/data/local/su` | ptr/len table @`.data.rel.ro 0x1b63a8` (relocations) → 9th entry ptr `0x1741a` len 14 → XOR-0x5A = `/data/local/su` ✓; `/su/bin/su` absent under raw/0x55/0x5A | **B right; A wrong on identity** (count = 9 was right) |
| 11 | Frida marker set | "a small base64 Frida marker set" | XOR-**0x37** blob `0x17365`: `gum-js-loop`+`libfrida-gadget`+`re.frida.server`; plus base64 `frida` @`0x15be1` | `0x17365 ^ 0x37` = `gum-js-looplibfrida-gadgetre.frida.server` ✓; base64 blobs verified ✓ | **both partly right**; merged superset (A's XOR-0x55/0x5A keyword lists + B's 0x37 blob) |
| 12 | Instagram API base | `https://i.instagram.com/api/v1/`, `https://b.i.instagram.com/api/v1/` (XOR-0x55) | `https://i.instagram.com/api/v2/`, `https://www.instagram.com/graphql/query` (nested b64) | **all exist**: XOR-0x55 @`0x1762c`/`0x17700` decode to the two v1 bases ✓; 4-layer b64 @`0x159ec` → `https://i.instagram.com/api/v2/` ✓; @`0x15de3` → `…/graphql/query` ✓; DEX also has `https://i.instagram.com/`, `https://b.i.instagram.com/`, `graphql/query` | **both right** — three IG bases coexist (Java v1 private-API + native v2/graphql fallback) |
| 13 | AES-GCM in native | "absent — no GHASH/H-table; GCM is Java-only" | "GCM proven native" (rev 4) → final: mode **inferred** from 24 B key + 12 B nonce + DEX `AES/GCM/NoPadding`, *not executed* | `func#191 @0x13ffb4` (the "GCM core"): 1,168 insns, **no `pmull`/`pmul`, no 0xE1 reduction constant, no `.rodata` table refs** → not GHASH; key/nonce install by `#157/#158` re-verified (B §11.6 re-run) | **merged**: GCM *context + key material* exists natively (proven); GCM *arithmetic* not present in the `.so` (A right); B's "proven native" wording overclaims and its own rev-7 text already retreats to "inferred" |
| 14 | SHA-1 | not claimed | present (`#199` update, `#201` round, `#202` pad) | re-disassembly of `func#199 @0x144d84`: exactly **4 × `lsl #5`** and **38 × `bic`** ✓ (SHA-1 `rotl5` fingerprint); IVs are blinded mov/movk consts (pair-probe inconclusive) | **B right (structural)** — no KAT executed; carried as "present, fingerprint-verified" |
| 15 | SHA-256 | used in signature compare | LibTomCrypt SHA-256 | K-table @`0x174c4` (`428a2f98 71374491…`) ✓, H IV @`0x17220` ✓ | **both right** |
| 16 | HMAC | silent | absent — `sign`/`digest` are hand-rolled SHA-256 concat | no ipad/opad construction found by B's sweep; field strings `hash_key`/`nonce`/`sign` present in `.rodata` ✓ | **B right** (absence claim) |
| 17 | dynamic imports | "no TLS stack, no crypto imports" | 92 imports (exec summary) vs "88-symbol import table" (§1.2) | 88 unique imported names; `.plt` = 1,440 B = 90 stubs; no TLS/crypto/net imports | **A right**; B internally inconsistent (92 ≠ 88) — resolved to **88 unique / 90 PLT stubs** |
| 18 | JNI native count | 22, none `([B)[B` | 22 = `func#51..#72` | independent relocation walk over `0x1b6198`: **22 entries**, fnPtrs identical to B's `jni_final.json`; no `([B)[B` signature in the table | **both right**, cross-validated |
| 19 | pin blob | signing-cert digest `d845591e…6bec5e`; doubles as tamper constant | @`0x15084`, **2 layers**: Base64(Base64(hex)), SHA-256 of the 864 B signer cert | decode chain @`0x15084` reproduced: b64 → b64 → hex `d845591e…6bec5e` ✓ | **both right**; B gives the encoding |
| 20 | hardcoded AES key | not claimed | `0123456789abcdef` @`0x161ca`/`0x17ae0`; all-zero AES-128-CBC (`#30`); AES-192 key `02df7523…` + nonces `58c544c1…`/`334544c1…` | all four byte-verified (plaintext search + XOR-0x5A decode + re-run KATs) | **B right — new findings merged into the register (CRYP-15…19)** |
| 21 | reCAPTCHA sitekey | `6Ld3yDspAAAAAH_yYoClNySU6O_dpbyXSXAujdQ` @`0x1764b` (XOR-0x55) | not claimed | XOR-0x55 decode @`0x1764b` ✓ (DEX uses hCaptcha SDK + `getSiteKey`) | **A right** |
| 22 | anti-replay UUID | `bbeeba8e-beaa-4458-ac60-6d9a61b2be9e` "×4" | not claimed | exactly **1** XOR-0x55 copy in arm64 `.rodata` @`0x17673`; none raw/0x5A; none in DEX | **A partly right** — value verified, multiplicity "×4" unproven (likely counts xrefs) |
| 23 | backend/ServerCheck | `https://top.nivafollower.app/v840/` @`0x176de`; `https://nivafollower-app.com/api-v3/topfollow_check.php` @`0x172d0` | not claimed | XOR-0x55 decodes ✓ | **A right** |
| 24 | function/instruction census | not claimed | 1,090 functions, 395,331 insns | from B's `model_arm64.json` (Capstone pass); not independently re-counted this session | **B carried** (tooling reproducible: `work/analysis/funcmap.py`) |
| 25 | `clock()` timing | not claimed (claims `clock_gettime` ABSENT — true) | `func#98` = `clock()`-based timing check | `clock` **is** imported (1 call site per B); `clock_gettime` absent ✓ | **B right; A's row stays true** (different symbol) — merged as new finding INTE-15 |
| 26 | Magisk/Shamiko/ptrace/TracerPid/property_get/SafetyNet-hardware | ABSENT | ABSENT | re-swept raw/XOR-0x55/XOR-0x5A + import table: all absent ✓ | **both right** |

## 3. Disproven claims (byte-level proof, kept so neither analysis' errors survive)

| Fabrication (from either side's inputs or earlier drafts) | Disproof |
|---|---|
| 2 MB white-box AES table at `.rodata:0x9A000` | `.rodata` is **37,547 B** total (`0x118b0–0x1ab5b`); `0x9A000` is inside `.gcc_except_table`/`.eh_frame`. No 2 MB region exists anywhere in the 1.72 MiB file |
| 18 MB `.so` | file is **1,805,400 B** |
| `sub_128A0` string-decryptor called 200+ times | `0x128A0` is **data**, 16 bytes before the S-box (`7b cb b0 b0 a8 fc 54 54 6d d6 bb bb 2c 3a 16 16`), inside `.rodata` — not code |
| 204 encrypted URLs | actual URL literal count is 7 native literals + 26 backend PHP paths in DEX (enumerated, all XOR/base64 one-to-four layers) |
| triple-layer PBKDF2 → white-box AES-GCM → RSA-OAEP | no PBKDF2/OAEP/white-box anywhere; real stack = keyless glide.d XOR cipher (local), AES-GCM + RSA-PKCS1 **Java** (`q8.t1`), LibTomCrypt AES-ECB/CBC **native** |
| HMAC-SHA512 / ChaCha / native GCM arithmetic | no `HmacSHA`/`sha512` strings; no `expand 32-byte k` / sigma words (both endiannesses swept); `func#191` has no carry-less multiply |
| ptrace / TracerPid / clock_gettime / SVC-hook anti-debug, Magisk/Zygisk/Shamiko *detectors* as classic suites | imports absent (`ptrace`, `prctl`, `clock_gettime`, `__system_property_get`); strings absent under raw/0x55/0x5A. (Note: `zygisk`/`lsposed` *marker strings* DO exist — row 9 — but there is no Magisk binary detector) |
| "Frida" string detection at `0x15e68` | the only ASCII match is **`Friday`** from the C++ locale weekday table (`strftime_l`) |
| A: maps read via `fopen`/`fgets` | row 8 — neither symbol is imported |
| A: 9th su path `/su/bin/su` | row 10 — actual 9th path `/data/local/su` |
| A: UUID "×4" | row 22 — one `.rodata` copy verified |

## 4. Merged result (what the unified analysis now states)

* **AES pipeline (native, LibTomCrypt):** Te/Td T-tables + S-box/inv/rcon verified byte-for-byte;
  `rijndael_setup @0x32158` is standard (FIPS-197 schedules for 128/192/256); three executed ciphers —
  ECB+PKCS#7→hex (`func#85/#94`, literal key `0123456789abcdef`), AES-128-CBC with **all-zero key+IV**
  (`func#30`, 7 of 22 JNI natives incl. the response handler), ECB-decrypt path (`func#36`, reachable
  as `q.k` slot 20 → padding-oracle shaped). A 5th pipeline (`0x2dc00`/`0x2eb94` wrappers around
  `0x2fdcc` enc / `0x30f18` dec with the runtime-derived key `RK0=1742e227…`) stays
  **mode-inconclusive on static evidence** — settle on device with `dynamic-lab/09_native_aes_dump.js`.
* **Detections (present, byte-proven):** maps scan via `__open_2`+`read` with tokens
  `/proc/self/maps`, `xposed`, `lsposed`, `edxposed`, `riru`, `substrate`, `libcso_substrate`,
  `libbridge.so`, `zygisk` (XOR-0x5A @`0x1746f` blob) + base64 layer (`frida`, `re.frida.server`,
  `gum-js-loop`, `libfrida-gadget`, `rwxp`, `libart.so (deleted)`, `libc.so (deleted)`, `xposed`,
  `lsposed`, `ygsik`); XOR-0x37 Frida blob @`0x17365`; 9 su paths (pointer table `0x1b63a8`);
  APK-signature digest compare (`d845591e…`); installer-package gate (Java); `clock()` timing (`func#98`).
  **Absent (proven):** Magisk/Zygisk/Shamiko *suites*, ptrace, TracerPid, property_get,
  clock_gettime, emulator props, SafetyNet/Play-Integrity hardware, SVC hooks, port 27042 probe.
* **Endpoints:** backend `https://top.nivafollower.app/v840/` (26 PHP endpoints in DEX) +
  ServerCheck `https://nivafollower-app.com/api-v3/topfollow_check.php`; IG `i.instagram.com/api/v1/`,
  `b.i.instagram.com/api/v1/` (Java private API) and `i.instagram.com/api/v2/`,
  `www.instagram.com/graphql/query`, `www.instagram.com` (native fallback); sitekey
  `6Ld3yDspAAAAAH_yYoClNySU6O_dpbyXSXAujdQ`; anti-replay UUID `bbeeba8e-beaa-4458-ac60-6d9a61b2be9e` (1 copy).
* **Vuln register:** A's 73 findings + 6 evidence-backed additions from B = **79** (14 Critical /
  26 High / 26 Medium / 13 Low) in `report/vulns_data.py`, de-duplicated; see §5.

## 5. Register deltas merged in from B (new IDs, all byte/KAT-verified)

| ID | Finding | Evidence |
|---|---|---|
| CRYP-15 (Critical) | literal AES key `0123456789abcdef` in plaintext `.rodata`, used by cert-pinner `#226/#73` and OkHttp builders `#71/#72` | `0x161ca`, `0x17ae0` |
| CRYP-16 (Critical) | `func#30` = AES-128-CBC with all-zero key + all-zero IV; key argument ignored; 7/22 JNI natives incl. response handler `q.p` | B §11.3 KAT re-run 2026-09-14 |
| CRYP-17 (Critical) | static AES-192 key `02df7523…` + two fixed 12-byte nonces `58c544c1…` / `334544c1…` (+ 12-byte getter family); fixed key + fixed nonce breaks GCM | `0x17428/48/58` XOR-0x5A+b64; B §11.1/§11.6 re-run |
| CRYP-18 (Medium) | `func#85` uses ECB — identical blocks ⇒ identical ciphertext (structure leak proven) | B §11.2 ECB-equality KAT |
| CRYP-19 (High) | `func#36` = AES-ECB decrypt + PKCS#7 unpad with internal key; padding-validity observable ⇒ padding-oracle shaped; reachable via `q.k` | B §11.4 re-run; JNI table slot 20 |
| INTE-15 (Low) | `clock()` timing check `func#98` reachable from 11 JNI natives (weak anti-debug, but real) | `clock` import; B §6.7 |

## 6. Open items (honest inconclusives, carried into the report)

1. Block mode of the runtime-key pipeline (`0x2fdcc`/`0x30f18` driven via ctx at `+0x438/+0x458`) — needs device (script 09).
2. Whether the native "GCM context" (`#157/#158`) is consumed by a Java `Cipher` or feeds `func#191`'s custom cipher end-to-end — device pass with script 10 + mitm capture.
3. B's func#199 SHA-1: fingerprint-verified, no KAT.

**Reproduce everything:** `.venv/bin/python work/unicorn_aes.py`, `work/unicorn_key_trace.py`,
`work/unicorn_round_structure.py`, `cd work && ../.venv/bin/python analysis/verify_all.py`,
`work/native_string_decrypt.py`. No device required; no Ghidra (Capstone-based substitute only,
as in `ghidra_pseudo.c`).
