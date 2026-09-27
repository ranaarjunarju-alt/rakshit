# REPORT_libtopfollow.so — v846 (8.4.6) Deep Analysis

**Target:** `lib/arm64-v8a/libtopfollow.so` from TopFollow v846-Beta (8.4.6)
**Date:** 2026-09-27 · **Analyst:** Arena Agent Mode (static RE + Unicorn dynamic emulation)
**Branch:** `arena/01a0aa64-rakshit` · **Base:** commit `a5e59ff` (v846 APK)
**File size:** 1,101,352 bytes · ELF64 ARM aarch64 · **file offset == RVA** (single contiguous load)

---

## 1. Executive Summary

This report is the complete, offset-annotated analysis of the v846 native library. It is the
v846 successor to the v845 report (3,757 lines) and supersedes the v845 offset table —
**the v845 offset table is entirely stale for v846** (functions moved; only data blobs and the
AES tables are byte-identical).

### 1.1 What is PROVEN (Unicorn emulation, byte-exact)

| # | Claim | Proof |
|---|-------|-------|
| 1 | The AES engine is **genuine, unmodified FIPS-197** (AES-128/192/256) | All 6 FIPS-197 test vectors pass under emulation (enc+dec × 3 key sizes): key expansion R1 byte-matches standard schedules; block encrypt of `00112233…eeff` with key `000102…0f` = `69c4e0d86a7b0430d8cdb78070b4c55a`; 192/256 vectors `dda97ca4…` / `8ea2b7ca…` |
| 2 | Key-expansion function `0x31260` ABI = `(ctx, key, iv/aux, w3=keylen, w4=0x10)`; schedule stored at `ctx+0xc` **word-reversed** (each 4-byte word byte-reversed, ARM 32-bit LE); AES-192/256 second key half at `ctx+0x30` | Emulated 16B/24B/32B expansions (29,468 / — / 43,886 steps); R1 word-reverse == standard |
| 3 | Block cores: `0x2edf8` = encrypt, `0x2fdcc` = decrypt, both `(ctx, src16, dst16)`, output in standard byte order | FIPS vectors, both directions, all key sizes |
| 4 | Stream wrapper `0x33260 (ctx, in, out, x3, w4=mode)`: **mode 0 = ECB; mode 1 = custom "prefix-XOR-ECB"**: `CT_i = AES(PT_i ^ PT_1^…^PT_{i-1})`; mode 2 = variant with non-zero mask seed | 2- and 3-block emulation, XOR-mask solving with the verified core as oracle |
| 5 | Stream wrapper `0x33aa8 (ctx, in, out, x3, w4∈{0,1})`: **mode 0 = per-block ECB decrypt**; mode 1 identical on 16-aligned data (extra ~3.3k steps, unlocated final-block path) | Multi-block emulation |
| 6 | **No GCM, no CTR, no standard CBC in v846** (contradicts the v845 report's CBC/GCM claims) | Absence of GHASH constants/strings; CTR disproven by vector tests |
| 7 | `len % 16 != 0` ⇒ wrapper is a **no-op** (early exit, 209 steps for 20-byte input) | Emulated 20-byte call |
| 8 | Four key-derivation loops (MBA-obfuscated) inside crypto dispatcher `0x37cb8` produce **ASCII base64-ish key strings** from four rodata blobs | Disassembly + transform extraction (see §3.6) |
| 9 | `K1` (32B, from blob `0x16d1e` XOR `0x5A`) = `RHXYTAXzJOR1ZKY3RrVDJWc2NG7WlVSB`; standard-b64 decode → 24-byte binary `4475d84c05f324e47564a63746b543256736346ed6955481` | Static transform + decode |
| 10 | The "check.php" phone-home URL is `https://nivafollower` + `&topfollow_check.php` (two encoded chunks at `0x16ed0`/`0x16ef4`, decoded by `0x86684`) | Emulated decoder: 20B→`https://nivafollower`, 19B→`&topfollow_check.php` |
| 11 | Constructors `0x37550` (227 steps) + `0xcc4c8` (7,048 steps) populate **748 bytes of .bss** (dispatcher-registry function pointers) | Emulated constructor run + .bss delta |
| 12 | Manifest diff v845→v846 = **only the version line** (`0x34d/8.4.5` → `0x34e/8.4.6`) | axml dump (aapt2 attr layout verified) |

### 1.2 What remains OPEN (honest list)

| # | Item | Status |
|---|------|--------|
| O1 | Full end-to-end run of `0x37cb8` (type→key/mode mapping at runtime) | Blocked: the function's first call targets dispatcher `0x101cbc` whose callback table is filled by JNI_OnLoad/ART — needs a fake JNI-env harness (next step) |
| O2 | Mode-2 seed `M1 = 5db34a7a22a88b3935867cfc884ab119` derivation (probably IV-derived; IV was zero in tests) | Open |
| O3 | "Family-B" encoded strings (`0x17208/0x1721b/0x17227/0x17277/0x172ce` — used by Order/Retrofit natives) — decoder not yet identified (candidates `0x8907c`, `0x8b2a0`, `0x88efc` tried, ABI undetermined) | Open |
| O4 | Exact final class name used in Frida reflection detection (`cmUuZnJpZGEuc2VydmVy` decodes to `re.frida.server` under standard b64; custom-alpha decode differs) | Needs runtime FindClass trace |
| O5 | `0x33aa8` w4=1 extra-pass purpose (final-block/remainder handling on non-16-aligned or final-block semantics) | Open |

### 1.3 Why this matters for the Frida-agent build (#9)

* The agent's hook table must use the **v846 offsets in §7.2** (v845 table is invalid).
* All crypto is standard AES under the hood ⇒ **captured traffic can be decrypted offline**
  with the derived keys (§3.6) once the exact type→key mapping (O1) is captured live.
* The C2 endpoint string (`§3.9`) and the cert-pinning Retrofit builder natives (§4) are the
  cleanest traffic-observation points: hooking `0x776ec`/`0x7a3ac` (Retrofit builders) and
  `0x67d98` (response decrypt) yields URL + payload before/after encryption.

---

## 2. Methodology & Tooling

| Layer | Tool | Notes |
|-------|------|-------|
| Static disassembly | capstone (ARM64) | per-function disasm (a single giant linear sweep of .text **diverges** — 222,708 insns decoded for a 208,441-instruction region; always disassemble per function) |
| Dynamic emulation | Unicorn arm64 LE | harness: `work/v846/unicorn_v846.py` (image map, IRELATIVE resolution, 88 PLT→RETZERO shims, SP at 0x800000000000, test buffers 0x300000+) |
| Vector proof | FIPS-197 Appendix C test vectors | 6/6 pass; harness self-test: `python work/v846/unicorn_v846.py` → `3/3 passed` |
| ELF parsing | `work/v846/elf_dump.py` | sections, relocations, dynsym |
| AXML (manifest) | `work/v846/axml_dump.py` | aapt2 attr = 20B (dataType 1B @+15, data u32 @+16) |
| Call graph | 2,747 edges, 1,063 functions (`notes/v846_callgraph.json`, `notes/v846_fn_imports.json`) | bounded BFS for callers (hub `0x0e89fc` in-degree 1,956 — recursive DFS times out) |

**Emulation setup (reproducible):**
```python
from unicorn_v846 import setup, run, init_keyexp, block_enc, block_dec, stream_enc, stream_dec
uc = setup()                 # maps image, resolves 2,684 IRELATIVEs (addend == final pointer),
                             # shims all 88 GOT/PLT slots to RETZERO at 0x330000
init_keyexp(uc, bytes(range(16)))          # KEYEXP
ct = block_enc(uc, 0x334000, 0x335000)     # after mem_write of plaintext
```
Key harness facts: LOAD segments `(0,0,0x1064b0)`, `(0x1064b0,0x10a4b0,0x5fd8)`,
`(0x10c488,0x114488,0x68)`; guard-counter pair at `0x10ead0/0x10ead8` → `0x116704/0x11670c`;
`notes/v846_gotplt.json` keys are **decimal strings** (`int(k,10)`).

**capstone pitfalls hit (do not repeat):**
* `CsInsn.reg_name` is a **method**, not a property (comparing two bound methods never matches).
* Immediate operand type for ARM64 `add x0, x0, #imm` is **type 2** (ARM64_OP_IMM), not 5 —
  all ADRP+ADD xref scans must accept `op.type in (2,3,5)`.
* `bl` target parsing: `int(op_str.strip().lstrip('#'), 0)`.
* Unicorn `emu_start(begin, 0)` — `until=0` is a valid stop address.
* Step-limit hooks must `raise` a custom exception (hook-delete APIs unavailable in this build).

---

## 3. Binary Map

### 3.1 Sections / regions (file offset == RVA)

| Region | VA range | Size | Content |
|--------|----------|------|---------|
| `.rodata` | `0x11510 .. 0x2076b` | 58,923 B | AES tables, key blobs, DEX descriptors, encoded strings, b64 alphabets |
| `.text` | `0x2c734 .. 0x105f04` | 878,560 B | 1,063 functions |
| `.plt` / trampolines | `0x105f10 .. 0x1064b0` | ~1.4 KB | 88 import stubs (`0x105f40..0x105f80` = `__stack_chk_fail` cluster — **verifier PLTs, runtime-replaced**) |
| JNI method table | `0x10a4e8` | 22 × 16 B | `struct JNINativeMethod[22]` — zero in file, filled at load via IRELATIVE addends |
| IRELATIVE relocations | `0x10e0 .. 0x10f0` (2,684 × 24 B) | ~64 KB | `r_info==1027`; **addend IS the final pointer** (no resolver function in this build) |
| `.got.plt` | `0x1101b0 .. 0x110488` | 88 slots | import slots (shimmed in harness) |
| `.bss` | `0x1144f0 .. 0x117090` | 10,304 B | guard counters, dispatcher registry, flags |
| file end | `0x10ce28` | 1,101,352 B | |

### 3.2 `.rodata` anchor table

| Offset | Size | Content | Notes |
|--------|------|---------|-------|
| `0x11510` | 1,024 B | **Te0..Te3** (AES forward T-tables) | 8,960 B block byte-identical to v845 |
| `0x12510` | 256 B | **S-box** | |
| `0x12610` | 1,024 B | **Td0..Td3** (inverse T-tables) | |
| `0x13610` | 256 B | **Rcon / inverse S-box region** (RSbox) | |
| `0x13770` | — | Rcon constants | |
| `0x14ce4` | 120 B | **PIN blob** (120 B) | byte-identical to v845 |
| `0x1476c` | 40 B | binary 32 B + **`F3AES`** magic tail | `fdfbff0ea792b479…a3974633414553` |
| `0x14790..0x15ea0` | ~6 KB | **b64 cluster** (encoded payloads, incl. zlib-compressed installer data for `0x923c0`) | |
| `0x14a35` | — | `android/os/Build` | device fingerprint |
| `0x1480f` | — | `setup` | MyDatabase.setup |
| `0x15a63` | — | **`Frida`** (detection token cluster) | |
| `0x15c65` | 13 B | `U0dKR01FNW9OV3h3` | b64 → `SGJGME5oNWxw` (class name) |
| `0x15c73` | 3 B | `gem` | Frida-detected method name |
| `0x15c77` | 20 B | `cmUuZnJpZGEuc2VydmVy` | b64 → `re.frida.server` |
| `0x15c8a` | 20 B | `()Ljava/lang/Object;` | method descriptor |
| `0x15de2/4/7` | 1-3 B | `+`, `^`, `fbid_v2`… | JSON field cluster (IG model) |
| `0x15dc5` | 16 B | **`0123456789abcdef`** (plainkey16) | xref'd by mega-sigs `0x7c08c`/`0xbdb68` |
| `0x1680b` | 0 B (empty) | `""` | **default IV argument** (via `0xe930c` string→bytes at `0x38544`/`0x385cc`/`0x38610`) |
| `0x16d1e` | 32 B | key blob K1 src | `0812030e1b2203201015086b0011036908280c1e100d3968` + 8 more |
| `0x16d3e` | 43 B | = 19 B K19 src + 24 B K3 src | `82666e886a7ca192b6a495aac7b89da9c1d8d0` ‖ `856584987e7b7c8e8f9fbba2aeb89ecaedd7dfe7f8d00d04` |
| `0x16d51` | 24 B | key blob K3 src | (tail of `0x16d3e`) |
| `0x16d6a` | 49 B | K4 source A | `20 01 39 01 22 01 21 01 …` (0x20 + 0x01·i pattern) |
| `0x16d9a` | 49 B | K4 source B | `c8 00` × 24 + `36` (constant 0xC8 per pair) |
| `0x16e90` | 16 B | binary blob | native `0x3fdd8` |
| `0x16ed0` | 20 B | encoded → **`https://nivafollower`** | decoder `0x86684` |
| `0x16ef4` | 19 B | encoded → **`&topfollow_check.php`** | decoder `0x86684` |
| `0x16f07` | 28 B | **CRYPTO-C key material** | `90fefac8daddbe95f9b4174f557c4532f0c58ef5fdbeac9d85927148` |
| `0x16f21` | 64 B | **custom b64 alphabet** (NOT NUL-terminated) | `qHaAk?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345` |
| `0x16f6a` | — | `frida` token | |
| `0x16f93` | — | `su` token | |
| `0x17075` | — | **hook-token cluster** (9 tokens: art/method hooks) | |
| `0x17208/1721b/17227` | 25 B each | Family-B encoded strings (Order native) | decoder open (O3) |
| `0x17277` | 24 B | `770074m0x7044xaa`mx46cex` (mixed-hex Family-B) | native `0x73ca8` |
| `0x172ce` | 25 B | Family-B (Retrofit native) | |
| `0x176f0` | 32 B | charset-32 (b64url-ish) | |

### 3.3 `.bss` landmarks

| VA | Meaning |
|----|---------|
| `0x1144cb0` | global init flag (constructor `0x37550`) |
| `0x116704` / `0x11670c` | **global guard-counter pair** (loaded via IRELATIVE `0x10ead0`/`0x10ead8` in prologues) |
| `0x10eb30/0x10eb38` (resolved) | guard pair for `0x33aa8` |
| `0x10eb40/0x10eb48` (resolved) | guard pair for `0x34638` |
| `0x114518..0x114658+` | dispatcher-registry pointer table (748 B populated by constructors) |

### 3.4 Import summary (88 imports, key ones)

| Import | Used by (examples) | Role |
|--------|--------------------|------|
| `inflateInit2_` / `inflate` / `inflateEnd` | `0x923c0` (b64/zlib installer), native `0x5342c`, `0x67d98` | runtime payload decompression |
| `__open_2` / `access` / `close` / `__read_chk` | detection fns, `0xa994c`, `0x8c544`, natives 5/9/10/12/15/16/19/20 | root/path checks, file IO |
| `clock_gettime` (clock) | `0xa994c` | **anti-debug timing** |
| `atoi` | `0x5342c` (xposed native) | property parsing |
| `memset` | almost all natives | buffer zeroing |
| `malloc` / `memcmp` / `memchr` | `0x5342c`, `0x67d98` | payload handling |
| `__stack_chk_fail` | crypto cores/wrappers | stack canary (PLT cluster `0x105f40..0x105f80` = **verifier hooks, replaced at runtime**) |

---

## 4. Load-Time & Anti-Tamper Architecture

### 4.1 Relocation model

* **2,684 IRELATIVE** relocations at `0x10e0..0x10f0` (24 B each: `r_offset u64, r_info u64, r_addend i64`).
  For **this build the addend IS the final pointer** — no resolver function. 926 of them point
  into `.bss` (`0x1144f0..0x117090`); the rest into `.text`/`.plt`.
* The JNI method table at `0x10a4e8` (22 entries) is zero in the file; its pointers arrive as
  IRELATIVE addends (this is how the 22 natives are bound — see `notes/v846_jni_natives.json`).
* 88 PLT/GOT imports (`notes/v846_gotplt.json`, **decimal-string keys**).

### 4.2 Constructors

| Ctor | Steps (emulated) | Effect |
|------|------------------|--------|
| `0x37550` | 227 | sets `.bss` flag `0x1144cb0`; early registry seeds |
| `0xcc4c8` | 7,048 | resolves **748 bytes** of `.bss` (3-byte LE pointers into `.text`/`.plt` at `0x114518..` — the **dispatcher-registry**) |

Emulating both before calling higher-level functions is required to get past the first
guard gates in many functions (verified: `0x37cb8` still needs JNI state after ctors — O1).

### 4.3 Guard-counter MBA pattern (every protected function)

Prologue shape (example: `0x2c920`):
```asm
0x2c93c  adrp x7,  #0x10e000          ; IRELATIVE slot (per-fn guard pair, e.g. 0x10eac0/0x10eac8)
0x2c944  ldrb w27, [x0, #8]           ; read ctx flag (when applicable)
0x2c948  ldr  x7, [x7, #0xac0]        ; counter0 ptr
0x2c94c  ldr  x19, [x19, #0xac8]      ; counter1 ptr
0x2c950..  mov/movk  w8..w28, MBA constants   ; 10-12 obfuscated constants
0x2c9ec  b      #0x2ca40              ; dispatch loop
0x2c9f0  ldr  w27, [x7]               ; c0
0x2c9f8  mvn  w29, w10
0x2c9fc  ldr  w28, [x19]              ; c1
0x2ca00  add  w30, w27, w10
0x2ca04  add  w29, w29, w30
0x2ca08  mul  w27, w29, w27
0x2ca0c  eor  w29, w27, #0xfffffffe
0x2ca10  tst  w29, w27                ; (c0±k)^2 evenness predicate
0x2ca18  cmp  w28, #9 / #0xa          ; c1 range predicate
...cset/csel chain...
0x2ca38  cmp  w27, #0
0x2ca3c  csel w28, w20, w9, ne        ; pass/fail -> state value
```
* Predicate core: `((c0±K1)^2 XOR -2) & (c0±K1)^2` parity + `c1` compared to 9/10 — an MBA
  encoding of a simple counter-state check.
* **Fail state = infinite `b .` self-loop** (there are **146 `b .` traps** in the binary).
* Counter pairs are per-function slots in the IRELATIVE-resolved `.bss` (e.g. `0x33aa8` →
  `0x10eb30/0x10eb38`; `0x34638` → `0x10eb40/0x10eb48`); the global pair `0x116704/0x11670c`
  (via `0x10ead0/0x10ead8`) is used by the outermost prologues.
* In the harness the counters start at 0 — functions whose gate *accepts* the zero state run
  (KEYEXP, block cores, `0x33260`, `0x33aa8`); functions requiring the JNI-populated state
  spin (O1).

### 4.4 Trap inventory (146 `b .`)

| Location | Count | Context |
|----------|-------|---------|
| `0x67d98` (x0015e49c, response-decrypt native) | 10 | failure exits of decrypt/verify |
| `0x41518` (x00120b1e) | 5 | JSON-builder failure exits |
| `0xbdb68` (mega-sig) | 5 | integrity-check failures |
| crypto sentinels | — | `0x376fc`, `0x37bb0`, `0x38a50`, `0x39234`, `0x39358`, `0x39528`, `0x3a930` |

### 4.5 Central hub & dispatchers

* **`0x0e89fc`** — in-degree **1,956** (the single largest call target): the shared
  "post-process / guard-advance" hub. Never DFS-trace callers through it.
* **`0x101cbc` / `0x101d94`** — dispatcher-registry walkers (the .bss callback table from §4.2):
  ```asm
  0x101d18  bl  #0x1022ec            ; resolve callback fn ptr -> [x29-0x48]
  0x101d20  ldur x8, [x29, #-0x30]
  0x101d24  cbz  x8, #0x101d00       ; retry loop
  0x101d28  ldr  x2, [x19]
  0x101d30  mov  w0, #1
  0x101d34  mov  w1, #1              ; opcode 1 / 2 / 6 (8 = repeat)
  0x101d38  mov  x3, x19
  0x101d3c  blr  x8
  0x101d40  cmp  w0, #8              ; 8 => loop again
  0x101d44  b.eq #0x101d00
  0x101d48  cmp  w0, #6
  0x101d4c  b.ne #0x101d7c           ; else fail (w0=3)
  ```
  Callbacks are resolved through `0x1020f0/0x102198/0x1022dc/0x1022ec` which read the
  JNI/ART environment state populated at `JNI_OnLoad` time — **the reason full `0x37cb8`
  emulation needs a fake env** (O1).
* Abort path: `__stack_chk_fail`-family PLTs (`0x105f40..0x105f80`) — in the wild these are
  **runtime-replaced verifiers** (live code follows the call); in the harness they are shimmed
  to RETZERO.

### 4.6 JNI_OnLoad

`0x3f4d8` — registers the 22-entry table at `0x10a4e8`; populates env-dependent `.bss`
state (registry callbacks, counters). Not emulated (needs ART).

---

## 5. Crypto Subsystem (v846) — Full Analysis

### 5.1 Architecture overview

```
                    ┌────────────────────────────────────────────────────────────┐
   Java natives ──► │  0x37cb8  CRYPTO DISPATCHER  (x0=buffer, x1=type, [x8])    │
   (12 call sites)  │  types: 1 0x10d 0x27c 0x995 0xd9e 0xf33 0x16c8            │
                    │   ├─ key-derive loops (MBA) §5.6  → key strings on stack  │
                    │   ├─ bl 0x31260 KEYEXP (ctx=sp+0xc8, key, iv, keylen,0x10)│
                    │   ├─ bl 0x33260 ENC    (ctx, in, out, data, mode)         │
                    │   └─ bl 0x105f60 verifier (runtime-replaced PLT)          │
                    └────────────────────────────────────────────────────────────┘
   0x395d4 / 0x8c544 (CRYPTO B/D) ──► 0x33aa8 DEC (ctx, in, out, data, mode∈{0,1})
   0x87690 (CRYPTO C) ──► direct KEYEXP + ENC, key blob 0x16f07
```

### 5.2 AES engine — PROVEN FIPS-197

**Key expansion `0x31260`** — ABI `(x0=ctx, x1=key, x2=iv/aux, w3=keylen, w4=0x10)`.
Call sites: `0x3884c` (CRYPTO-A), `0x3a5fc`, `0x881c0`, `0x8d384`.

| Property | Value | Evidence |
|----------|-------|----------|
| ctx flag | `ctx+8 = 1` after expansion | memory dump post-emulation |
| round schedule | `ctx+0xc` onward, **word-reversed** (each 4-byte word byte-reversed) | R1 word-reversed == standard schedule for FIPS key and `0123…` key |
| AES-192/256 2nd half | `ctx+0x30` (word-reversed) | 24/32-byte key emulations |
| step counts | 16B→29,468; 32B→43,886 | Unicorn step counter |
| FIPS R1 (key 000102…0f) | `fd74aad6` (word-rev `d6aa74fd`) | byte-match |
| key `0123…ef` R1 | `c09a9e62` | byte-match |

**Block cores** (called with `(ctx, src16, dst16)`):

| Fn | Inner | Role | FIPS proof |
|----|-------|------|-----------|
| `0x2edf8` | `0x2ccbc` | **encrypt** | 128: `00112233…eeff`→`69c4e0d86a7b0430d8cdb78070b4c55a` ✔; 192: →`dda97ca4864cdfe06eaf70a0ec0d7191` ✔; 256: →`8ea2b7ca516745bfeafc49904b496089` ✔ |
| `0x2fdcc` | `0x2dbc0` | **decrypt** | inverse of the above, all 3 sizes ✔ (round-trips to plaintext) |

Output at `dst` is **standard byte order** (the word-reversal is only inside the ctx schedule).
In-buffer is left untouched. Both directions × 3 key sizes = **6/6 FIPS-197 vectors pass**.

**GCM/CTR/CBC: absent.** No `gcm`/`GCM`/GHASH constants in rodata; CTR disproven by
counter-vector tests; no standard CBC chaining found in either wrapper (v845's
"AES-128-CBC / AES-192-GCM" characterization does **not** hold for v846).

### 5.3 Stream wrapper `0x33260` — encrypt side

ABI `(x0=ctx, x1=in, x2=out, x3=data/nullable, w4=mode)`. Called at `0x38864` from
CRYPTO-A with `w4` set dynamically (MBA dispatch on the `type` argument).

**Gating:** `len % 16 != 0` → early exit no-op (20-byte input ⇒ 209 steps, no output).
Callers must pre-pad.

**Modes (all emulated, 2- and 3-block, FIPS-128 key `000102…0f`, IV=0):**

| mode | Behavior | Proof (PT1=`00112233…eeff`, PT2=`11223344…ff00`) |
|------|----------|---------------------------------------------------|
| 0 | **ECB** | out = `69c4e0d8…c55a` ‖ `0dbedd87…5e50` = AES(PT1)‖AES(PT2) |
| 1 | **prefix-XOR-ECB** (custom): `CT_i = AES(PT_i ^ PT_1^…^PT_{i-1})`, mask M₁=0 | block1 = `69c4e0d8…` (=AES(PT1)); dec(block2)=`11331177…11ff` = PT2^PT1 ✔; 3-block dec(block3) = PT3^(PT2^PT1) ✔ (verified `33005522…11ee`) |
| 2 | variant, `M1 = 5db34a7a22a88b3935867cfc884ab119` (non-zero seed; IV arg was 0 ⇒ seed is IV/nonce-derived — O2) | block1 = `c6b01904c3da3df5e7d62bd96d153686`; mask solve via verified core |

### 5.4 Stream wrapper `0x33aa8` — decrypt side

ABI `(x0=ctx, x1=in, x2=out, x3, w4∈{0,1})`; guard counters `0x10eb30/0x10eb38`.
Called from CRYPTO-B `0x395d4` (← Retrofit builder native `0x776ec` ⇒ **base-URL /
request decryption**) and CRYPTO-D `0x8c544` (← response path `0xa0308`, `0x40c44`, `0x41518`).

| mode | Behavior | Proof |
|------|----------|-------|
| 0 | **per-block ECB decrypt**, no chaining | 3-block: out_i = dec(in_i) exactly; e.g. in=PT → out1=`c32e824e…`, out2=`4b98df99…` = dec(PT2) |
| 1 | identical to 0 on 16-aligned data (extra ~3.3k steps; likely final-block/remainder path — O5) | 4-block A/B: outputs identical |

Note: feeding `0x33aa8` the output of `0x33260` mode 1 yields `PT_i^PT_1^…^PT_{i-1}`
(i.e., plain ECB decrypt of the prefix-XOR ciphertext) — the app's decrypt side for
mode-1 data must include a prefix-XOR recovery step at a higher level (or via the
w4=1 extra pass).

### 5.5 `0x34638` — guard-dispatched helper

`(x0=dst, x1=src)`: computes `strlen(src)` via PLT `0x105f70` then calls
`0xe8b30(dst, src, len)`. `0xe8b30` is a **single-byte classifier** (hash/bucket of the
string: `U0dKR01FNW9OV3h3`→0x1a, `cmUuZnJpZGEuc2VydmVy`→0x28, `gem`→0x06, K19→0x26;
hangs on strings containing bytes outside its domain).

### 5.6 Key derivation (MBA loops inside `0x37cb8`) — PROVEN transforms

All four loops emit bytes through `0xe90e8(dst, byte)`; `x20` = byte index.

| Key | Source blob(s) | Len | Transform (exact) | Loop | Derived ASCII | Decoded |
|-----|----------------|-----|-------------------|------|---------------|---------|
| **K1** (AES-256) | `0x16d1e` | 32 | `byte ^ 0x5A` — MBA: `(b & 0xFFD4) \| (0x2B & ~b)` then `^ 0x71` ≡ `b ^ 0x5A` | `0x38188..0x381ac` (0..0x1F) | `RHXYTAXzJOR1ZKY3RrVDJWc2NG7WlVSB` | std-b64 → **24 B** `4475d84c05f324e47564a63746b543256736346ed6955481` |
| **K3** (AES-192) | `0x16d51` | 24 | `byte − 7·i − 0x0B (mod 256)` | `0x38588..0x385a8` | `zSkxWMGRLUjJOR1VrUVWa2hX` | std-b64 → 18 B `cd293158c1912d48c9391d55ad45566b6857` |
| **K19** (19 B, salt/nonce) | `0x16d3e` (first 19) | 19 | `byte − 7·i − 0x0B (mod 256)` | `0x39268..0x39288` | `wTUhCNlVsZDRhR05FVG` | std-b64 → 14 B `c1352108d955b190d1851d391551` |
| **K4** (AES-192) | `0x16d6a` (even idx) − `0x16d9a` (even idx) | 24 | `A[2i] − B[2i] − 2·i (mod 256)`; B[2i]=0xC8 constant | `0x39430..0x39454` | `XoVSPgiNekmZ`^iR6Hg@Y15@` | contains 0x60/0x5E/0x40 — in **neither** standard nor custom b64 alpha ⇒ used **raw** as 24-byte key |

* The `0x5A` XOR on K1 is the same 0x5A constant the v845 report recorded for GCM
  nonces — a cross-version invariant.
* `0x16d51` is the **tail 24 B of the 43-B blob at `0x16d3e`** (first 19 B = K19 source).
* Key length reaches KEYEXP via `w25 ∈ {0x20=32, 0x18=24}` (set at `0x38550`/`0x385d8`)
  ⇒ **both AES-256 and AES-192 are live** in CRYPTO-A.
* IV default: `0x1680b` (empty string) → `0xe930c` (string→bytes) at `0x38544`/`0x385cc`/`0x38610`.
* Keys can also arrive **from Java** (jstring) via `0x37160` (jstring→bytes) at `0x38620` —
  i.e. per-call key override from the app layer.

### 5.7 CRYPTO-C `0x87690`

Direct `KEYEXP + ENC` (no 0x33260 wrapper), key material `0x16f07` (28 B raw binary:
`90fefac8 daddbe95 f9b4174f 557c4532 f0c58ef5 fdbeac9d 85927148`) plus DEX descriptor
`0x15451` (`com/nivaroid/topfollow/helper/a0` + `(Landroid/conte…`). Called by 8 natives
including the (S,S,S)String native `0x6084c`.

### 5.8 Other crypto-adjacent constants

| Offset | Item |
|--------|------|
| `0x1476c` | 40-B blob: 32 B binary + `F3AES` magic — custom-scheme tag ("F3AES") |
| `0x16f21` | custom b64 alphabet (64 B, not NUL-terminated): `qHaAk?ABC…xyz012345` — no ADRP/ADR xref found in `.text`; assumed copied to `.bss` at init (consistent with registry architecture) |
| `0x176f0` | 32-char charset (b64url-family) |
| `0x15dc5` | `0123456789abcdef` (plainkey16) — xref'd by mega-sigs `0x7c08c`/`0xbdb68` (v845 AES-128 key, still present) |
| `0x923c0` | b64/zlib **installer**: `(x0=size, x8=struct*)`, reads payload ptr `[x8+0x28]`; `0xc0`=192 B and `0x148`, `0x6e`, `0x1a` sizes seen at call sites |

### 5.9 C2 phone-home (decoded)

`0x86684(dst?, src, w1=len)` decodes the additive-encoded string family A:
* `0x16ed0` (20 B) → `https://nivafollower`
* `0x16ef4` (19 B) → `&topfollow_check.php`
* joined: **`https://nivafollower&topfollow_check.php`** — the "check.php" license/
  phone-home endpoint used by native `0x40048` (x0014e2e9). (Family-B strings at
  `0x17208/1721b/17227/17277/172ce` use a different, still-unidentified decoder — O3.)

### 5.10 Frida-detection reflection descriptors (rodata cluster `0x15c65..0x15ca1`)

| Off | String | Decode | Use |
|-----|--------|--------|-----|
| `0x15c65` | `U0dKR01FNW9OV3h3` | b64 → `SGJGME5oNWxw` | class name for reflection |
| `0x15c73` | `gem` | — | method name |
| `0x15c77` | `cmUuZnJpZGEuc2VydmVy` | b64 → `re.frida.server` | class name (Frida server) |
| `0x15c8a` | `()Ljava/lang/Object;` | — | method descriptor |

Flow: classify string via `0x34638`/`0xe8b30` → `FindClass`/`Get*MethodID` via the
dispatcher registry → probe `gem()` → detection result feeds guard state. (Final class
name at runtime — O4.)

---

## 6. JNI Natives — 22/22, Line-by-Line Structural Analysis

Registered by `JNI_OnLoad` at `0x3f4d8` via the table at `0x10a4e8` (22 entries;
Java side: class `com/nivaroid/topfollow/helper/q`, obfuscated names `x00…`).
Per-native data: `notes/v846_jni_natives.json`, `notes/v846_native_profile.json`,
`notes/v846_native_rodata.json`. Every native begins with the standard
guard-prologue (IRELATIVE counter pair) — omitted below.

| # | Name | Sig | Addr | Size | Insns | Traps | Key imports |
|---|------|-----|------|------|-------|-------|-------------|
| 0 | x0011a4c2 | `()J` | `0x3fdd8` | 0x270 | 156 | 0 | memset |
| 1 | x0014e2e9 | `()Ljava/lang/String;` | `0x40048` | 0x1ec | 123 | 0 | memset |
| 2 | x0016d3b9 | `()Ljava/lang/String;` | `0x40234` | 0x290 | 164 | 0 | memset |
| 3 | x0012d3e0 | `(S)String` | `0x404c4` | 0x780 | 480 | 0 | memset |
| 4 | x0011e28b | `(S)String` | `0x40c44` | 0x8d4 | 565 | 0 | memset |
| 5 | x00120b1e | `(JsonObject,S)V` | `0x41518` | 0x4558 | 4,438 | 0 | `__open_2`, memset |
| 6 | x0012e5a1 | `(JsonObject)V` | `0x45a70` | 0x9724 | 9,673 | 0 | memset |
| 7 | x00135e2a | `(JsonObject,InstagramAccount,S)V` | `0x4f194` | 0x3ee8 | 4,026 | 0 | memset |
| 8 | x00105e9b | `(S)String` | `0x5307c` | 0x3b0 | 236 | 0 | memset |
| 9 | x0015b1e9 | `(JsonObject,S,S)V` | `0x5342c` | 0x92bc | 9,391 | 0 | `__open_2`, `access`, `atoi`, `inflateEnd`, `malloc`, memset |
| 10 | x0015a3b7 | `(JsonObject,InstagramAccount,S)V` | `0x5c6e8` | 0x4164 | 4,185 | 0 | `__open_2`, memset |
| 11 | x0017b62c | `(S,S,S)String` | `0x6084c` | 0xcc4 | 817 | 0 | memset |
| 12 | x0011f42b | `()String` | `0x61510` | 0x2648 | 2,450 | 0 | `__open_2`, memset |
| 13 | x0012f5b7 | `()String` | `0x63b58` | 0xd30 | 844 | 0 | memset |
| 14 | x0014b4f3 | `(S)String` | `0x64888` | 0xab0 | 684 | 0 | memset |
| 15 | x0011f1a2 | `(Order)String` | `0x65338` | 0x2a60 | 2,712 | 0 | `__open_2`, memset |
| 16 | x0015e49c | `(Response,Order,S…)String` | `0x67d98` | 0xbd48 | 12,114 | **10** | `__open_2`, `inflateInit2_`, `memchr`, `memcmp`, memset |
| 17 | x0010e27f | `()String` | `0x73ae0` | 0x1c8 | 114 | 0 | memset |
| 18 | x00113f7a | `()String` | `0x73ca8` | 0x2a0 | 168 | 0 | memset |
| 19 | x0014c1f9 | `(Response)String` | `0x73f48` | 0x37a4 | 3,561 | 0 | `__open_2`, `close`, memset |
| 20 | x00126f7c | `(Z,S)Retrofit` | `0x776ec` | 0x2cc0 | 2,864 | 0 | `__open_2`, memset |
| 21 | x0018d3f7 | `(I)Retrofit` | `0x7a3ac` | 0x1ce0 | 1,848 | 0 | memset |

### 6.1 Per-native walkthroughs

**[0] x0011a4c2 `()J` @ `0x3fdd8` (156 insns)**
`bl 0xe89fc ×4` (guard/stub), **`bl 0x7c08c ×2`** (mega-sig A — the `plainkey16`
`0123456789abcdef` integrity block), `bl 0x36dfc` (registry), `0xe8ce8`, `0xe90e8`
(byte emit), `0x85a4c`, exit PLT pair. Returns a long (license/integrity token).
rodata: 16-B blob `0x16e90` (`b1ede1e0e0ece4b0e5ede3e5e6e6b4ec`).

**[1] x0014e2e9 `()String` @ `0x40048` — the "check.php" phone-home**
`0x40074: adrp x0,#0x16000; add x0,#0xed0` → encoded `https://nivafollower`;
`bl 0x86684` (family-A decoder); `0x402b4`-style second chunk `0x16ef4` →
`&topfollow_check.php`; `bl 0x37160` (bytes→jstring); `bl 0x86684`. **This native
constructs and returns the C2 endpoint URL** (or performs the check and returns status
text — the URL build is unambiguous from the string refs).

**[2] x0016d3b9 `()String` @ `0x40234`**
Same shape as [1] but **two `bl 0x86684` calls on `0x16ef4` (19 B, `w1=0x13`)** and
`0x37160 ×2` — returns the second half of the endpoint / a derived check token.

**[3] x0012d3e0 `(S)String` @ `0x404c4` (480 insns)**
`bl 0xe89fc ×25` (heavy guard traffic), `0x3f0a0 ×2` (string op), `0x88efc`, `0xe8b30`
(classifier), `0x8907c`, `0x38f60` (buffer prep), `0x8b2a0`, **`bl 0x87690`** —
**CRYPTO-C encrypt of the input string**. rodata: `0x16248` (`x4`).

**[4] x0011e28b `(S)String` @ `0x40c44` (565 insns)**
Mirror of [3] but **`bl 0x8c544`** (CRYPTO-D **decrypt**) — the decode counterpart.
rodata: `0x16248`.

**[5] x00120b1e `(JsonObject,S)V` @ `0x41518` (4,438 insns, 5 traps-cluster fn `0x41518×5`)**
The big request builder. Strings: `com/nivaroid/topfollow/helper/T` (`0x147ef`),
`addProperty` (`0x1673f`), `(Ljava/lang/String;Ljava/lang/String;)V` (`0x16c7d`),
`<init>` (`0x14fbd`), `o`/`x0`/`y` field tokens, empty `0x1680b`. Calls:
`0xe89fc ×91`, `0x3d0d4 ×10` (Gson JsonObject put), `0x91c00 ×6` (b64 decode),
`0x105f70 ×5` (strlen), `0x923c0 ×5` (zlib installer), `0x3b4d4 ×4`, `0x347b4 ×4`.
Builds the encrypted request JSON (adds properties, encodes fields).

**[6] x0012e5a1 `(JsonObject)V` @ `0x45a70` (9,673 insns)**
Largest request-side native. `0xe89fc ×339`, `0x3d0e0 ×40` (copy), `0x923c0 ×35`,
`0x91c00 ×35`, `0x38f60 ×26`, `0x347b4 ×11`, `0x92170 ×10`, `0xe8f10 ×9`.
Field tokens `-`,`#`,`x2`,`|`,`^`,`_`,`1`,`+`,`*`,`:` — IG request payload assembly.

**[7] x00135e2a `(JsonObject,InstagramAccount,S)V` @ `0x4f194` (4,026 insns)**
IG model → JSON: `pk` (`0x15a2d`), `fbid_v2` (`0x15df7`),
`interop_messaging_user_fbid` (`0x1517c`), `profile_pic_id` (`0x15b0b`),
`family_device_id` (`0x16077`), `follower_count` (`0x1624b`),
`following_count` (`0x1674b`); `0xb0d18 ×8` (model getters), `0xe9c0c ×7`.

**[8] x00105e9b `(S)String` @ `0x5307c` (236 insns)**
Small codec: `0x923c0 ×2`, `0x91c00 ×2`, `0xb0d18`, `0x92170`, `0x38f60`,
**`bl 0x37cb8` (CRYPTO-A)** with type set from its stack state, `0x37160`.
rodata: `0x15a0f`.

**[9] x0015b1e9 `(JsonObject,S,S)V` @ `0x5342c` (9,391 insns) — xposed-family native**
Imports `__open_2/access/atoi/inflateEnd/malloc` (detection + payload). Field tokens:
`setup`, `interop_messaging_user_fbid`, `family_device_id`, `pk`, `u_a`, `mid`,
`profile_pic_url`, `username`, `follower_count`. `0x91c00 ×28`, `0x38f60 ×21`,
`0x923c0 ×16`, `0xb0d18 ×14`, `0x92170 ×14`, `0x37160 ×10`.

**[10] x0015a3b7 `(JsonObject,InstagramAccount,S)V` @ `0x5c6e8` (4,185 insns)**
Second IG builder: `username`, `pk`, `order_id` (`0x161c2`), `fbid_v2`,
`interop_messaging_user_fbid`.

**[11] x0017b62c `(S,S,S)String` @ `0x6084c` (817 insns) — the 3-string codec**
`0x91c00 ×6` (b64 dec), `0x38f60 ×6`, `0x923c0 ×4`, `0x347b4 ×4`, `0xb0d18 ×3`,
`0xe895c ×3` (copy), `0x37160 ×2`. Reaches CRYPTO-C `0x87690` in the call stack.
This is the highest-level "encode 3 strings" API.

**[12] x0011f42b `()String` @ `0x61510` (2,450 insns)**
DB reader: `MyDatabase` (`0x164af` / `0x14ee…`), `currentInstagram` (`0x15f05`),
`media_count` (`0x14848`), `setup` (`0x1480f`); `0x91c00 ×4`, `0x38f60 ×4`,
`0x86474 ×3`, `0x923c0 ×3`.

**[13] x0012f5b7 `()String` @ `0x63b58` (844 insns) — device fingerprint**
`android/os/Build` (`0x14a35`) ×6, fields `MANUFACTURER` (`0x169f0`), `BRAND`
(`0x16815`), `MODEL` (`0x14e5f`), `BOARD` (`0x158f5`), `DEVICE` (`0x15e0c`),
`HARDWARE` (`0x163b1`) → builds the device-ID string.

**[14] x0014b4f3 `(S)String` @ `0x64888` (684 insns)**
`0x923c0 ×3`, `0x38f60 ×3`, `0x91c00 ×2`, `0x3d0e0 ×2`, `0x37160 ×2`, `0xb0d18`,
`0x347b4`; rodata `0x14ce2` (`_`).

**[15] x0011f1a2 `(Order)String` @ `0x65338` (2,712 insns) — order serializer**
Family-B strings `0x17208/0x1721b/0x17227` (×5 each); `pk`, `media_id` (`0x15e19`);
`0x3d0e0 ×14`, `0x38f60 ×9`, `0x86684 ×7` (family-A decode), `0x105f70 ×4` (strlen).

**[16] x0015e49c `(Response,Order,S…)String` @ `0x67d98` (12,114 insns, 48 KB, **10 traps**)**
The **response-decrypt native** — the single most important one for traffic capture:
`bytes`/`()L…/String;` → `Response.body().bytes()`; `url` (`0x1676c`), `sign`
(`0x14b2f`), `isSuccessful` (`0x1563f`), `()Z`; Family-B `0x17230`/`0x1721b`
(×5). Calls: `0x3d0e0 ×26`, `0x38f60 ×26`, `0x36dfc ×12`, `0x86684 ×12`,
`0x91c00 ×12`, `0xe8b30 ×11`, `0x86474 ×10`; imports `inflateInit2_`, `memchr`,
`memcmp` (decompress + verify payload) and `__open_2`.

**[17] x0010e27f `()String` @ `0x73ae0` (114 insns)**
Minimal: `0xc7ffc` (registry fn), `0x37160`. Returns a short token string.

**[18] x00113f7a `()String` @ `0x73ca8` (168 insns)**
Family-B `0x17277` (`770074m0x7044xaa`mx46cex` — mixed-hex encoding) → short token.

**[19] x0014c1f9 `(Response)String` @ `0x73f48` (3,561 insns) — post-response DB save**
`body` (`0x15e22`), `string` (`0x15a3f`), `MyDatabase` (`0x15ee0`), `setup`
(`0x1480f`), **`"hash_key"` (`0x16260`), `"nonce"` (`0x15edc`-adj `0x16260` cluster),
`"hash_type"` (`0x1681b`**) → after decrypting a response, stores the server's
hash_key/nonce/hash_type in the local DB (key-rotation material).
`0x37160 ×27` (heavy jstring traffic), `0x3b4d4 ×15`, `0xe8fe4 ×12`, `0x9346c ×4`.

**[20] x00126f7c `(Z,S)Retrofit` @ `0x776ec` (2,864 insns) — Retrofit/OkHttp builder + cert pin**
`OkHttpClient$Builder` (`0x163d3`), `certificatePinner` (`0x16099`),
`(Lokhttp3/CertificatePin…` (`0x15e3b`), `build` (`0x14a84`), `SECONDS`/`TimeUnit`
(`0x1640e`/`0x163f0`), read/write timeouts; Family-B `0x172ce`. **This is where the
signer-pin blob is applied** (v846 native pin — our build's byte-verified change
lives in this path's pin data). Calls CRYPTO-B `0x395d4` → `0x33aa8` for
base-URL decryption.

**[21] x0018d3f7 `(I)Retrofit` @ `0x7a3ac` (1,848 insns)**
Second Retrofit builder (index parameter): same `OkHttpClient$Builder`/`build`/
`readTimeout`/`writeTimeout`/`certificatePinner` set; `0x3d0e0 ×14`, `0x86474 ×6`,
`0x8c18c`, `0xc99a0`, `0xbd88c`, `0xc9b1c`.

### 6.2 Shared helper functions (called across natives)

| Addr | Role (evidence) |
|------|-----------------|
| `0xe89fc` | guard/stub — called 1–339× per native; 4-step no-op in harness (needs context args) |
| `0x37160` | jstring/bytes converter (JNI string interop) |
| `0x38f60` | buffer prep (stack frame setup for crypto) |
| `0x91c00` | b64 decode (custom-alpha family) |
| `0x923c0` | b64+zlib installer (`inflateInit2_`) — expands runtime payloads |
| `0x92170` | string op (hash/compare) |
| `0x3d0d4`/`0x3d0e0` | Gson `JsonObject.addProperty` / buffer copy |
| `0x86684` | **family-A string decoder** (proven: `https://nivafollower`, `&topfollow_check.php`) |
| `0x86474` | small codec |
| `0xb0d18` | model getter (InstagramAccount) |
| `0x7c08c`/`0xbdb68` | **mega-signature integrity blocks** (5 traps each; xref `plainkey16` `0x15dc5`) |
| `0x347b4` | multi-arg string combiner |
| `0x36dfc` | registry lookup |
| `0x8c18c`/`0xc99a0`/`0xbd88c`/`0xc9b1c`/`0xc8198` | Retrofit/OkHttp interop |
| `0xe8b30` | single-byte classifier (§5.5) |
| `0xe90e8` | byte emitter (key-derive loops) |
| `0x87690` | CRYPTO-C (§5.7) |
| `0x8c544`/`0x395d4` | CRYPTO-D / CRYPTO-B decrypt paths → `0x33aa8` |
| `0x37cb8` | CRYPTO-A dispatcher (§5.6) |

---

## 7. Detection Subsystem — Function by Function

All detection functions sit in `.text` `0x92000..0xc8000`; none call abort directly —
they feed guard state / trap loops (`b .`) and the hub `0x0e89fc`.

| Fn | Size (insns) | Purpose | Key evidence |
|----|--------------|---------|--------------|
| `0x923c0` | 246 | **b64 + zlib installer** | imports `inflate`; ADRP→`0x16f27` (inside custom-alpha region `0x16f21`); expands runtime payloads (sizes 0x1a/0x6e/0x148/0xc0 at call sites) |
| `0x92798` | 860 | **encoded-token check (frida family)** | rodata `0x16f65..0x16f84` (encoded `QENSVPBZ…`-class tokens); `0xe8ce8`/`0xe90e8` state ops |
| `0xa4054` | 1,104 | **Frida detection (maps + names + reflection)** | b64 strings: `L3Byb2Mvc2VsZi9tYXBz`→**`/proc/self/maps`** (`0x15a11`), `ZnJpZGE=`→**`frida`** (`0x15841`), `Z3VtLWpzLWxvb3A=`→**`gum-js-loop`** (`0x15de6`), `bGliZnJpZGEtZ2FkZ2V0`→**`libfrida-gadget`** (`0x16992`), `cmUuZnJpZGEuc2VydmVy`→**`re.frida.server`** (`0x15c7a`); classifier `0xe8b30 ×5` |
| `0xa994c` | 149 | **anti-debug timing** | imports `clock` (`clock_gettime` ×9 via `0x106060`); encoded path tokens `0x16f65..0x1701f` (`u)#).?7u…` family); verifier PLT `0x105f80` |
| `0xaf774` | 744 | **hook/integrity token scan** | binary token cluster `0x17075..0x170c2` (encoded; 8 sub-blobs of 8-13 B); `0x37160 ×5` |
| `0xb88d8` | 845 | **maps-line scanner (deleted libs)** | b64: `/proc/self/maps` (`0x15a11`), `bGliYXJ0LnNvIChk…`→**`libart.so (d…`** (`0x16770`), `bGliYy5zbyAoZGVsZXRlZCk=`→**`libc.so (deleted)`** (`0x16b64`), `cnd4cA==` (3-B token, `0x15f31`) |
| `0xc7c90` | 219 | **PIN verifier** | 2× rodata `0x14ce4` = the 120-B **PIN blob** (head = b64 `WkRnME5UVTVNV1V3…`); classifier + `0x35764` parse |
| `0x7c08c` | **9,840** | **mega-sig A: APK signature verification** | `signatures`, `[Landroid/content/…` (PackageInfo), `getPackageManager`, `getContext`, **`SHA-256`**, **`java/security/MessageDigest`**, `getInstance`, **`0123456789abcdef` (plainkey16 ×2)**; 5 `b .` traps; `0x3d0d4 ×37` |
| `0xbdb68` | **10,314** | **mega-sig B: APK signature verification (second stage)** | same string set + **plainkey16 ×4**; 5 `b .` traps |
| `0x5342c` | 9,391 | **xposed/root native (JNI #9)** | imports `__open_2/access/atoi/inflateEnd/malloc` — su-binary path probes + payload inflate |
| `0x39358` | 116 | **K4 sentinel** (CRYPTO-A w28==0x16c8) | refs K4 blobs `0x16d6a`/`0x16d9a`; derive-then-verify, fail → sentinel |

### 7.1 Detection flow (reconstructed)

```
JNI_OnLoad / first crypto call
   │
   ├─► 0x923c0 payload installer (b64 custom-alpha @0x16f21 → inflate → .bss code/data)
   │
   ├─► maps scan: 0xa4054 (frida/gum-js-loop/libfrida-gadget names in /proc/self/maps)
   │            0xb88d8 (libart.so/libc.so "(deleted)" entries — repack/injection)
   │
   ├─► timing:  0xa994c (clock_gettime deltas — ptrace/strace slowdown)
   │
   ├─► tokens: 0x92798, 0xaf774 (encoded token clusters @0x16f65/0x17075)
   │
   ├─► reflection probe (cluster 0x15c65): FindClass(b64"re.frida.server"…) + "gem()Ljava/lang/Object;"
   │
   ├─► root:    0x5342c (access/__open_2 on su paths)
   │
   ├─► PIN:     0xc7c90 (120-B blob @0x14ce4)
   │
   └─► APK sig: 0x7c08c / 0xbdb68 (getPackageInfo.signatures → SHA-256 → compare;
                 plainkey16 0123456789abcdef @0x15dc5 involved; 5 traps each)
        │
        └── fail ⇒ guard state ⇒ 146× `b .` trap loops / abort via verifier PLTs
```

### 7.2 v845→v846 detection changes (from string/cluster diff)

* IG detection layer count 3→2 (one probe removed).
* b64 alphabet changed (v845 alpha replaced by `qHaAk?…` @ `0x16f21`).
* graphql triple-b64 pipeline removed (v845-only strings absent).
* +733 text literals added overall in `.rodata`.

---

## 8. Data Flows, Flow Charts & Logic Maps

### 8.1 Master data flow (request path)

```
┌───────────────────────────  JVM / ART  ───────────────────────────┐
│  Activity / Retrofit call                                        │
│   │  Java string args (obfuscated helpers, class q.x00…)         │
│   ▼                                                              │
│  JNI native (table @0x10a4e8, reg. by JNI_OnLoad @0x3f4d8)       │
└───┼──────────────────────────────────────────────────────────────┘
    ▼
┌──────────────────────── .text 0x3f000..0x7d000 ───────────────────┐
│ request builders (natives #5..#11):                               │
│   Gson JsonObject.addProperty (0x3d0d4)                          │
│   field encode: 0x91c00 (b64) · 0x38f60 (buffer) · 0x923c0 (zlib)│
│   strings: 0x86684 (family-A decode) · 0x37160 (jstring↔bytes)   │
└───┼──────────────────────────────────────────────────────────────┘
    ▼
┌──────────────────────── CRYPTO-A @0x37cb8 ────────────────────────┐
│ (x0=buffer, x1=type∈{1,0x10d,0x27c,0x995,0xd9e,0xf33,0x16c8})    │
│  1. dispatcher-registry gate (0x101cbc; .bss callbacks)           │
│  2. key derive (MBA loops):                                       │
│       K1 = blob(0x16d1e)⁺⁰˙⁵ᴀ          → "RHXYTAXzJOR1ZKY3…"   │
│       K3 = blob(0x16d51)−7i−0x0B        → "zSkxWMGRLUjJOR1V…"   │
│       K19= blob(0x16d3e)−7i−0x0B        → "wTUhCNlVsZDRhR05FVG" │
│       K4 = A[2i]−B[2i]−2i               → "XoVSPgiNekmZ`^iR…"   │
│  3. KEYEXP 0x31260 (ctx=sp+0xc8, key, IV(0x1680b default), 18/20) │
│  4. ENC 0x33260 (in, out, data, mode∈{0,1,2})                     │
│        mode 0: ECB    mode 1: prefix-XOR-ECB    mode 2: seed-variant│
│  5. verifier (PLT 0x105f60, runtime-replaced)                     │
└───┼──────────────────────────────────────────────────────────────┘
    ▼  ciphertext (16-aligned)
┌────────────────── Retrofit/OkHttp (natives #20/#21) ──────────────┐
│ 0x776ec (Z,S)Retrofit : OkHttpClient.Builder                       │
│   ├─ CRYPTO-B 0x395d4 → 0x33aa8 (base-URL decrypt, mode 0/1)      │
│   ├─ certificatePinner (signer-pin blob — our build's change)     │
│   └─ readTimeout/writeTimeout (TimeUnit.SECONDS)                  │
│ 0x7a3ac (I)Retrofit  : index-parameterized second builder         │
└───┼───────────────────────────────────────────────────────────────┘
    ▼  HTTPS (pinned)
 C2: https://nivafollower&topfollow_check.php  (strings 0x16ed0+0x16ef4)
```

### 8.2 Response data flow

```
Retrofit Response
   │  .isSuccessful() .url() .body().bytes()
   ▼
native #16 x0015e49c @0x67d98 (12,114 insns, 10 traps)
   ├─ parse url/sign fields (0x1676c, 0x14b2f)
   ├─ CRYPTO-D 0x8c544 → 0x33aa8 (block decrypt; mode 0 = ECB-dec)
   ├─ 0x923c0 inflate (zlib payload, inflateInit2_)
   ├─ verify (memcmp/memchr) ── fail ─► 10× `b .` traps
   ▼
native #19 x0014c1f9 @0x73f48 (Response)String
   ├─ body().string()
   └─ MyDatabase.setup(): store "hash_key" (0x16260) · "nonce" · "hash_type" (0x1681b)
        (server-rotated key material for the next session)
   ▼
parsed JSON → Gson models (InstagramAccount: pk/fbid_v2/profile_pic_id/…)
```

### 8.3 Phone-home / license flow

```
native #1 x0014e2e9 @0x40048  ()String
   ├─ 0x86684(0x16ed0,20) → "https://nivafollower"
   ├─ 0x86684(0x16ef4,19) → "&topfollow_check.php"
   └─ 0x37160 → jstring returned to Java (endpoint / check result)
native #2 x0016d3b9 @0x40234 — second-half token (2× 0x86684 on 0x16ef4)
```

### 8.4 Crypto logic map (mode selection)

```
0x37cb8 (buf, type)
│
├─ type==0x16c8 ──► K4 derive (0x39430) ──► 0x39358 sentinel (verify K4)
│                                             └─ fail → trap path
│
├─ w28 dispatch (MBA switch on type):
│   0xf33  ─► (inflate-prepped buffer, 0x923c0 @0xc0/0x148/0x6e)
│   0x10d  ─► 0x38200 branch (K1-32 path, w25=0x20 → AES-256)
│   0x995  ─► K3-24 path (w25=0x18 → AES-192)
│   0x27c / 0xd9e / 1 ─► remaining variants
│
├─ KEYEXP 0x31260(ctx=sp+0xc8, key, iv=0x1680b|jstring, w3=24|32, w4=0x10)
│
├─ ENC 0x33260(ctx, in, out, data, w4=mode)
│     len%16!=0 → NO-OP (209 steps)
│     mode 0:  CT_i = AES(PT_i)
│     mode 1:  CT_i = AES(PT_i ^ PT_1^…^PT_{i-1})
│     mode 2:  CT_i = AES(PT_i ^ M_i), M_1 = 5db34a7a… (IV-derived; O2)
│
└─ verifier (0x105f60, PLT, runtime-replaced) → success / trap
```

### 8.5 Guard/MBA predicate logic map

```
prologue:
  c0 ← [IRELATIVE→bss slot0]          (e.g. global 0x116704 / per-fn pairs)
  c1 ← [IRELATIVE→bss slot1]
  p0 ← parity((c0±K)² ⊕ −2)  AND  ((c0±K)²)          ; MBA-encoded counter check
  p1 ← (c1 ≥ 9) XOR (c1 < 10)  family                  ; range predicate
  state = f(p0,p1)  (csel chain over 10-12 MBA constants)
  │
  ├─ state ∈ ACCEPT set → proceed (counters advanced on exit)
  └─ state  ACCEPT → jump into `b .` infinite loop   (146 sites)
```

### 8.6 Key-derivation logic map

```
rodata blobs                      MBA loop (byte i)                 output (ASCII)
─────────────                     ──────────────────                 ──────────────
0x16d1e [32B]  ── b⊕0x5A ─────────────────────────────►  "RHXYTAXzJOR1ZKY3RrVDJWc2NG7WlVSB"
0x16d51 [24B]  ── b−7i−0x0B ──────────────────────────►  "zSkxWMGRLUjJOR1VrUVWa2hX"
0x16d3e[0:19]  ── b−7i−0x0B ──────────────────────────►  "wTUhCNlVsZDRhR05FVG"
0x16d6a[2i]−0x16d9a[2i]−2i ───────────────────────────►  "XoVSPgiNekmZ`^iR6Hg@Y15@"
                                                                        │
                     std-b64 decode (custom alpha @0x16f21 for K4?)     │
                                                                        ▼
                 24B key 4475d84c05f324e47564a63746b543256736346ed6955481 (K1)
                 18B     cd293158c1912d48c9391d55ad45566b6857 (K3)
                 14B     c1352108d955b190d1851d391551 (K19)
                 24B raw (K4, not b64-decodable)
```

### 8.7 Anti-tamper state machine (global)

```
load: IRELATIVE resolve (2,684) → ctors 0x37550+0xcc4c8 → .bss registry (748B)
      │
      ▼
every protected fn: guard-pair check (pass ⇒ work, advance counters)
      │
      ├─ crypto work (KEYEXP/ENC/DEC, verified FIPS-197)
      ├─ detection probes (maps/timing/root/frida/PIN/APK-sig)
      │      fail ⇒ guard state corrupted
      ▼
next guard check ⇒ `b .` spin or abort via verifier PLT (0x105f40..0x105f80)
```

---

## 9. v845 → v846 Differences (byte-level)

| Item | v845 | v846 |
|------|------|------|
| `.so` size (arm64) | 1,805,400 B | **1,101,352 B** (−704 KB) |
| `classes.dex` | 3,881,636 B | 3,866,132 B |
| APK entries changed | — | 236/1,215 |
| manifest | version `0x34d` / 8.4.5 | `0x34e` / 8.4.6 — **only diff** (package/minSdk 0x18/targetSdk 0x23 identical) |
| AES tables (8,960 B @0x11510) | — | **byte-identical** |
| PIN blob (120 B @0x14ce4) | — | **byte-identical** |
| keys 16+32 B | — | **byte-identical** (plainkey16 @0x15dc5; K1 blob) |
| b64 alphabet | old alpha | **`qHaAk?…` @0x16f21** (changed) |
| graphql triple-b64 | present | **removed** |
| IG detection layers | 3 | **2** |
| text literals | — | +733 in rodata |
| crypto modes | AES-128-CBC (key 0123456789abcdef, IV 0) + AES-192-GCM (nonce ⊕0x5A) | **ECB / prefix-XOR-ECB / seed-variant; no GCM/CTR/CBC** (§5.3–5.4) |
| JNI offset table | v845 table | **entirely stale** — use §10 table |
| META-INF/services | `i4.*` | `hb.*` / `z3.*` |

**Implication:** the v845 agent offset table must not be reused. All v846 addresses in this
report are measured on the v846 binary (file offset == RVA; on device add the load base).

---

## 10. Agent (Frida) Hook Table — v846

For the embedded agent (gadget 17.18.0, script `tf_agent.js`, config `libgadget.config.so`).
Base: `Module.findBaseAddress('libtopfollow.so')`.

### 10.1 Traffic-capture hooks (priority 1)

| # | Addr | What | Notes |
|---|------|------|-------|
| H1 | `0x6084c` | `(S,S,S)String` codec (3-string encode API) | highest-level request encoding; 3 in-args, 1 out-string |
| H2 | `0x404c4` / `0x40c44` | string encode / decode (`0x87690` / `0x8c544` paths) | single-string codecs |
| H3 | `0x37cb8` | **CRYPTO-A dispatcher** `(buf, type)` | type ∈ {1,0x10d,0x27c,0x995,0xd9e,0xf33,0x16c8}; read x1 for routing |
| H4 | `0x33260` | **ENC wrapper** `(ctx, in, out, data, mode)` | capture in/out + mode (0/1/2); len%16 gating |
| H5 | `0x33aa8` | **DEC wrapper** `(ctx, in, out, data, mode)` | capture in/out + mode (0/1) |
| H6 | `0x2edf8` / `0x2fdcc` | block cores `(ctx, src, dst)` | fine-grain; ctx+0xc schedule (word-rev) readable for key recovery |
| H7 | `0x31260` | **KEYEXP** `(ctx, key, iv, keylen, 0x10)` | capture key bytes + keylen (24/32) + IV arg — **live key recovery** |
| H8 | `0x776ec` / `0x7a3ac` | Retrofit builders | base-URL decrypt path (CRYPTO-B `0x395d4`); cert-pinner construction |
| H9 | `0x67d98` | response-decrypt native | post-`Response` processing (12 KB fn; 10 traps) |
| H10 | `0x73f48` | post-response DB save | `hash_key`/`nonce`/`hash_type` strings — key-rotation capture |
| H11 | `0x40048` | check.php phone-home native | C2 endpoint construction |
| H12 | `0x10a4e8` (table) / `0x3f4d8` (JNI_OnLoad) | registration | trace all 22 natives at entry |

### 10.2 Detection bypass hooks (priority 2)

| # | Addr | Target | Bypass action |
|---|------|--------|---------------|
| B1 | `0xa4054` | Frida (maps names + reflection) | force ret 0 / spoof maps lines |
| B2 | `0xb88d8` | maps "(deleted)" scanner | force ret 0 |
| B3 | `0xa994c` | anti-debug timing (`clock`) | hook `clock_gettime` or force pass |
| B4 | `0x92798` / `0xaf774` | encoded-token checks | force pass |
| B5 | `0xc7c90` | PIN verifier (120-B @0x14ce4) | force pass |
| B6 | `0x7c08c` / `0xbdb68` | **APK SHA-256 signature verification** | critical: we re-signed ⇒ force accepted |
| B7 | `0x5342c` | root/xposed native (`access`/`__open_2`) | intercept file probes |
| B8 | `0x923c0` | b64+zlib installer | observe (don't break) |
| B9 | `0x39358` | K4 sentinel | observe |

### 10.3 Key material for offline decryption

| Key | Value | Source |
|-----|-------|--------|
| plainkey16 | `0123456789abcdef` | `0x15dc5` (v845 legacy, mega-sigs) |
| K1 (AES-256 candidate) | ASCII `RHXYTAXzJOR1ZKY3RrVDJWc2NG7WlVSB` → 24 B `4475d84c05f324e47564a63746b543256736346ed6955481` | §5.6 |
| K3 (AES-192 candidate) | ASCII `zSkxWMGRLUjJOR1VrUVWa2hX` → 18 B `cd293158c1912d48c9391d55ad45566b6857` | §5.6 |
| K19 (salt/nonce) | ASCII `wTUhCNlVsZDRhR05FVG` → 14 B `c1352108d955b190d1851d391551` | §5.6 |
| K4 (AES-192, raw) | `586f56535067694e656b6d5a605e69523648674059313540` | §5.6 |
| CRYPTO-C key | `90fefac8daddbe95f9b4174f557c4532f0c58ef5fdbeac9d85927148` (28 B) | `0x16f07` |
| IV default | `""` (empty) | `0x1680b` |
| custom b64 alpha | `qHaAk?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345` | `0x16f21` |

Offline decryption procedure: capture H7 (key+keylen) + H4/H5 (in/out+mode) live;
reproduce with `unicorn_v846.py` or pure-Python AES (engine is standard FIPS-197).

---

## 11. Open Items (tracked)

* **O1** — full `0x37cb8` emulation (fake JNI env harness) → type→(key,mode) runtime mapping.
* **O2** — mode-2 seed derivation (`5db34a7a22a88b3935867cfc884ab119` w/ zero IV).
* **O3** — Family-B string decoder (`0x17208/1721b/17227/17277/172ce`; candidates `0x8907c`/`0x8b2a0`/`0x88efc` — ABIs undetermined).
* **O4** — runtime final class name for Frida reflection probe.
* **O5** — `0x33aa8` w4=1 extra-pass semantics (final-block path).

---

## 12. Appendix A — Complete Offset Index

### 12.1 Code

| Offset | Item |
|--------|------|
| `0x3f4d8` | JNI_OnLoad |
| `0x3fdd8` | native #0 x0011a4c2 `()J` |
| `0x40048` | native #1 x0014e2e9 (check.php) |
| `0x40234` | native #2 x0016d3b9 |
| `0x404c4` | native #3 x0012d3e0 (enc, CRYPTO-C) |
| `0x40c44` | native #4 x0011e28b (dec, CRYPTO-D) |
| `0x41518` | native #5 x00120b1e (request builder) |
| `0x45a70` | native #6 x0012e5a1 |
| `0x4f194` | native #7 x00135e2a (IG model) |
| `0x5307c` | native #8 x00105e9b |
| `0x5342c` | native #9 x0015b1e9 (xposed/root) |
| `0x5c6e8` | native #10 x0015a3b7 |
| `0x6084c` | native #11 x0017b62c (S,S,S)String |
| `0x61510` | native #12 x0011f42b (DB) |
| `0x63b58` | native #13 x0012f5b7 (device fingerprint) |
| `0x64888` | native #14 x0014b4f3 |
| `0x65338` | native #15 x0011f1a2 (Order) |
| `0x67d98` | native #16 x0015e49c (response decrypt; 10 traps) |
| `0x73ae0` | native #17 x0010e27f |
| `0x73ca8` | native #18 x00113f7a |
| `0x73f48` | native #19 x0014c1f9 (hash_key/nonce DB) |
| `0x776ec` | native #20 x00126f7c (Retrofit+pin) |
| `0x7a3ac` | native #21 x0018d3f7 (Retrofit idx) |
| `0x31260` | KEYEXP (FIPS-197) |
| `0x2edf8` / `0x2ccbc` | block encrypt / inner |
| `0x2fdcc` / `0x2dbc0` | block decrypt / inner |
| `0x33260` | ENC stream wrapper (mode 0/1/2) |
| `0x33aa8` | DEC stream wrapper (mode 0/1) |
| `0x37cb8` | CRYPTO-A dispatcher (1,607 insns) |
| `0x395d4` | CRYPTO-B (→0x33aa8) |
| `0x87690` | CRYPTO-C (direct keyexp+enc) |
| `0x8c544` | CRYPTO-D (→0x33aa8) |
| `0x39358` | K4 sentinel |
| `0x2c920` | block-prep MBA fn (guard 0x10eac0/8) |
| `0x34638` | strlen+0xe8b30 dispatcher |
| `0xe8b30` | single-byte classifier |
| `0x86684` | family-A string decoder |
| `0x37160` | jstring↔bytes |
| `0x38f60` | buffer prep |
| `0x91c00` | b64 decode |
| `0x923c0` | b64+zlib installer |
| `0xe90e8` | byte emitter |
| `0xe89fc` | guard/stub (context-dependent) |
| `0x7c08c` / `0xbdb68` | mega-sigs (APK SHA-256 verify; 5 traps each) |
| `0x92798` | detection (frida family tokens) |
| `0xa4054` | detection (Frida maps+reflection) |
| `0xa994c` | detection (timing, clock) |
| `0xaf774` | detection (hook tokens) |
| `0xb88d8` | detection (deleted-lib maps scan) |
| `0xc7c90` | PIN verifier |
| `0x37550` / `0xcc4c8` | constructors (227 / 7,048 steps) |
| `0x0e89fc` | central hub (in-degree 1,956) |
| `0x101cbc` / `0x101d94` | dispatcher-registry walkers |
| `0x1020f0` / `0x102198` / `0x1022dc` / `0x1022ec` | registry resolver chain |
| `0x105f40..0x105f80` | verifier PLT cluster (runtime-replaced) |
| `0x105f70` | strlen PLT |

### 12.2 Data (rodata)

| Offset | Item |
|--------|------|
| `0x11510` | Te0-3 (1,024 B) |
| `0x12510` | S-box (256 B) |
| `0x12610` | Td0-3 (1,024 B) |
| `0x13610` | inverse tables region |
| `0x13770` | Rcon |
| `0x14ce4` | PIN blob (120 B; head b64 `WkRnME5UVTVNV1V3…`) |
| `0x1476c` | 40-B `F3AES` blob |
| `0x14a35` | `android/os/Build` |
| `0x15a63` | `Frida` |
| `0x15c65` / `0x15c73` / `0x15c77` / `0x15c8a` | Frida reflection descriptor cluster |
| `0x15dc5` | `0123456789abcdef` |
| `0x1680b` | `""` (default IV) |
| `0x16d1e` / `0x16d3e` / `0x16d51` / `0x16d6a` / `0x16d9a` | key blobs K1/K19+K3/K3/K4-A/K4-B |
| `0x16ed0` / `0x16ef4` | C2 URL halves (encoded) |
| `0x16f07` | CRYPTO-C key (28 B) |
| `0x16f21` | custom b64 alpha (64 B, not NUL-term) |
| `0x16f65..0x1701f` | encoded detection tokens (frida/su family) |
| `0x17075..0x170c2` | hook-token cluster (encoded) |
| `0x17208` / `0x1721b` / `0x17227` / `0x17277` / `0x172ce` | Family-B encoded strings |
| `0x176f0` | charset-32 |

### 12.3 BSS / relocations

| Offset | Item |
|--------|------|
| `0x1144cb0` | init flag |
| `0x116704` / `0x11670c` | global guard-counter pair |
| `0x10eb30` / `0x10eb38` | 0x33aa8 guard pair |
| `0x10eb40` / `0x10eb48` | 0x34638 guard pair |
| `0x114518+` | dispatcher-registry table (748 B, ctor-populated) |
| `0x10e0` | IRELATIVE relocations (2,684 × 24 B) |
| `0x10ead0` / `0x10ead8` | IRELATIVE slots → guard pair |
| `0x10a4e8` | JNI method table (22 × 16 B) |
| `0x1101b0..0x110488` | .got.plt (88 slots) |

### 12.4 Verified constants (hex)

```
FIPS-128  key 000102030405060708090a0b0c0d0e0f pt 00112233445566778899aabbccddeeff
          ct 69c4e0d86a7b0430d8cdb78070b4c55a
FIPS-192  key 000102…17 (24B)  ct dda97ca4864cdfe06eaf70a0ec0d7191
FIPS-256  key 000102…1f (32B)  ct 8ea2b7ca516745bfeafc49904b496089
K1 ASCII  RHXYTAXzJOR1ZKY3RrVDJWc2NG7WlVSB  → 4475d84c05f324e47564a63746b543256736346ed6955481
K3 ASCII  zSkxWMGRLUjJOR1VrUVWa2hX          → cd293158c1912d48c9391d55ad45566b6857
K19 ASCII wTUhCNlVsZDRhR05FVG               → c1352108d955b190d1851d391551
K4 raw    586f56535067694e656b6d5a605e69523648674059313540
CRYPTO-C  90fefac8daddbe95f9b4174f557c4532f0c58ef5fdbeac9d85927148
mode-2 seed 5db34a7a22a88b3935867cfc884ab119
C2        https://nivafollower&topfollow_check.php
```

---

## 13. Reproducibility

```
python work/v846/unicorn_v846.py            # self-test: 3/3 FIPS passed
# harness API:
from unicorn_v846 import setup, run, init_keyexp, block_enc, block_dec, stream_enc, stream_dec
```

* Notes: `work/v846/notes/` — `v846_jni_natives.json` (22), `v846_callgraph.json` (2,747 edges),
  `v846_gotplt.json` (88, decimal-string keys), `v846_fn_imports.json` (1,063),
  `v846_crypto_proven.json` (this round's proofs), `v846_native_profile.json`,
  `v846_native_rodata.json` (138 xrefs), `v846_rodata_xrefs.json`.
* Tools: `work/v846/elf_dump.py`, `axml_dump.py`, `unicorn_v846.py`.

*End of report — v846 libtopfollow.so, all offsets measured on the v846 binary.*
