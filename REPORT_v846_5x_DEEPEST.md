# libtopfollow.so (v846) — 5× DEEPEST COMPLETE ANALYSIS
**Commit base:** v846 APK → `extract/lib/arm64-v8a/libtopfollow.so` (1,101,352 B, sha256 `2b2a9eed…787b`)
**Branch:** `arena/01a0aa64-rakshit` · Date: 2026-09-27
**Method:** static RE (capstone), full machine-level scans, Unicorn instruction-level emulation (PLT→TZ shims, IRELATIVE resolved, guard counters), byte-exact blob decoders, symbol-pool string resolution. **No claim below is made without its evidence column.**

---

## 0. हिंदी में सारांश (Hindi summary — पुराने report में क्या सही/गलत था)

1. **`0x923c0` कोई "custom AES" नहीं है।** यह एक **general-purpose base64-style decoder** है (62-char alphabet `A-Z a-z 0-9` @ `0x16f27`)। हर output byte में `clock()` का salt मिलाता है — यही इसको "dynamic" बनाता है। **94 call sites** पूरे .text में हैं — हर जगह encoded strings decode करके यहीं से मिलती हैं (URLs, JSON fields, paths, tokens)। Output = C-string; fail होने पर `b .` self-loop (hang)।
2. **"AES" की सच्चाई:** binary में **गenuine FIPS-197 AES** है — key expansion `0x31260`, block encrypt `0x2edf8`, block decrypt `0x2fdcc`। Unicorn से **6/6 FIPS vectors pass** (128/192/256 enc+dec)। Schedule storage **word-reversed** है। Upstream = `mbedtls 3.x` (AES core + `md_wrap*`)। Wrapper `0x33260` modes: **0=ECB**, **1=PREFIX-XOR-ECB** (CT_i = AES(PT_i ⊕ PT_1⊕…PT_{i-1})), **2=seeded variant** (M1 seed = `5db34a7a22a88b3935867cfc884ab119`)।
3. **Detection load kab hota hai:** .so load करते ही **ctors** (registry @0x37550/0xcc4c8) चलते हैं → `JNI_OnLoad` (0x3f4d8, 158-slot ptr-cache) → Java side **`x0011a4c2()` init** call करता है — **यहीं APK SHA-256 compute होता है (app start पर)।**
4. **Detection run kab hota hai:** कोई thread/background scanner **नहीं** है। सारे checks **inline** हैं, हर API action से पहले/बाद:
   - हर request से पहले (x0012e5a1): **frida_scan + APK SHA re-check**
   - हर response के बाद (x0015e49c): **delmaps + frida_tokens + APK SHA-2 + pin_verify**
   - string transform हर call पर (x0014b4f3): **frida_scan**
   - XPOSED scan (x0015b1e9): `/proc/self/maps` में `xposed/lsposed/edxposed` + **9× access() su-binary check**
5. **Root check:** `access(path, F_OK)` × 9 पर **9 su paths** — 7/9 decode हुए: `/sbin/su, /system/bin/su, /system/xbin/su, /data/local/xbin/su, /data/local/bin/su, /system/sd/xbin/su, /data/local/su` (+2 और जो epoch-counter gate में फंसे)।
6. **Inflate (zlib) = DEAD CODE** — पूरे binary में 0 call sites (machine-level scan)। पहले report में "inflates base64" — **गलत** था।
7. **3 file readers** (`__open_2` @ 0x59a28/0x985fc/0xae720): path runtime-decoded C-strings (stack buffers), flags=O_RDONLY। Reader-1 (0x55000-0x5b000 module) = **/proc/self/maps reader + thread-name scanner** — 24× `gum-js-loop` (Frida JS thread name) references।
8. **JNI vtable offsets** इस binary में standard table से अलग हैं (ART-extended): `env[0x538]` = NewStringUTF-semantic, `env[0xf8]` = field/getter, `env[0xb8]` = method-call — हर native के सारे JNI calls offset+semantic के साथ नीचे document किए गए हैं।

---

## 1. EXECUTIVE SUMMARY (what changed vs previous reports)

| # | Previous claim | 5× finding | Evidence |
|---|----------------|-----------|----------|
| 1 | "0x923c0 = custom AES" | **general custom-B64 decoder**, 94 callers, clock() salted, `b.` hang on fail | Unicorn decode of 15/15 real call pairs; full disasm; machine BL scan |
| 2 | "inflate decodes base64" | **inflate trio = dead code, 0 callers in entire .text** | machine BL scan over 0x2c734..0x105f04 = 0 sites (scan validated: known targets hit correctly) |
| 3 | URL/header/response offsets (deep3 report) | **confirmed + refined**: all are custom-B64 encodings at known rodata addrs; `i.instagram.com/api/v2/` is the literal base (20B, `0x20` len) | byte dumps + emulation |
| 4 | "detection = 22 natives list" | **full lifecycle mapped**: load-time (ctors→JNI_OnLoad→init native w/ APK SHA) vs run-time (per-request frida_scan+SHA, per-response delmaps+tokens+SHA-2+pin) — all inline, zero threads | caller-map json + per-site native attribution |
| 5 | xposed native = 0x5342c | 0x5342c is the **xposed/root-scan + JSON builder** — contains b64'd `xposed`, `lsposed`, `edxposed` tokens + `/proc/self/maps` + 9×su access() calls | rodata strings 0x1680c/0x163a4/0x15dff/0x15a11 + call map |
| 6 | "147 .got slots" | .got 0x10eab0..0x10f3a0 = **IRELATIVE-final global data / counter page** (147 QWORDs); PLT stubs at 0x105f04..0x106558 resolve to it (0x105f0c→0x10ee90 etc.) | ELF parse + stub disasm |
| 7 | 22 natives = "opaque" | **every native's exact logic**: args, JNI call sequence, rodata (field names), internal fn calls, flags, return construction — §4 | per-native semantic extraction (v846_22native_semantics.json) |
| 8 | AES "custom" | **FIPS-197 AES, proven 6/6** (128/192/256 enc+dec); mbedtls lineage; word-reversed schedule; wrappers ECB / prefix-xor-ECB / seeded | Unicorn vectors |

---

## 2. BINARY MAP (verified)

```
.size 1,101,352 B   sha256 2b2a9eed…787b   file offset == RVA (no LOAD shift)
.text        0x002c734..0x0105f04  (   891,492 B; 80,796 insns BTI-audited)
PLT stubs    0x0105f04..0x0106558  (86 stubs → .got slots; e.g. 0x105f0c→0x10ee90=memcpy-final)
.rodata      0x011510..0x014d54    (static encodings)
rodata-ext   0x014d54..0x02076b    (symbol pool: 5,591 printable strings, 86% C++ mangled)
data/ro      0x014ce4 (PIN blob 120B b64(b64(hex(sha256)))); 0x16f07 (CRYPTO-C key 28B);
             0x16f27 (62-char alphabet A-Z a-z 0-9); 0x16f90 (su-path blob); 0x16ed0 (nivafollower)
.got/ptrpage 0x010eab0..0x010f3a0  (147 QWORD slots; hot: 0x10ee90×178, 0x10efd0×110, 0x10eef0×88)
JNI table    0x010a4e8 (22 natives, exact list §4)
ctors        .init_array → 0x37550 (REGISTRY 0x101eb8 write), 0xcc4c8 (REGISTRY)
JNI_OnLoad   0x003f4d8 (158-slot ptr-cache fill)
```

**IRELATIVE (0xf00) resolution — final call targets:**
- 0x10ee90 = memcpy-final (178 sites), 0x10efd0 = strlen-like (110), 0x10eef0 = chk-fail-like (88)
- PLT 0x105f0c (memcpy import) resolves to 0x10ee90 — i.e. **the dynamic linker already wrote finals**; the "1,956 sites" of `0xe89fc` etc. are internal helpers on this page.

**Machine-level BL caller map (validated scan — notes/v846_caller_map.json):**

| target | callers | meaning |
|--------|---------|---------|
| 0x923c0 (custom-B64) | **94** | every encoded string decode |
| 0x86684 (DECODE_STR) | 36 | small-string decoder (≤20B direct / ≥31B walker) |
| 0x38f60 (CONCAT) | 126 | string concat |
| 0xe89fc (FLAGCHECK) | **1,956** | kill-flag poll (gated by 0x36dfc init, 12 sites) |
| crypto_a 0x37cb8 | 12 | AES dispatch |
| crypto_c 0x87690 | 17 | keyed transform (28B key @0x16f07) |
| crypto_b 0x395d4 | 1 (0x77a64) | Retrofit#1 path only |
| frida_scan 0xa4054 | 2 (0x4c814 req, 0x6498c x0014b4f3) | env scan |
| frida_tokens 0x92798 | 3 (0x44c0c, 0x7276c, 0xa5370) | token check |
| delmaps 0xb88d8 | 1 (0x711f4 resp) | /proc/self/maps tamper check |
| pin_verify 0xc7c90 | 1 (0x72e1c resp) | signer-pin blob verify |
| apksha 0x7c08c | 3 (0x3fe80/0x3fed4 init, 0x4c87c req) | APK SHA |
| apksha2 0xbdb68 | 1 (0x72e14 resp) | APK SHA v2 |
| **inflate trio** | **0 (DEAD)** | zlib linked but never called |
| 0xa9ba0 (su-path builder) | 9× from 0xa998c..0xa9b4c | root check |
| access() import | 9 sites (all inside root-check fn 0xa8c80+) | F_OK × 9 su paths |
| __open_2 import | 3 sites (0x59a28, 0x985fc, 0xae720) | file readers |
| clock() import | 1 site (0x923fc inside custom-B64) | salt source |

**JNI import usage (85/88 imports called; notable zeros: NO pthread_create, NO dlopen/dlsym, NO system, NO fopen — only `__open_2`; 3 inflate = dead; NO dlsym ⇒ no runtime plugin load).**

---

## 3. DETECTION LIFECYCLE — "kab load hota hai, kab chalta hai"

### 3.1 LOAD (process start, .so mapped)
```
1. dyld maps libtopfollow.so
2. .init_array ctors:
     0x37550 → writes REGISTRY global @0x101eb8 (+0x8970/0x8974/0x8978 words)
     0xcc4c8 → REGISTRY write #2
3. Java loads class → static { } → native init chain:
     JNI_OnLoad 0x3f4d8 (158-slot ptr-cache: caches env fns, class refs, jmethodIDs)
     → Java calls x0011a4c2 ()J  [0x3fdd8, 624B]
        step1: FLAGCHECK ×4
        step2: APKSHA 0x7c08c ×2   ← **APK SHA-256 computed HERE, at app startup**
        step3: H_36dfc (counter init), 0xe8ce8, 0xe90e8, 0x85a4c
        step4: REGISTRY finalize
        → returns token (J) to Java (stored in helper singleton)
```
**So: detection state (registry, counters, APK hash) is LOAD-BORN. The APK is hashed once at startup; the hash is re-verified per request (§3.2).**

### 3.2 RUN (per user action, all INLINE — no threads, no timers)
```
USER TAPS "ORDER / FOLLOW" etc.
└─ Java activity → native request chain:
   1. x00135e2a (JsonObject, InstagramAccount, String)   [IG account JSON: fbid_v2, interop_messaging_user_fbid, follower_count, following_count]
   2. x0015a3b7 (JsonObject, InstagramAccount, Order)    [payload JSON: username, order_id, fbid]
   3. x00120b1e (JsonObject, String)                     [helper T object init + addProperty×N]
   4. x0012e5a1 (JsonObject)   ← **THE SIGN/SEND PREP (38,692B, 249×FLAGCHECK)**
        • CUSTOM_B64 ×34 (all field strings decoded)
        • CONCAT ×26 (assembled)
        • CRYPTO_C ×8 (keyed transforms)
        • GATEWRAP ×40
        • 0x4c814 → **FRIDA_SCAN**  ── runs BEFORE the request goes out
        • 0x4c87c → **APKSHA**     ── APK hash re-verified BEFORE request
   5. x0017b62c (String,String,String)String  [final string combine]
   6. x00126f7c (Z,String)Retrofit  → OkHttpClient build (CertificatePinner.add×3, TimeUnit, TLS)
   7. x0018d3f7 (I)Retrofit → IG endpoint client (base 0x17230 encoded)
   8. (Java/Retrofit executes HTTP)
   9. x0015e49c (Response, Order, …)  ← **RESPONSE HANDLER (48,456B)**
        • read body: isSuccessful()Z → body() → bytes()[B  / errorBody() → raw()
        • 0x711f4 → **DELMAPS** (maps tamper check)
        • 0x7276c → **FRIDA_TOKENS**
        • 0x72e14 → **APKSHA2** (second hash variant)
        • 0x72e1c → **PIN_VERIFY** (signer-pin blob re-check)
        • internal 0xa5xxx (via 0xa5c90): HOOKTOKENS + FRIDA_TOKENS + CRYPTO_A
        • H_36dfc ×12, DECODE_STR ×12, CTX_BUILD ×9
   10. x0014c1f9 (Response)String  ← **PARSE: body().string() → JSON → "hash_key","nonce","hash_type" → setHash_key/setNonce/setHash_type on model**
        (29× env[0xb8] calls = per-field get/set; 15× CTX_VALID; 12× H_e8fe4)
   11. x0011f1a2 (Order)String  ← URL BUILD (media_id field; path encodings @0x17208/0x1721b/0x17227)
   12. x0011f42b ()String / x00105e9b (String)String / x0014b4f3 (String)String
        [status/codec transforms — x0014b4f3 runs FRIDA_SCAN on every call]
   13. x0012f5b7 ()String  ← fingerprint: Build.MANUFACTURER/BRAND/MODEL/BOARD/DEVICE/HARDWARE + "XRl"
   14. x0010e27f ()String / x00113f7a ()String  [small getters; 0xc7ffc = pin/hash read]
   15. x0015b1e9 (JsonObject,String,String) ← **XPOSED/ROOT SCAN (37,564B)**
        • reads "/proc/self/maps" (b64 @0x15a11) via reader-1 module (0x55000-0x5b000)
        • scans maps text for b64 tokens: xposed (0x1680c), lsposed (0x163a4), edxposed (0x15dff)
        • 24× thread-name match "gum-js-loop" (Frida JS worker) in same module
        • root: 9× access(path, F_OK) on su paths (§7)
        • env[0x2f0]×24 + env[0x2f8]×12 = static-method calls into helper
```

**Trigger summary (the answer to "kab chalta hai"):**
| check | fires | where |
|-------|-------|-------|
| registry/ctors | .so load | 0x37550/0xcc4c8 |
| ptr-cache | first native call | JNI_OnLoad 0x3f4d8 |
| APK SHA-1 | **app startup** (init native) | 0x3fe80/0x3fed4 |
| frida_scan | **before every request** + on x0014b4f3 transform | 0x4c814, 0x6498c |
| APK SHA re-check | **before every request** | 0x4c87c |
| delmaps (maps tamper) | **after every response** | 0x711f4 |
| frida_tokens | after response ×2 + internal | 0x7276c, 0xa5370 |
| APK SHA-2 | after every response | 0x72e14 |
| pin_verify (signer blob) | after every response | 0x72e1c |
| hooktokens | after response (internal 0xa5xxx) | 0xa5368 |
| xposed maps scan + 9× su access() | during payload/scan native | 0x5342c.. fn, 0xa8c80+ |
| FLAGCHECK (kill-flag poll) | 1,956 sites — effectively **every basic block boundary** in natives | 0xe89fc |

**On detection:** flags land in 0x10eab0-page slots → next FLAGCHECK takes the fail edge → `b .` self-loop (hang) at 146 trap sites; some paths → `0xeb2d0` cluster → **syslog/abort** (crash-with-log as anti-forensics/nuisance). No silent exit — the app deliberately hangs or crashes.

---

## 4. THE 22 JNI NATIVES — EXACT LOGIC

**Verified env-table offset map** (this .so indexes the runtime env table by raw offset; semantics verified from argument registers + paired rodata names + result usage — exact spec-index names depend on the build-time jni.h, so semantics are given instead):

| offset | verified call signature | verified semantics (usage-proven) |
|--------|------------------------|-----------------------------------|
| 0x30 | (env, x1) → obj | string/class creation helper (NewStringUTF-like); results fed to addProperty / class refs |
| 0xf8 | (env, obj, name, sig) → ID | field-ID lookup (paired with field names in model/JSON natives) |
| 0x108 | (env, obj, name, sig) → ID | **GetMethodID** — every use is paired with name + *method* signature (`build`/`()Lokhttp3/CertificatePinner;`, `add`/`(Ljava/lang/String;[Ljava/lang/String;)Lokhttp3/CertificatePinner$Builder;`, `isSuccessful`/`()Z`, `body`/`()L...;`) |
| 0x2b0, 0xef0 | (env, obj, name, sig) → ID | GetMethodID variants (encoded-class paths) |
| 0x488 | (env, obj, mid, x3=jlong) → obj | **CallLongMethod** — e.g. OkHttpClient.Builder.timeout(millis, TimeUnit) (TimeUnit FindClass immediately precedes) |
| 0x538 | (env, C-string) → jstring | **NewStringUTF** — result returned to Java in 20+ natives |
| 0x548 | (env, jstring, …) → char* | **GetStringUTFChars**-like — input string extracted before hash/concat |
| 0xb8 | (env, obj, mid) → jint | **CallIntMethod** — model int getters (follower_count, media_count, …) |
| 0x2f0/0x2f8 | (env, class, smid, …) | **CallStaticXxxMethod** — helper singleton statics |
| 0xec0 | (env, class-name) → jclass | **FindClass** — proven with `java/util/concurrent/TimeUnit`, `okhttp3/OkHttpClient$Builder` |

Common prologue/epilogue of every native: `stp` frame, `mrs xN, tpidr_el0`, stack-canary check, **FLAGCHECK (0xe89fc) poll before/after each call block** (1,956 polls total), REGISTRY finalization, `__stack_chk_fail` on canary mismatch. GATE (0x37160) / GATEWRAP (0x3d0e0/0x3d0d4) = counter-based anti-debug gate: reads A from 0x10eab0-page, computes `A·(A−1)+B ∈ {9,10}`, else `b .` hang.

### 4.1 x0011a4c2 `()J` — 0x3fdd8..0x40048 (624 B) — **INIT**
```
x0011a4c2():
  FLAGCHECK ×4
  h1 = APKSHA()            ; 0x7c08c — SHA-256 of the APK file, computed at startup
  h2 = APKSHA()            ; second pass (0x3fed4)
  H_36dfc()                ; counter/epoch init
  r  = 0xe8ce8(h1,h2)      ; mix
  r  = 0xe90e8(r)
  r  = 0x85a4c(r, 0x16e90) ; + constant string (0x16e90)
  REGISTRY finalize (0x101eb8)
  return r                  ; long token stored by Java in helper singleton
```
**Purpose:** one-shot init; binds the APK hash into the registry. Runs once per process (Java static init).

### 4.2 x0014e2e9 `()String` — 0x40048..0x40234 (492 B)
`DECODE_STR(≤20B MBA) → GATE → return NewStringUTF(decoded)` — returns one decoded constant string (app/version token). 2× NewStringUTF = try/retry path.

### 4.3 x0016d3b9 `()String` — 0x40234..0x404c4 (656 B)
rodata anchor **0x16ef4 = `topfollow_check.php`** + `DECODE_STR ×2` + `GATE ×2` → **returns the C2 endpoint path** (`https://nivafollower` + `topfollow_check.php`).

### 4.4 x0012d3e0 `(String)String` — 0x404c4..0x40c44 (1,920 B)
```
in = GetStringUTFChars(x0)
out = 0x88efc(in)                ; transform (0x3f0a0 ×2 pre-step)
out = CTX_BUILD(out)             ; AES ctx setup
out = CRYPTO_C(out)              ; keyed transform, 28B key @0x16f07
out = CONCAT(out, 0x8b2a0)
out = 0x86880(out, "256"@0x16248); SHA-256 context (the "256" tail of "SHA-256")
return NewStringUTF(hex(out))
```
**Purpose:** input string → SHA-256 + keyed transform → hex string. (Request-hash primitive.)

### 4.5 x0011e28b `(String)String` — 0x40c44..0x41518 (2,260 B)
Twin of 4.4 with `0x8c544` in place of the 0x86880 step (28 FLAGCHECKs) — **hash variant #2** (different mix order; used where the C2 expects variant B).

### 4.6 x00120b1e `(JsonObject, String) V` — 0x41518..0x45a70 (17,752 B)
```
T = FindClass("com/nivaroid/topfollow/helper/T"); t = NewObject(T.<init>)
addProperty(json, "3e0" , t.3e0())          ; helper method names "3e0()", "x21()", "d27()"
                                            ; (obfuscated helper class, string codecs)
for field in [decoded strings ×5 (CUSTOM_B64)]:
    GATEWRAP2; CTX_BUILD ×7; CTX_VALID ×4
    addProperty(json, name, value)          ; 10× env[0xb8] int-style getters + 4× NewStringUTF
```
**Purpose:** initializes the obfuscated helper singleton `T` and fills the request JSON with helper-computed fields.

### 4.7 x0012e5a1 `(JsonObject) V` — 0x45a70..0x4f194 (38,692 B) — **MAIN SIGN/SANITIZE**
```
for each field in json:                      ; 34× CUSTOM_B64 (decode encoded field values)
    v = customB64decode(value)
    v = CONCAT chain (×26)
    v = CRYPTO_C(v) ×8                       ; keyed transform (0x16f07 key)
    GATEWRAP ×40; H_91c00 ×35; H_e8f10 ×9
    json.setProperty(key, v)
FRIDA_SCAN()      ; 0x4c814 — /proc/self/maps frida scan BEFORE request
APKSHA()          ; 0x4c87c — APK hash re-verify BEFORE request
(249× FLAGCHECK across all blocks)
```
**Purpose:** the pre-request gate — decodes, re-encrypts all payload fields, then runs the two big environment checks. If either fails → flags set → next FLAGCHECK hangs.

### 4.8 x00135e2a `(JsonObject, InstagramAccount, String) V` — 0x4f194..0x5307c (16,104 B)
```
addProperty(json, "fbid_v2",                     acct.getFbid_v2())
addProperty(json, "interop_messaging_user_fbid", acct.getInteropFbid())
addProperty(json, "follower_count",  acct.getFollowerCount())    ; env[0xb8] int getters
addProperty(json, "following_count", acct.getFollowingCount())
addProperty(json, "x21", <helper x21()>)
(0xb0d18 ×8, 0xe9c0c ×7 = field-ID/decode helpers)
```
**Purpose:** IG account → JSON (note: requests **Facebook IDs** — fbid_v2, interop fbid — as part of the payload).

### 4.9 x00105e9b `(String)String` — 0x5307c..0x5342c (944 B)
`CUSTOM_B64 ×2 → CONCAT → CRYPTO_A(type) → GATE → NewStringUTF` — **string codec** (CRYPTO-A AES dispatch, method anchor `f7c`). Used to decode/encode tokens before/after transport.

### 4.10 x0015b1e9 `(JsonObject, String, String) V` — 0x5342c..0x5c6e8 (37,564 B) — **XPOSED/ROOT SCAN + SETUP JSON**
```
maps = reader1(open("/proc/self/maps"))        ; b64 @0x15a11, reader fn 0x59a28 (module 0x55000-0x5b000)
if maps contains b64"xposed"  (0x1680c)  → flag XPOSED
if maps contains b64"lsposed" (0x163a4)  → flag LSPOSED
if maps contains b64"edxposed"(0x15dff)  → flag EDXPOSED
for each tid: thread_comm = /proc/self/task/<tid>/comm  ; 24× "gum-js-loop" matches (Frida JS thread)
root = suCheck()                                ; 9× access(path, F_OK) — §7
addProperty(json, "setup", ...)                 ; CallStaticMethod ×24 (env[0x2f0]) — helper setup
addProperty(json, "currentInstagram", ...)      ; env[0x2f8] ×12
(211× FLAGCHECK, GATE ×10, CTX_BUILD ×9)
```
**Purpose:** the environment-scan native (this is where "xposed" detection actually lives) + builds setup/currentInstagram JSON. The two String args are mode selectors.

### 4.11 x0015a3b7 `(JsonObject, InstagramAccount, Order) V` — 0x5c6e8..0x6084c (16,740 B)
```
addProperty(json, "username", acct.getUsername())          ; env[0x548] char* extraction
addProperty(json, "order_id", order.getOrderId())
addProperty(json, "interop_messaging_user_fbid", acct.getInteropFbid())
+ order fields (strlen ×7 = length guards, CTX_BUILD ×7, GATEWRAP2 ×6)
```
**Purpose:** the actual **order payload** (who: username+fbid; what: order).

### 4.12 x0017b62c `(String,String,String)String` — 0x6084c..0x61510 (3,268 B)
`CUSTOM_B64 ×4 + CONCAT ×6 + H_91c00 ×6 + GATE ×2 → NewStringUTF` — **final string combiner** (three inputs: typically base + payload + hash) → the final signed body string.

### 4.13 x0011f42b `()String` — 0x61510..0x63b58 (9,800 B)
Builds a **state JSON string**: 20× NewStringUTF, fields `setup`, `currentInstagram`, `media_count`, `f7c`, `x21`; env[0x388]×4, env[0xf8]×4, static calls env[0x2f0]×4 → serialized app state (sent to C2 for sync/billing).

### 4.14 x0012f5b7 `()String` — 0x63b58..0x64888 (3,376 B) — **DEVICE FINGERPRINT**
```
f = Build.MANUFACTURER | Build.BRAND | Build.MODEL | Build.BOARD | Build.DEVICE | Build.HARDWARE
f = CONCAT chain (×7) + 0xb6a1c ×6 (per-field normalization) + CUSTOM_B64 ×3
f = CONCAT(f, "XRl"@0x15a3d)          ; fixed suffix marker
return NewStringUTF(f)
```
**Purpose:** device fingerprint string (attaches to requests; server-side device binding).

### 4.15 x0014b4f3 `(String)String` — 0x64888..0x65338 (2,736 B)
`CUSTOM_B64 ×3 → CONCAT ×3 → GATEWRAP ×2 → GATE ×2 → FRIDA_SCAN() @0x6498c → NewStringUTF` — **string transform that re-runs the Frida scan on EVERY call** (cheap per-transform tripwire).

### 4.16 x0011f1a2 `(Order)String` — 0x65338..0x67d98 (10,848 B) — **URL BUILDER**
```
base = DECODE_STR("i.instagram.com/api/v2/")      ; 20B @0x17208 area (literal, 0x20 len)
path = DECODE_STR(order.action):
    "friendships/create/" (0x17208) | "media/" (0x1721b) | "comment/" (0x17227)
    "create_note/v2/" (0x14854) | "/save/" (0x14a48) | "seen/" (0x1675b)
url  = CONCAT(base, path, order.media_id, "6*2"@0x16dea params)
GATEWRAP ×14, CTX_BUILD ×4, strlen ×4 (length sanity)
return NewStringUTF(url)
```
**Purpose:** full IG API URL for the order action. (C2 base = `https://nivafollower` + `topfollow_check.php` from §4.3; `nivafollower.app` @0x172ce used in client TLS config.)

### 4.17 x0015e49c `(Response, Order, …) …` — 0x67d98..0x73ae0 (48,456 B) — **RESPONSE HANDLER**
```
ok = response.isSuccessful()            ; env[0x108] GetMethodID + CallX (18× env[0xf8] field ops)
if ok:   b = response.body();  bytes = b.bytes()[B
else:     eb = response.errorBody(); raw = eb.raw(); bytes = raw()…
DELMAPS()          ; 0x711f4 — /proc/self/maps tamper check (post-response)
FRIDA_TOKENS()     ; 0x7276c
APKSHA2()          ; 0x72e14
PIN_VERIFY()       ; 0x72e1c — signer-pin blob (0x14ce4) re-verify
internal(0xa5c90): HOOKTOKENS(0xa5368) + FRIDA_TOKENS(0xa5370) + CRYPTO_A(0xa54ec)
decrypt/parse(bytes) → state update (H_36dfc ×12, DECODE_STR ×12, CTX_BUILD ×9, H_86474 ×10)
```
**Purpose:** read response, run the post-response detection battery (4 checks), process/decrypt payload.

### 4.18 x0010e27f `()String` — 0x73ae0..0x73ca8 (456 B)
`0xc7ffc(read pin/hash slot) → GATE → NewStringUTF` — small getter for a stored value (pin-derived string).

### 4.19 x00113f7a `()String` — 0x73ca8..0x73f48 (672 B)
`DECODE_STR(36-char constant) → GATE → NewStringUTF` — returns the fixed **36-char app token** (decoded at runtime; not in rodata in plain form).

### 4.20 x0014c1f9 `(Response)String` — 0x73f48..0x776ec (14,244 B) — **RESPONSE PARSE**
```
s = response.body().string()             ; GetMethodID "body" + "string"
json = parse(s)
model.setHash_key(json["hash_key"])      ; 29× env[0xb8]-class get/set pairs
model.setNonce(json["nonce"])
model.setHash_type(json["hash_type"])
CTX_VALID ×15 (each field validated), H_e8fe4 ×12, H_9346c ×4, H_9bfe4 ×3
return NewStringUTF(payload-or-status)
```
**Purpose:** extracts `hash_key`/`nonce`/`hash_type` from server JSON into the model (these drive the next request's signing).

### 4.21 x00126f7c `(Z, String)Retrofit` — 0x776ec..0x7a3ac (11,456 B) — **C2 HTTP CLIENT**
```
domain  = decode(0x172ce)                ; "nivafollower…"
pinner  = CertificatePinner.Builder()
            .add(domain, pins[3])         ; PINNER ×3
            .build()                      ; GetMethodID "add"/"build" (usage-proven)
client  = OkHttpClient.Builder()
            .certificatePinner(pinner)
            .timeout(millis, TimeUnit)    ; FindClass "java/util/concurrent/TimeUnit" + env[0x488] CallLongMethod
            .build()
retrofit = Retrofit.Builder().baseUrl("https://" + domain + "/topfollow_check.php").client(client).build()
x0 (Z flag) selects C2 vs local build; H_86474 ×10 = builder-step helper
```
**Purpose:** builds the **C2 client with certificate pinning** (3 pins).

### 4.22 x0018d3f7 `(I)Retrofit` — 0x7a3ac..0x7c08c (7,392 B) — **IG API CLIENT**
Same okhttp pattern (GATEWRAP ×14, H_86474 ×6, DECODE_STR ×2, PINNER ×1, env[0x108]×5 GetMethodID, env[0x30]×6, env[0x488]×2 timeouts) with base = decode(0x17230, 31B) = `i.instagram.com/api/v2/…`; `I` arg = endpoint selector. **Purpose:** builds the Instagram API Retrofit client.

---

## 5. EXACT AES LOGIC (Unicorn-proven — 6/6 FIPS-197 vectors)

**Provenance:** upstream = **mbedtls 3.x** (file header `Copyright (C) 2006-2024, Arm Limited` at 0x11510; AES core + md_wrap*). The "custom" feel comes from (a) word-reversed schedule storage and (b) a mode wrapper that is not plain ECB/CBC.

### 5.1 Key expansion — 0x31260
```
ABI: (ctx, key, iv_or_aux, w3=keylen, w4=0x10)     call sites: 0x3884c, 0x3a5fc, 0x881c0, 0x8d384
ctx+8  = 1 (rounds flag: 10/12/14 by keylen)
schedule stored at ctx+0xc, each 32-bit word BYTE-REVERSED vs standard
AES-192/256 second key half at ctx+0x30 (word-reversed)
Algorithm: genuine FIPS-197 R1 — round constants, S-box, SubWord/RotWord/ MixColumn-equivalent
           (verified: R1 output matches FIPS appendix for 128B and 0123…-style 256B keys)
Emulation cost: 29,468 steps (16B), 43,886 (32B)
```

### 5.2 Block cores — FIPS-197 verified
| core | addr | inner | ABI | proof |
|------|------|-------|-----|-------|
| **AES-128/192/256 ENCRYPT** | 0x2edf8 | 0x2ccbc | (ctx, src16, dst16) | FIPS vector: key 000102…0f, PT 00112233…eeff → CT `69c4e0d8 6a7b0430 d8cdb780 70b4c55a` ✓ (plus 192/256 vectors) |
| **AES-128/192/256 DECRYPT** | 0x2fdcc | 0x2dbc0 | (ctx, src16, dst16) | all 3 key sizes ✓ |
Output at dst in **standard byte order** (the reversal is storage-only). 6/6 enc+dec×128/192/256 passed.

### 5.3 Stream wrapper (encrypt) — 0x33260
```
ABI: (ctx, in, out, x3=data/null, w4=mode)
GATE: if (len % 16 != 0) return;              ; 20B input → 209 steps, zero output (measured)
mode 0 = ECB:                     CT_i = AES(PT_i)                     [proven, 2-block]
mode 1 = PREFIX-XOR-ECB:          CT_i = AES(PT_i ^ (PT_1⊕…PT_{i-1})) [proven, 3-block]
mode 2 = SEEDED variant:          M1 = dec(CT1) ^ PT1 = 5db34a7a 22a88b39 35867cfc 884ab119
                                  (nonzero seed appears with zero IV arg; exact seed derivation open — 1 item)
```

### 5.4 Stream wrapper (decrypt) — 0x33aa8
```
ABI: (ctx, in, out, x3, w4 ∈ {0,1})
mode 0 = ECB decrypt (proven); mode 1 = inverse of prefix-xor-ECB (proven)
```

### 5.5 CRYPTO-A — 0x37cb8 (12 call sites) — the dispatch
```
switch (type) {
  case 0x001: …  case 0x10d: …  case 0x27c: …  case 0x995: …
  case 0xd9e: …  case 0xf33: …  case 0x16c8: → KEY K4 → mode-1 PREFIX-XOR-ECB (the request-body cipher)
}
each arm: KEYEXP(0x31260) → WRAP(0x33260, mode) → per-16B-block 0x33aa8-style loop
```
**Known arm:** type 0x16c8 = K4 key + mode 1 (proven end-to-end: request bodies decrypt correctly with K4/mode-1). Other arms' keys partially behind the 0x101cbc walker (O1 item); the arm STRUCTURE (keyexp→wrap→blocks) is identical.

### 5.6 CRYPTO-C — 0x87690 (17 call sites)
```
key = 28B static @0x16f07 (not AES keylen — used as XOR/CTR stream seed, not fed to 0x31260)
out = transform(in, key28)   ; 17 sites = every JSON field re-encryption (§4.7) + response parsing
```
### 5.7 CRYPTO-B — 0x395d4 (1 call site, 0x77a64 = Retrofit#1/C2 path)
C2-channel transform only. (Single caller = C2 body encryption.)

### 5.8 Keys inventory
| key | location | use |
|-----|----------|-----|
| K1..K4 (AES-128) | runtime-decoded via 0x923c0 from rodata encodings (K4 = request body, proven) | CRYPTO-A arms |
| 28B key | static @0x16f07 | CRYPTO-C |
| M1 seed | 5db34a7a22a88b3935867cfc884ab119 | wrapper mode 2 |
| 36-char app token | 36-char encoding, decoded at runtime (x00113f7a) | request auth field |
| pin blob | 0x14ce4, 120B = b64(b64(hex(sha256))) = d845591e…ea6bec5e | signer pin (build #8 rewrote; #9 must too) |

---

## 6. DETECTION — COMPLETE MAP (every check, exact trigger)

### 6.1 LOAD phase
| # | what | when | addr |
|---|------|------|------|
| L1 | registry write (global state page) | .so ctor (dyld) | 0x37550, 0xcc4c8 → 0x101eb8 |
| L2 | 158-slot env/class ptr-cache fill | JNI_OnLoad | 0x3f4d8 |
| L3 | **APK SHA-256 #1** (of the installed APK file) | init native x0011a4c2 (app startup) | 0x3fe80, 0x3fed4 |
| L4 | counter/epoch init | init native | 0x36dfc via 0x3fdd8 |

### 6.2 RUN phase (inline, no threads — verified: NO pthread_create import anywhere)
| # | check | when | caller fn (native) | site |
|---|-------|------|--------------------|------|
| R1 | **Frida scan** (#1) | before every request | x0012e5a1 | 0x4c814 |
| R2 | **APK SHA re-verify** | before every request | x0012e5a1 | 0x4c87c |
| R3 | Frida scan (#2) | every x0014b4f3 string transform | x0014b4f3 | 0x6498c |
| R4 | **maps tamper (delmaps)** | after every response | x0015e49c | 0x711f4 |
| R5 | **frida_tokens** | after every response | x0015e49c | 0x7276c |
| R6 | **APK SHA #2 variant** | after every response | x0015e49c | 0x72e14 |
| R7 | **signer-pin verify** | after every response | x0015e49c | 0x72e1c |
| R8 | hooktokens + frida_tokens + CRYPTO_A | after response (internal) | 0xa5xxx via 0xa5c90 | 0xa5368/0xa5370/0xa54ec |
| R9 | **XPOSED maps scan** (xposed/lsposed/edxposed) + **gum-js-loop thread scan** + **9× su access()** | payload/scan native | x0015b1e9 | 0x5342c.. + 0xa8c80+ |
| R10 | FLAGCHECK kill-flag poll | ~every basic block (1,956 sites) | all | 0xe89fc |
| R11 | GATE counter check (MBA A·(A−1)+B∈{9,10}) | before/after call blocks | many | 0x37160 (+wraps 0x3d0e0/0x3d0d4) |

### 6.3 ROOT CHECK (exact) — fn 0xa8c80+ inside x0015b1e9
```
for i in 0..8:
    src, len = encoded window of blob @0x16fa0 (overlapping 23..25B windows)
    path = STR_BUILD(src, len, dst, salt=0x5a)   ; 0xa9ba0 — clock/epoch-gated decode
    if access(path, F_OK) == 0:  flag ROOT       ; import access(), 9 sites @0xa998c..0xa9b4c
```
**7/9 decoded paths** (isolated Unicorn of the builder; deterministic):
```
/sbin/su              /system/bin/su         /system/xbin/su
/data/local/xbin/su   /data/local/bin/su     /system/sd/xbin/su
/data/local/su
```
2 windows (0x16f93 len25, 0x17008 len23) are gated by a call-epoch counter that must run in-sequence (O2). All 9 are classic su-binary presence checks (F_OK = file exists).

### 6.4 FRIDA SCAN (0xa4054) — what it looks for
- reads `/proc/self/maps` (reader 0x59a28 in module 0x55000–0x5b000)
- matches map line names/paths against **Frida markers** incl. `frida`, `gadget`, `linjector`, `frida-agent` token group (0x92798 token table; 24× `gum-js-loop` = Frida's JS worker thread name, matched via /proc/self/task/<tid>/comm)
- dl_iterate_phdr @0x1028e8 (single site) walks loaded DSOs for the same tokens
- **Inflate (zlib) = NOT used here — dead code (0 callers).**

### 6.5 delmaps (0xb88d8) — post-response maps tamper
Re-reads maps and checks expected mapping list integrity (catches runtime map-rewriters).

### 6.6 pin_verify (0xc7c90) — signer-pin blob
Recomputes/compares the 120B blob @0x14ce4 (b64(b64(hex(sha256))) — the APK's expected signature hash). Build #8/#9 rewrite this blob to match the resigned APK; trap sites 0x7c08c / 0xbdb68 (5 each) fire on mismatch.

### 6.7 FAILURE BEHAVIOR (what detection does)
1. flag bits set on 0x10eab0-page (hot slots 0x10ee90/0x10efd0/0x10eef0 = 178/110/88 referrers)
2. next FLAGCHECK (0xe89fc) fails → `b .` **self-loop hang** (146 trap sites) — app freezes on-screen
3. some paths → 0xeb2d0 cluster → **syslog + abort** (crash with forensic log)
4. custom-B64 decode failure → `b .` @0x92748 (silent hang)
**No silent exit, no fake-success — deliberate nuisance/hang.** → agent must keep hooks log-only and never disturb flag/counter values.

---

## 7. URL / HEADER / RESPONSE CONSTRUCTION (consolidated + corrected)

### 7.1 String decoding machinery (the "obfuscation" explained)
| layer | addr | mechanism |
|-------|------|-----------|
| CUSTOM_B64 | 0x923c0..0x92780 (94 callers) | out[i] = table62[0x16f27][ MBA(clock() ⊕ i) ]; alphabet A–Z a–z 0–9; anti-debug salt; fail → `b .` @0x92748 |
| DECODE_STR | 0x86684 | ≤20B direct MBA on spot; ≥31B via 0x101cbc runtime walker (O1) |
| CONCAT | 0x38f60 (126 callers) | string concat |
| symbol pool | 0x14d54..0x2076b | 5,591 printable strings (Java class/method names, sigs, field names) — JNI name sources |

### 7.2 Endpoints
| purpose | value | encoding addr |
|---------|-------|---------------|
| IG API base | `i.instagram.com/api/v2/` (literal, len 0x20) | 0x17208 area |
| IG paths | `friendships/create/` `media/` `comment/` `create_note/v2/` `/save/` `seen/` | 0x17208/0x1721b/0x17227/0x14854/0x14a48/0x1675b |
| C2 base | `https://nivafollower` + `topfollow_check.php` | 0x16ed0 / 0x16ef4 |
| C2 domain (TLS config) | `nivafollower.app` | 0x172ce |
| IG client base (31B) | i.instagram.com/api/v2/… (encoded) | 0x17230 |
| registry-only strings (runtime decode) | 0x17277 (36B), 0x172de (47B) | — |

### 7.3 Request flow (what actually goes on the wire)
```
body = x00120b1e(helper T + fields)
     → x00135e2a(acct: fbid_v2, interop fbid, follower/following counts)
     → x0015a3b7(username, order_id, fbid)
     → x0012e5a1(all fields: customB64 decode → CRYPTO_C re-encrypt → frida_scan → apksha)
     → x0017b62c(base+payload+hash) = final string
headers: 36-char token (x00113f7a) + device fingerprint (x0012f5b7:
         MANUFACTURER|BRAND|MODEL|BOARD|DEVICE|HARDWARE + "XRl" suffix) + state JSON (x0011f42b)
url  = x0011f1a2(order) → i.instagram.com/api/v2/<action>/<media_id>…
client = x00126f7c (C2, 3-pin cert pinner) / x0018d3f7 (IG, selector int)
```
### 7.4 Response flow
```
x0015e49c: isSuccessful? body.bytes() : errorBody.raw()
           → delmaps + frida_tokens + apksha2 + pin_verify + internal(token checks + CRYPTO_A decrypt)
x0014c1f9: body().string() → JSON → {hash_key, nonce, hash_type} → model setters
           (these 3 fields drive the NEXT request's CRYPTO-A keying — the handshake ratchets)
```

---

## 8. ANTI-TAMPER STATE MACHINE
- **counter page** 0x10eab0..0x10f3a0 (147 QWORDs): global state (flags, epochs, ptr-cache finals)
- **GATE 0x37160:** reads A (counter), computes `A·(A−1)+B` (MBA-encoded); must be ∈ {9,10} else `b .`. Counter is advanced only by legitimate code paths (0x36dfc init, 12 sites) — patching counters desyncs the gate.
- **FLAGCHECK 0xe89fc:** 1,956 sites; reads kill-flag slot; on flag → branch to `b .` trap (146 sites).
- **custom-B64 fail** → `b .` @0x92748.
- **146 total `b .` self-loops** = the "hang" arsenal.
- **0xeb2d0 cluster:** syslog/abort (crash+log path).
- **Implication for agent:** hooks must be **log-only** (no returns patched, no counters touched). Intercept at import level (access/open/syslog/abort) + at the 3 detection fns' ENTRY/EXIT (read flags, don't write).

---

## 9. GADGET / AGENT PLAN (v9) — updated from this analysis
(unchanged build pipeline; agent hooks refined:)
| hook | addr | action |
|------|------|--------|
| H13 | 0x86684 (DECODE_STR) post | log decoded strings (registry URLs) |
| H14 | 0x395d4 (CRYPTO-B) in/out | log C2 transform I/O |
| H15 | 0x923c0 (CUSTOM_B64) post | log decoded C-strings (x0=in, x8=out) — **this single hook reveals every obfuscated string at runtime** |
| H16 | 0x38f60 (CONCAT) post | log concatenations (URL/header assembly) |
| H17 (new) | 0xa4054 frida_scan in/out | log scan verdict (flag delta) |
| H18 (new) | 0xa998c..0xa9b4c (access×9) | log each su path + result (root check live view) |
| H19 (new) | 0xb88d8/0xc7c90 in/out | log delmaps/pin_verify verdicts |
| H20 (new) | 0x37cb8 (CRYPTO-A) dispatch | log type + keys (which AES arm per call) |
| B6 | 0x14ce4 blob | rewrite to new signer sha (as #8) |
| traffic | okhttp/retrofit Java-level (Frida Java API) | full req/resp capture + encrypted resend via PC frida 17.18.0 |

---

## 10. OFFSET APPENDIX (verified, v846 — supersedes all prior offset notes)
```
.text 0x2c734..0x105f04 | PLT stubs 0x105f04..0x106558 (86) | .got/page 0x10eab0..0x10f3a0 (147 slots)
JNI_OnLoad 0x3f4d8 | JNI table 0x10a4e8 (22 natives §4) | ctors 0x37550, 0xcc4c8 | REGISTRY 0x101eb8
custom-B64 0x923c0 (alphabet 0x16f27; fail-loop 0x92748; clock 0x923fc) | frida_tokens 0x92798
DECODE_STR 0x86684 (walker 0x101cbc) | CONCAT 0x38f60 | EMIT 0x86148 | PARSE 0x86510
FLAGCHECK 0xe89fc (1956 sites) | GATE 0x37160 | GATEWRAP 0x3d0e0/0x3d0d4 | traps: 146× b.
kill/flag page 0x10eab0 (hot 0x10ee90/0x10efd0/0x10eef0) | syslog cluster 0xeb2d0
frida_scan 0xa4054 (callers 0x4c814, 0x6498c) | delmaps 0xb88d8 (0x711f4)
apksha 0x7c08c (0x3fe80/0x3fed4/0x4c87c) | apksha2 0xbdb68 (0x72e14)
pin_verify 0xc7c90 (0x72e1c) | pin blob 0x14ce4 (120B; traps 0x7c08c/0xbdb68)
hooktokens 0xaf774 (0x5f2f4, 0xa5368, 0xa5ba0)
AES: KEYEXP 0x31260 | ENC 0x2edf8 (0x2ccbc) | DEC 0x2fdcc (0x2dbc0)
     WRAP-ENC 0x33260 (modes 0/1/2) | WRAP-DEC 0x33aa8 | per-block 0x33aa8
     CRYPTO-A 0x37cb8 (12 sites; arms 1/0x10d/0x27c/0x995/0xd9e/0xf33/0x16c8; 0x16c8=K4+mode1 proven)
     CRYPTO-B 0x395d4 (1 site 0x77a64) | CRYPTO-C 0x87690 (17 sites; key28 @0x16f07)
CTX_BUILD 0xe8b30 | CTX_VALID 0x3b4d4 | PINNER 0x8c18c | H_36dfc 0x36dfc | H_86474 0x86474
root: builder 0xa9ba0 | blob 0x16fa0 | access×9 @0xa998c..0xa9b4c | fn 0xa8c80+
readers: __open_2 @0x59a28 (x19+0x510 path; module 0x55000-0x5b000, gum-js-loop×24)
         @0x985fc (x19+0x28) | @0xae720 (x19+0x28) — flags=wzr, paths runtime-decoded
strings: nivafollower 0x16ed0 | topfollow_check.php 0x16ef4 | nivafollower.app 0x172ce
         IG base 0x17208 | paths 0x1721b/0x17227/0x14854/0x14a48/0x1675b | 31B 0x17230
         "SHA-256" tail 0x16248 | b64 xposed 0x1680c | lsposed 0x163a4 | edxposed 0x15dff
         /proc/self/maps b64 0x15a11 | su blob 0x16fa0 (windows 0x16f93 len25, 0x17008 len23 = O2)
env offsets (usage-verified): 0x30 str/create | 0xf8 fieldID | 0x108 GetMethodID | 0x2b0/0xef0 mID var
         0x488 CallLong(timeout) | 0x538 NewStringUTF | 0x548 GetStringUTFChars | 0xb8 CallInt
         0x2f0/0x2f8 CallStatic | 0xec0 FindClass
```

## 11. OPEN ITEMS (explicitly NOT closed)
- **O1** — 0x101cbc runtime walker (≥31B DECODE_STR): registry strings 0x17277(36B)/0x172de(47B)/0x17230(31B)/0x16df4(31B) decode at runtime; exact walk = in-order emulation (blocked by 0x101cbc context). **H15/H13 agent hooks will capture all of these at runtime — no further static work needed.**
- **O2** — 2 su-path windows (0x16f93 len25, 0x17008 len23): epoch-counter gated; in-order emulation of the 9-decode sequence or live H18 capture.
- **O3** — reader-2/reader-3 (0x985fc/0xae720) runtime paths: sequential emulation of parent fns (0x985c4.., 0xadecc..) or live capture.
- **O4** — wrapper mode-2 seed derivation (M1 = 5db34a7a…): exact seed source unconfirmed (nonzero with zero IV arg).
- **O5** — 0xa5xxx fn boundary (reached via 0xa5c90): no BTI start, boundary unconfirmed (internal fn of response path).
- **O6** — CRYPTO-A arms other than 0x16c8: keys behind O1 walker (runtime capture via H20).

## 12. EVIDENCE FILES (workspace)
```
work/v846/notes/v846_caller_map.json        machine-level BL caller map (validated)
work/v846/notes/v846_22native_semantics.json per-native calls/env/rodata extraction
work/v846/notes/v846_crypto_proven.json     Unicorn crypto proofs (6/6 FIPS + wrapper modes)
work/v846/notes/v846_import_calls.json      85 import → call-site lists
work/v846/notes/v846_plt_stubs.json         86 PLT stubs → imports
work/v846/notes/v846_got_full.json          88 JUMP_SLOT GOT → symbol
work/v846/notes/v846_jni_natives.json       22 natives exact
work/v846/notes/v846_native_profile.json    native ranges
REPORT_libtopfollow_so.md (1,168L) + REPORT_libtopfollow_v846_deep3.html (prior rounds)
```

---
# PART B — APK / SMALI DEEP ANALYSIS (v846, pure-Python: androguard 4.1.4 dex+axml parse)

## 13. APK STRUCTURE
```
v846_new.apk — 9,231,182 B — 1,238 zip entries — sha256 ac0b993e…
  classes.dex            3,866,132 B   (SINGLE dex: 4,050 classes / 26,618 methods / 21,729 strings)
  AndroidManifest.xml    17,924 B      (binary AXML)
  resources.arsc         2,181,552 B
  lib/  (3 ABIs: arm64-v8a, x86, x86_64)
      libtopfollow.so              1,101,352 B  (= analyzed .so, sha 2b2a9eed…)
      libdatastore_shared_counter.so   7,112 B  (androidx.datastore native — NOT app code)
  assets/coin_anim.json  21,892 B     (Lottie coin animation)
  assets/dexopt/baseline.prof/.profm (ART profile)
  res/                   1,111 entries
  META-INF/              NO MANIFEST.MF / .SF / .RSA — NO APK signature block (v2/v3) —
                         file in workspace is the UNSIGNED pipeline artifact.
                         (The .so's pin blob 0x14ce4 still holds the ORIGINAL signer hash
                          d845591e…ea6bec5e → B6 rewrite mandatory on every rebuild.)
```

## 14. MANIFEST (complete)
```
package=com.nivaroid.topfollow  versionCode=0x34e (846)  versionName=8.4.6
compileSdk=36  minSdk=24  targetSdk=35  platformBuild=0x10
permissions: INTERNET, FOREGROUND_SERVICE, FOREGROUND_SERVICE_SPECIAL_USE,
             POST_NOTIFICATIONS, ACCESS_NETWORK_STATE, WAKE_LOCK, c2dm.RECEIVE
application: name=MyApp  allowBackup=false  extractNativeLibs=false (original value;
             build #9 flips → true)  usesCleartextTraffic=false  supportsRtl=false
LAUNCHER = TopActivity (NOT MainActivity)
activities (all exported=false): WebViewActivity, TwoFactorLoginActivity, RequestSaveActivity,
  RequestRepostActivity, CoinMinersActivity, LeaderBoardActivity, ShowFragmentActivity,
  OrdersActivity, DailyRewardActivity, CouponActivity, InviteFriendsActivity,
  RequestLikeActivity, RequestCommentActivity, MenuActivity, UpgradeActivity,
  InstagramLoginActivity, InfoActivity, TopActivity(LAUNCHER), MainActivity
service: DoTasksService (exported=false, foregroundServiceType=specialUse)
receiver: TaskActionReceiver (broadcast "task.service.receiver")
Firebase: FCM (FirebaseMessagingService + FirebaseInstanceIdReceiver), Crashlytics,
  Installations, Sessions, DataTransport; GoogleApiActivity; FirebaseInitProvider
```

## 15. DEX / SMALI INVENTORY
- **173 app classes** (`com.nivaroid.topfollow.*`): application(3), db(2 Room), helper(3: **T, q, a0**), listeners(23), models(75), ui(19), views(58 incl. cardview/slidingpanel/tuto), + obfuscated packages (i9, y9, z9, ca, ba, gc, m5, u7, s7, t2, w0, aa, r3, e0, da, a8, i6, lb, wa, ma, n9, yb, w5, ja, gb, lb…)
- Dependency stack visible in dex: **Jetpack Compose** (UI), Room, Retrofit2+OkHttp, Gson, DataStore(+native), Firebase/FCM/Crashlytics, **Play Integrity + SafetyNet**, **reCAPTCHA v3 + hCaptcha**, Coroutines, Lottie.
- **Root/xposed strings in dex: ZERO** (su paths, /proc/self/maps, xposed tokens — none in Java) → **all environment detection is 100% native-side** (Java layer is clean; only native checks).

## 16. NATIVE BRIDGE — `com.nivaroid.topfollow.helper.q`
22 × `private static native` methods (exact names x00…) + 22 × `public static` **pass-through wrappers** (zero logic — pure `invoke-static` + return):
```
q.a(String)=x0014b4f3   q.b()=x0012f5b7       q.c(String)=x00105e9b
q.d()=x0016d3b9         q.e()=x0014e2e9       q.f()=x0010e27f
q.g()=x00113f7a         q.h(Order)=x0011f1a2  q.i(JsonObject,String)=x00120b1e
q.j()J=x0011a4c2        q.k(String,Z)=x00126f7c  q.l(I)=x0018d3f7
q.m()=x0011f42b         q.n(String)=x0011e28b   q.o(String)=x0012d3e0
q.p(Response,Order,Account)=x0015e49c  q.q(Response)=x0014c1f9
q.r(JsonObject,String,String)=x0015b1e9  q.s(String,String,String)=x0017b62c
q.t(JsonObject,Account,Order)=x0015a3b7  q.u(JsonObject,Account,String)=x00135e2a
q.v(JsonObject)=x0012e5a1
```
**Load point:** `MyApp.<clinit>` (3 instructions): `System.loadLibrary("topfollow")` — runs at Application class init, before any activity. (Other 2 loadLibrary sites = `loadLibrary("datastore_shared_counter")` — androidx, unrelated.)

## 17. `helper.T` — KEYSTORE ECDSA DEVICE IDENTITY (NEW — native calls into Java!)
```
m5/h.v(bytes)  — key creation (once, synchronized):
    if AndroidKeyStore.containsAlias("top_key_4286") return
    KeyPairGenerator("EC", "AndroidKeyStore")
      .initialize(KeyGenParameterSpec("top_key_4286", PURPOSE_SIGN)
          .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
          .setDigests("SHA-256")
          .setUserAuthenticationRequired(false)
          .setAttestationChallenge(bytes))   ← challenge = input (hex-decoded by m5/h.x)
      .generateKeyPair()
T.o(String hex)  — full attestation blob:
    data = hex→bytes
    ks = AndroidKeyStore; cert = ks.getCertificate("top_key_4286")  (null → "null")
    sig  = SHA256withECDSA.sign(data)
    return Base64( sig + "#" + Base64(pubKey.encoded) + "#" + JSONArray[Base64(chain certs)] )
T.sd(String)  — signature only: Base64(SHA256withECDSA.sign(UTF8(input))) or "null"
```
Native `x00120b1e` does `FindClass("com/nivaroid/topfollow/helper/T") + NewObject + GetMethodID((String)String) + Call` → **the .so calls T.o/T.sd over JNI**: every request JSON gets an **attestation-signed payload** (secp256r1, key attestation chain, alias `top_key_4286`). Server side can verify the key is device-bound (keystore, non-exportable) and the challenge binding.

## 18. MAIN ORCHESTRATOR — `i9/m.k(Account, JsonObject, JsonCallback)` (203 insns)
```
device = MyDatabase.getDevice()
if device: q.v(json)                     ; ← native MAIN SIGN (frida_scan + apksha inside)
prefs = getSharedPreferences("TOPNU_Shared", MODE_PRIVATE)
deviceId = decode(prefs["DeviceId"])     ; gc/l.j = Base64 decode ("null"→"")
if empty: deviceId = encode(UUID.randomUUID()) → save     ; gc/l.k = Base64 encode
q.u(json, account, deviceId)             ; ← account JSON native
if prefs["SND"]:                          ; send-mode gate
    if prefs["RID"] == 3850153:           ; magic server-check id
        playIntegrity:
            vendor  = Play Integrity (com.android.play.core.integrity IIntegrityService)
            check   = "com.android.vending" installed + enabled + u7/f.a(signatures) + versionCode ≥ 82380000
            nonce   = q.j() + 877665803231   ; ← native init token + constant
            rd      = decode(prefs["RD"])   ; base64 → bytes (attestation challenge)
            IntegrityTokenRequest{nonce=nonce, integrity token, rd-challenge}
            "requestIntegrityToken(%s)" log; async via Handler
        json.addProperty("x2", encode("x2"))
        prefs["AIT"] → decode → encode("x2") → property "x2"
        RIT (request integrity ts) expiry = 21,600,000 ms = 6 HOURS
callback.onReady(json)                    ; → y9/a.onReady → q.a (transform+frida) → request out
```
**Play Integrity + SafetyNet both wired** (u7/*, s7/* wrappers; `ISafetyNetService` strings present) — integrity token ratchets with the 6h RIT window.

## 19. BACKGROUND ROBOT — `DoTasksService` + `TaskActionReceiver`
```
onStartCommand(intent):
    action="stop"   → cancel all aa/i tasks, stopSelf
    action="enable" → aa/i(account=MyDatabase.p(id), ctx, scheduler) → task list
    action=<uid>    → disable task for that account id
    default        → notification channel via aa/a, startForeground(1, "Auto Robot Running")
                     broadcast "task.service.receiver" (pkg com.nivaroid.topfollow, extra "start")
TaskActionReceiver.onReceive: "task.service.receiver" → type "stop"/"stoping" → service stop
```
**The app auto-runs Instagram actions (like/comment/follow) per-account in a foreground service** — "Auto Robot Running" — this is the product's core automation loop (coins economy: users earn coins via MinerRequests, spend on orders).

## 20. CAPTCHA FLOW — `CaptchaRequest`
```
showRobotDetectionDialog()  → "Suspicious activity detected… prove you are not a robot"
showReCaptcha()             → reCAPTCHA v3 SDK (verifyWithRecaptcha, site-key)
showHCaptcha()              → hCaptcha SDK (WebView js.hcaptcha.com/1/api.js, site-key meta-data)
verifyCaptcha(token)        → JsonObject{"request_id": …} + token → i9/m + JsonCallback
                              (token goes to C2 for server-side verification)
```
C2 verifies captcha server-side; native `q.f()`/`q.g()` (pin getter / 36-char token) are called from the captcha path.

## 21. C2 API SURFACE (all .php endpoints found in dex — base from native: `https://nivafollower` + host)
```
account/addCoupon.php            account/getCoupons.php           account/getCoupon...
account/changeMinerRequest.php   account/checkDailyGift.php       account/getDailyItems.php
account/getGiftCodeReward.php    account/getInviteData.php        account/getLeaderBoard.php
account/getMinerRequests.php     account/getQuestions.php         account/getSecretKey.php
account/getUpgradeStatus.php     account/requestDigitCode.php     account/setInviteCode.php
account/upgradeAccountToVip.php  order/getDefaultComment.php      order/getSelfOrders.php
order/syncOrder.php              get_image.php
```
Other URLs: `https://b.i.instagram.com/` (IG web-login API), `https://i.instagram.com/` (+ `/rupload_igphoto/`), `https://nivafollower-app.com/instagram_info/ic_2fa_1..5.jpg` + `suspicious_login_img_1..4.jpg`, `https://topfollow-apk.org/` (site), `tg://resolve?domain=followland` (Telegram), `market://details`, `googlechrome://navigate?url=instagram.com/accounts/emailsignup|password/reset`.

## 22. STORAGE MAP
```
SharedPreferences "TOPNU_Shared": DeviceId (base64 UUID), RD (base64 integrity challenge),
    AIT (base64 auth token), RID (int 3850153), RIT (long, 6h expiry), SND (bool)
    — ALL values Base64'd via gc/l.j (decode) / gc/l.k (encode)
Room DB (MyDatabase, MyDatabase_Impl): accounts (InstagramAccount: u_id, username,
    fbid_v2, interop fbid, follower/following counts…), orders (Order: order_id, media_id,
    action), device (DeviceModel)
DataStore (androidx, native counter lib): shared counters
Keystore: EC secp256r1 "top_key_4286" (attested, sign-only, no user-auth)
```

## 23. JAVA→NATIVE CALL GRAPH (complete, from full dex scan)
```
q.j  (init/APKSHA)          ← i9/m.k
q.v  (MAIN sign+sanitize)   ← i9/m.k
q.u  (account JSON)         ← i9/m.k
q.t  (payload JSON)         ← y9/a.onReady
q.a  (transform+frida_scan) ← y9/a.onReady
q.r  (xposed scan+setup)    ← y9/b.onReady
q.s  (string combine)       ← y9/b.onReady
q.h  (URL builder)          ← aa/i.b (robot task), ba/f.success
q.k  (C2 Retrofit)          ← y9/h.<init>, y9/h.e
q.l  (IG Retrofit)          ← z9/q.w
q.p  (response handler)     ← ba/h.onResponse, ba/m.onResponse, z9/m.onResponse, z9/n.onResponse
q.q  (response parse)       ← ba/f.onResponse, ba/q.onResponse, r3/c.onResponse, y9/e.onResponse, y9/f.onResponse
q.b  (fingerprint)          ← gc/d.o (per request map build)
q.n/q.o (hash variants)     ← gc/l.j, gc/l.k (prefs codec helpers — actually hash natives called by codec wrappers)
q.d  (C2 endpoint path)     ← y9/d.onReady
q.e  (string token)         ← y9/i.<init>
q.f  (pin getter)           ← CaptchaRequest.showReCaptcha
q.g  (36-char token)        ← CaptchaRequest.showHCaptcha
q.m  (state JSON)           ← ca/i.onReady
q.i  (helper T JSON)        ← ca/i.onReady
```
(Complete machine-readable: notes/v846_q_callers.json)

## 24. SMALI-SIDE CONCLUSIONS FOR THE AGENT
1. **No smali-level detection to bypass** — Java layer contains zero root/frida/xposed checks (all in .so).
2. **Play Integrity token** — agent cannot forge; but hooks can log token requests/results (u7/r, s7/d) to see when integrity runs.
3. **Keystore key `top_key_4286`** — non-exportable; T.o/T.sd results visible only as strings — hook `T.o`/`T.sd` to log attestation blobs (Java-level, trivial).
4. **All secrets live in native** — dex strings contain no AES keys, no signing secrets, no C2 auth tokens (the 36-char token + pin are decoded in .so).
5. **FCM + Crashlytics embedded** — the app phones home via Firebase (project `topfollow-74c69` / `topfollow-74c69.appspot.com`); agent should log FCM messages (push = server commands to the robot).
6. **extractNativeLibs=false (original)** — our build flips to true (frida gadget + minizip fix, per prior decision).
7. **targetSdk=35** — 16KB page alignment NOT required (<10000? targetSdk 35 < 36 → no 16KB page requirement yet).
