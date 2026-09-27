## 14. Deep-3 Round (2026-09-27) — URL / Header / Response Construction

Third analysis pass (3× deeper than the base report). This round resolved the string-
obfuscation question (old O3), mapped the complete encoded-string inventory, reconstructed
the URL/HTTP construction flows, and characterized the call-sequence anti-tamper state
machine. All offsets below are v846 file offsets (== RVAs for this binary).

### 14.1 The string decoder — fully characterized

`0x86684` is the **single** runtime decoder for all obfuscated rodata strings
(family-A *and* family-B; the earlier 0x8907c/0x8b2a0/0x88efc candidates were wrong).

- ABI: `x0 = encoded source, w1 = length, x8 = destination` (call sites, e.g. 0x40088–0x40098).
- Output has a **leading tag byte** (0x0c/0x12/0x20/0x26/0x28…) which the consumer
  `0x38f60` (STR_CONCAT) drops; the usable string is `[1..]`.
- **Short inputs (≤20 B) decode directly** via an MBA byte-loop (≈50–700 emulator steps).
- **Long inputs (≥31 B) take a segmented path**: the decoder enters the registry walker
  `0x101cbc`/`0x101d94` (a JNI-iterator bridge that pulls segments from a live Java object —
  `[x19]` struct with callback at +0x0, state at +0x18). Without a JVM these calls loop
  forever (200k+ steps, zero output). Statically undecodable: 0x17230(31), 0x16df4(31),
  0x17277(36), 0x172de(47). A runtime hook on `0x86684` returns trivially.

Complete call-site map (36 sites, 15 unique sources — `notes/v846_decoder_calls.json`):

| src | w1 | sites | decoded value |
|---|---|---|---|
| 0x16ed0 | 36 | 0x40098 | *(36-char, registry)* — C2 base URL, e.g. `https://nivafollower…` |
| 0x16ed0 | 20 | 0x3884c-region | `https://nivafollower` ✓ emulated |
| 0x16ef4 | 19 | 0x402c4, 0x40320 | `topfollow_check.php` ✓ |
| 0x17208 | 19 | 0x6639c | `friendships/create/` ✓ |
| 0x1721b | 6 | 0x66548, 0x667dc, 0x66948, 0x66aa8, 0x66b64, 0x6e4ac | `media/` ✓ |
| 0x17227 | 9 | 0x66e80, 0x6e9f4 | `comment/` ✓ |
| 0x17230 | 31 | 0x6e168, 0x6e17c, 0x6e394, 0x6e41c, 0x6e63c, 0x6e0cc, 0x7b4d8, … | *(31-char, registry)* — base API path |
| 0x17277 | 36 | 0x73cf8 | *(36-char, registry)* — runtime token |
| 0x172ce | 16 | 0x7816c, 0x781d8 | `nivafollower.app` ✓ (cert-pinner domain) |
| 0x172de | 47 | 0x7a214 | *(47-char, registry)* — Retrofit#2 base |
| 0x16df4 | 31 | 0x6e0cc/0x6e0e0 | *(31-char, registry)* |
| 0x16dea | 6 | 0x66548-region | `5555d6545554` (6 B crypto material) ✓ |

### 14.2 Base64-encoded inventory (2–4 layers)

Recursive b64 sweep over all .rodata NUL-terminated strings
(`notes/v846_deep3_findings.json`):

| offset | layers | value |
|---|---|---|
| 0x14b0e | 4 | `https://` (scheme prefix) |
| 0x1564c | 3 | `https://i.instagram.com/api/v2/` (IG API base) |
| 0x15862 | 2 | `https://www.instagram.com/` |
| 0x14854 | 3 | `create_note/v2/` (endpoint) |
| 0x1675b | 3 | `seen/` (endpoint) |
| 0x14a48 | 2 | `/save/` (endpoint) |
| 0x14ce4 | 3 | PIN blob → `d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e` (SHA-256, see §14.5) |
| 0x15a11 | 1 | `/proc/self/maps` (detection) |
| 0x16992 | 1 | `libfrida-gadget` (detection) |
| 0x163a4 | 1 | `lsposed` (detection) |
| 0x16770 | 1 | `libart.so (deleted)` (detection) |
| 0x16b64 | 1 | `libbc.so (deleted)` (detection) |
| 0x16f31 | 1 | `rwxp` (maps permission check) |
| 0x15c65 | 2 | `HbF0Nh5lp` (token) |
| 0x15dff | 2 | `79dc69a2c79d` (token) |

### 14.3 URL construction — exact flows

**The app is an Instagram automation client** (`com.nivaroid.topfollow`). Two Retrofit
clients are built natively:

**(a) C2 / check client — `x00126f7c (Z,String) → Retrofit` @ 0x776ec (11,456 B)**
1. DECODE `nivafollower.app` (0x172ce, twice — 0x7816c/0x781d8) → `CertificatePinner`
   domain (helper 0x8c18c ×3 → 3 pins).
2. Build 3,648-byte (0xe40) config struct via `0xe8b30`, then **CRYPTO_B `0x395d4`**
   bulk-decrypts it (call at 0x77a64; ABI `x0=ctx, w1=0xe40, x8=input`).
3. `OkHttpClient$Builder` + `certificatePinner(...)` + `writeTimeout(…, TimeUnit.SECONDS)`.
4. `Retrofit$Builder.baseUrl(<String arg>)` — the base host comes from the Java string
   argument; the pinner pins `nivafollower.app`.
5. Getters: `x0014e2e9 ()String` @0x40048 returns the 36-char C2 base URL
   (DECODE 0x16ed0/36 → `NewStringUTF` vtbl[334]); `x0016d3b9 ()String` @0x40234 returns
   `topfollow_check.php` (two identical branches).

**(b) Production IG API client — `x0018d3f7 (I) → Retrofit` @ 0x7a3ac (7,392 B)**
1. DECODE 31-char base (0x17230, two branches 0x7b4d8/0x7b560) + 47-char (0x172de via
   0xc8310 at 0x7c014).
2. PINNER ×1; client helpers 0xc99a0 / 0xbd88c / 0xc9b1c (timeouts/interceptors).
3. 12× `0x3d0e0` gated per-byte transforms (parameter encoding).

**(c) Order → request URL — `x0011f1a2 (Order) → String` @ 0x65338 (10,848 B)**
1. DECODE base31 (0x17230) → T1 (e.g. `https://i.instagram.com/api/v2/`-class path).
2. Branch on order type: DECODE `friendships/create/` (0x17208) / `media/` (0x1721b ×4
   sites) / `comment/` (0x17227).
3. `STR_CONCAT` ×9 (0x38f60) — e.g. 0x66954: `dst = a + "media/"`.
4. 14× `0x3d0e0` → `0x3c9e8` per-byte transform (query-parameter encoding).
5. Each decode is wrapped in a **counter-guard MBA loop** (see §14.5): mismatch → `b .`
   infinite trap at 0x66384/0x66b40 etc.

**Endpoint inventory (assembled from the decoded set):**
`https://i.instagram.com/api/v2/` + `friendships/create/` · `media/` · `comment/` ·
`create_note/v2/` · `seen/` · `/save/` — plus C2 `https://nivafollower…` +
`topfollow_check.php`, host pinned to `nivafollower.app`.

### 14.4 Header / signing & response construction

**JNI symbol pool** (plain, 0x15f00–0x17100 — the app's native→Java surface):

- JSON fields (Gson `JsonObject.addProperty(String,String)`):
  `order_id`, `order_stamp2`, `follower_count`, `following_count`, `family_device_id`,
  `hash_key`, `hash_type`, `url`, `token`, `type`, `base`, `currentInstagram`,
  `account_type`, `request`; quoted literals `"hash_key"`, `"hash_type"`;
  `errorBody` (okhttp); `setHash_type`; `addDevice` (DB).
- Models: `com/nivaroid/topfollow/models/Order`, `…/models/InstagramAccount`,
  `…/db/MyDatabase`, `…/helper/T`; Gson ctor
  `(JsonObject, InstagramAccount, Order)`.
- **Signing**: `java/security/MessageDigest.getInstance("SHA-256")` is invoked from
  native — the hash_key/hash_type values are computed server-side and re-verified
  client-side; `x0014c1f9 (Response) → String` @0x73f48 parses the response body
  (`()Lokhttp3/ResponseBody;` / `errorBody`), runs the decrypt/verify pipeline
  (GATE ×10, `0x3b4d4` ×15, `0xe8fe4` ×12, `0x9346c` ×4), and returns the result string.
- `x00113f7a () → String` @0x73ca8 returns a **36-char runtime token**
  (DECODE 0x17277 + GATE + 2 JNI calls).

**Big response handler — `x0015e49c (Response, Order, …) → String` @ 0x67d98 (48,456 B,
12,114 insns):**
- 269 `0x0e89fc` flag-checks, 26 CONCAT, 26 GATEWRAP, 12 DECODE (base31 ×5, friend19 ×2,
  media6, comment9…), 11 `0xe8b30` ctx-builds (→ CRYPTO_B), 3× CRYPTO-C `0x87690`,
  **10× `0x923c0` (b64+zlib embedded-payload installer)**.
- JNI: `NewStringUTF` ×20, `PopLocalFrame` ×20, `CallIntMethod` ×10,
  `GetStringChars` ×6, `GetStringRegion` ×5, `GetArrayLength` ×2.
- Saves results via `MyDatabase` (`add`/`addDevice`).

### 14.5 Anti-tamper state machine (new, quantified)

- **Pointer cache page** 0x10e080–0x10ff00: 158 slots (`.got`-region), initialized in
  JNI_OnLoad (0xcb000s). Holds pointers to the global counters + cached JNI refs.
- **Hot counter slots**: 0x10ee90 (178 refs), 0x10ee98 (79), 0x10efd0 (110), 0x10efd8
  (80), 0x10eec0 (49), 0x10eef0 (88).
- **GATE `0x37160`** (and every function prologue): loads counter pair (A, B) through
  the cache; computes MBA `A·(A−1)`, `xor 0xfffffffe`, `tst`; requires **B ∈ {9, 10}**
  (`cmp w, #9`/`#0xa`). Fail → trap. This makes every call **order-sensitive**: the
  global call-counter must sit at the expected epoch.
- **Central flag checker `0x0e89fc`**: `ldrb w8,[x0]; tbnz w8,#0,→trap; ret` — bit 0 of a
  .bss compromise flag. **1,956 call sites** poll it.
- **146 self-loop traps** (`b .`); guard counters e.g. 0x66374–0x66384 (URL builder).
- Direct counter bumps found at 0xcf800, 0xd2b30, 0xd31a4, 0xd3920, 0xe0a4c
  (detection counters); the call-epoch counter is advanced indirectly (hub/ctors).
- **APK integrity**: expected SHA-256 =
  `d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e`, stored at 0x14ce4
  as `b64(b64(hex))` (120 B). Verified by 0x7c08c/0xbdb68. Because it is **data**, a
  runtime rewrite of the 120-byte blob to our re-signed APK's hash is the least invasive
  bypass (B6) — no code patching of the verifier required.

### 14.6 Agent implications (hook-table deltas)

- Hook `0x86684` (post-call read of `x8`) to capture the four registry strings
  (31/31/36/47) and the 36-char C2 base — closes old O3 at runtime.
- All hooks must stay **non-invasive** (log-only): any hook that skips, reorders or
  re-enters a gated native desyncs the call-epoch counter → silent `b .` hang.
- B6 strategy: patch the 120 B blob at 0x14ce4 (data) instead of NOPing verifiers.
- Detection tokens added: `lsposed`, `rwxp`, `libart.so (deleted)`, `libbc.so (deleted)`,
  `HbF0Nh5lp`, `79dc69a2c79d`.
