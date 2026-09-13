# TopFollow v8.4.5-Beta — Threat Model

**Target:** `com.nivaroid.topfollow` · versionCode 845 · 8.4.5-Beta
**APK SHA-256:** `a60bcf064d0907072712a16398968d2f50c6802fc0d56fb60139030a98701a04`
**Backend:** `https://top.nivafollower.app/v840/` (server-rotatable at runtime)
**Companion document:** [`TopFollow_Security_Analysis.html`](TopFollow_Security_Analysis.html) — full findings register, evidence and PoCs

---

## 1. System overview

TopFollow is a follower-exchange service. A user surrenders an Instagram
credential; the app then drives that account to follow, like, comment on, save
and view other users' content in exchange for **coins**; coins are spent to buy
engagement for the user's own account. A premium **gem** currency and a **VIP**
tier sit alongside it.

Three trust domains share one process:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        TopFollow client process                          │
│                                                                          │
│  ┌────────────────────┐   ┌─────────────────────┐   ┌────────────────┐   │
│  │  DOMAIN A          │   │  DOMAIN B           │   │  DOMAIN C      │   │
│  │  Vendor backend    │   │  Instagram          │   │  Local storage │   │
│  │                    │   │                     │   │                │   │
│  │  ha.h / ha.k       │   │  ia.q.l(0|1|2)      │   │  Room DB       │   │
│  │  q.k() -> Retrofit │   │  q.l() -> Retrofit  │   │  t_f_d_b_f_v_c │   │
│  │  26 .php endpoints │   │  ia.g / ja.e worker │   │  TOPFVC_Shared │   │
│  │  d.t() headers     │   │  ia.q.f() headers   │   │  (unencrypted) │   │
│  └─────────┬──────────┘   └──────────┬──────────┘   └───────┬────────┘   │
│            │                         │                      │            │
│            └─────────── libtopfollow.so (22 JNI fns) ────────┘            │
└──────────────────────────────────────────────────────────────────────────┘
```

Domain C holds the assets that Domains A and B both consume. There is **no
isolation between them** — one hook or one MITM reaches all three
(TRAN-05).

---

## 2. Assets

| Asset | Where it lives | Protection in place | Actual strength |
|---|---|---|---|
| **Instagram password** | `instagram_accounts.u_w`, `two_factors.u_p` | `glide.d.q()` | **Keyless** 4-stage byte transform — re-implemented and round-tripped in Python. Not encryption. |
| **TOTP / 2FA seed** | `two_factors.s_k` | same | Same. Permanently defeats 2FA. |
| **Instagram OAuth bearer** | `instagram_accounts.u_a` | same | Synthesised from stolen WebView cookies as `Bearer IGT:2:<base64({ds_user_id,sessionid})>` |
| **Instagram session token** | `instagram_accounts.token` | none | Sent to the vendor in a plaintext `Token:` header on every backend call |
| **Coin / gem balance** | `device.coin`, `device.gem` | none | Local unencrypted SQLite row; also the client's own affordability oracle |
| **Backend base URL + pin** | `TOPFVC_Shared` → `Pin`, `PinActive` | `glide.d.q()` | **Supplied by the network** via ServerCheck — the trust anchor is remotely writable |
| **Device identity** | `Aid`, `DeviceId`, `RD`, `device.hash_key`, `device.nonce`, `fcm_token` | partial | Persistent cross-install fingerprint, uploaded |
| **Integrity token** | `RD`, `RIT`, `AIT` | none | Cached 6 h, replayable, predictable nonce |
| **Instagram platform integrity** | — | — | Attacked by the product itself: forged nav-chains, human-behaviour simulation, multi-account farming |

---

## 3. Actors

| Actor | Capability | Route in | Findings |
|---|---|---|---|
| **Vendor operator** | Full server control, sees every request | *No exploit needed.* The app POSTs Instagram credentials to `instagramLogin.php` and sends the live session token in a `Token:` header by design. | CRED-04, CRED-05 |
| **Malicious user** (own device, rooted) | Frida, Magisk, `sqlite3`, file access | Force `get_coin="true"`; inflate `device.coin`; replay the static `x4`; rewrite `order_value`. | BIZ-01, BIZ-02, BIZ-03, BIZ-06 |
| **Network attacker** (same Wi-Fi, rogue AP, hostile CDN) | TLS MITM | Hook `CertificatePinner.check` (Java-side — the `.so` has no TLS code), or simply wait for ServerCheck to hand over a fresh pin. | TRAN-01, TRAN-02, CRYP-04, CRYP-05 |
| **Local attacker** (stolen phone, forensic tool) | Read app data | Open `t_f_d_b_f_v_c` with `sqlite3`; invert the keyless cipher. No root needed if the backup path is used. | STOR-01, CRYP-01 |
| **Google-account attacker** | Cloud restore / D2D migration | `allowBackup=true` and **both** backup-rule resources are empty, so the credential DB restores onto their device. | STOR-02 |
| **Repackager** | Modify + re-sign the APK | Hook `MessageDigest.digest()` to return `d845591e…`, or patch the embedded constant. | INTE-01, CRYP-02, INTE-12 |
| **Instagram** (defender) | Abuse detection, bans | Every user presents an identical hard-coded device fingerprint, `x-ig-app-id` and bloks version — trivially mass-bannable. | CRED-06, CRED-07, CRED-08 |
| **The end user** (victim) | None | Surrenders a password or session, is never re-asked for consent, is automated on indefinitely. | CRED-01, STOR-15, BIZ-08 |

---

## 4. Trust boundaries

### Boundary 1 — credential surrender (User → Vendor)

The user types an Instagram password into TopFollow, or logs in through an
in-app WebView whose cookies the app then reads. The credential crosses from
the user's control into a third party's, with **no OAuth, no scoping and no
expiry**.

*Crossed by:* `ia.v.a()` storing `u_w`; `oa.l1.onPageFinished()` lifting
`sessionid`/`ds_user_id`; `ha.b` case 0 POSTing `instagramLogin.php`.
*Verdict:* **broken by design.** The vendor holds long-term credentials for the
entire user base.

### Boundary 2 — private-API impersonation (Client → Instagram)

The client presents itself as `Instagram 369.0.0.46.101 Android
(33/13;420dpi;1080x2269;samsung;SM-E625F;f62;exynos9825;en_US;785863906)` with
`x-ig-app-id: 567067343352427` and a fixed `x-bloks-version-id`, and fabricates
`x-ig-nav-chain` / `x-ig-salt-ids` / `x-fb-rmd` per request to look organic. A
warm-up burst with jittered timestamps precedes each action.

*Crossed by:* `ia.q.f()`, `ja.e.b()`, `ia.x`.
*Verdict:* **hostile.** This boundary exists to be deceived; the deception is
the product.

### Boundary 3 — URL and pin injection (Network → Client) ← **the structural flaw**

```
ServerCheck response {url, pin, pin_active, repair_mode, update_available, update_url}
        │
        ▼   com.bumptech.glide.manager.r
SharedPreferences  "Pin" = d.q(url)      "PinActive" = pin_active
        │
        ▼   ha.h
helper.q.k( d.p(SP"Pin"), SP"PinActive" )   →  libtopfollow.so!x00126f7c
        │
        ▼
OkHttpClient + CertificatePinner + Retrofit  →  every backend call
```

The app takes its **transport trust anchor from the network it is supposed to
be defending against**. Whoever controls one ServerCheck response controls
Boundaries 1 and 2 as well, because the redirect carries the Instagram
password and session token with it — and the attacker's certificate is pinned
as trusted before the first request is made.

*Verdict:* **inverted.** A pin must be a build-time constant.

---

## 5. Attack surface inventory

### 5.1 Network — 26 backend endpoints

Base `https://top.nivafollower.app/v840/`. Seven paths are single-layer base64
obfuscated and were decoded from DEX literals.

| Path | Discovery | Purpose |
|---|---|---|
| `order/submitOrder.php` | base64 | Place an order (spend coins). Carries `set_order_stamp`. |
| `order/syncOrder.php` | literal | **Claim coins.** Carries `x4,x5,x6,x7,get_coin,order_value`. |
| `order/getSelfOrders.php` | literal | List own open orders |
| `order/getDefaultComment.php` | literal | Server-supplied comment text |
| `instagramLogin.php` | base64 | **Receives the IG login body** built by native `q.r()` |
| `getMainInfo.php` | base64 | Pushes `app_info`: `coin_per_*` rates, `min_*_order`, links |
| `account/checkCaptcha.php` | base64 | `captcha_stamp = q.c(token)` |
| `pre-login/setUpDevice.php` | base64 | First-run device registration |
| `pre-login/activeDevice.php` | base64 | Device activation |
| `pre-login/privacyPolicy.php` | base64 | Privacy gate before login |
| `account/getQuestions.php` | literal | 2FA challenge questions |
| `account/getSecretKey.php` | literal | TOTP / secret-key material |
| `account/requestDigitCode.php` | literal | Digit-code 2FA step |
| `account/upgradeAccountToVip.php` | literal | VIP upgrade (`vip_stamp`) |
| `account/getUpgradeStatus.php` | literal | Poll VIP status |
| `account/addCoupon.php` · `getCoupons.php` | literal | Coupon redemption / listing |
| `account/getGiftCodeReward.php` | literal | Gift-code reward |
| `account/checkDailyGift.php` · `getDailyItems.php` | literal | Daily reward (device clock) |
| `account/getInviteData.php` · `setInviteCode.php` | literal | Referrals |
| `account/getLeaderBoard.php` | literal | Leaderboard |
| `account/getMinerRequests.php` · `changeMinerRequest.php` | literal | Coin miners |
| `get_image.php` | literal | **Fetches a client-supplied `image_url`** — SSRF primitive |

All reached through one generic method: `ha.k.a(String path, HashMap headers,
RequestBody body)`.

Headers on every authenticated call (`com.bumptech.glide.d.t`):
`Content-Type`, `Version-Name: 8.4.5-Beta`, `Version-Code: 845`,
`Android-Name`, `Device-Language` (base64 locale), `Top-Language`,
`User-Agent` (native `q.b()`), `Top-Token` (device token), `Active-Id` (IG pk),
**`Token` (the live Instagram session token)**.

### 5.2 Network — Instagram

| Factory | Base URL | Use |
|---|---|---|
| `helper.q.l(0)` | `https://b.i.instagram.com/api/v1/` | private mobile API |
| `helper.q.l(1)` | `https://i.instagram.com/api/v2/` | private API v2 |
| `helper.q.l(2)` | `https://www.instagram.com/graphql/query` (+ `/`) | GraphQL / web path |

Also referenced: `direct_v2/has_interop_upgraded/`, `create_note/v2/` (Threads
notes), `seen/`, `/save/`, three Facebook `doc_id` GraphQL documents,
`attestation/create_android_keystore/`, and the token prefix
`3,IGbdd5f76a8fb9c4f86adf36a09f2750dc,{pk}`.

### 5.3 Native — 22 JNI functions

`libtopfollow.so` exports only `JNI_OnLoad`; everything else is reached via
`RegisterNatives`. On x86 the `JNINativeMethod` table sits at file offset
`0xd8fec` and all 22 resolved directly; the 64-bit builds construct it at
runtime, so `dynamic-lab/07_native_jni_dumper.js` intercepts `RegisterNatives`.

| Java | Native | Role |
|---|---|---|
| `q.a(String)` | `x0014b4f3` | IG-response transform → claim field `x5` |
| `q.b()` | `x0012f5b7` | backend User-Agent |
| `q.c(String)` | `x00105e9b` | `captcha_stamp` (captcha token signer) |
| `q.d()` | `x0016d3b9` | ServerCheck endpoint path |
| `q.e()` | `x0014e2e9` | response host/path verifier |
| `q.f()` / `q.g()` | `x0010e27f` / `x00113f7a` | reCAPTCHA / hCaptcha site keys |
| `q.h(Order)` | `x0011f1a2` | **Instagram `signed_body`** for every action |
| `q.i(JsonObject,String)` | `x00120b1e` | integrity + device-info injector |
| `q.j()` | `x0011a4c2` | native timestamp (integrity nonce) |
| `q.k(String,boolean)` | `x00126f7c` | **backend Retrofit + CertificatePinner** |
| `q.l(int)` | `x0018d3f7` | **bootstrap mega-function** — see below |
| `q.m()` | `x0011f42b` | `vip_stamp` |
| `q.n` / `q.o` | `x0011e28b` / `x0012d3e0` | cipher stage 1 (decrypt / encrypt) |
| `q.p(Resp,Order,Acct)` | `x0015e49c` | claim body part |
| `q.q(Response)` | `x0014c1f9` | claim field `x7` |
| `q.r(Json,UA,DevId)` | `x0015b1e9` | **`instagramLogin.php` body builder** |
| `q.s(String,String,String)` | `x0017b62c` | **`set_order_stamp`** |
| `q.t(Json,Acct,Order)` | `x0015a3b7` | **`order/syncOrder.php` body builder** |
| `q.u` / `q.v` | `x00135e2a` / `x0012e5a1` | account/device injectors |

**`x0018d3f7` responsibilities** (622 `.rodata` references resolved to it):
builds all three IG Retrofits; verifies the APK signature via
`getPackageInfo(GET_SIGNATURES)` → reflective `MessageDigest("SHA-256")`;
scans `/proc/self/maps`; probes nine `su` paths; reads `ANDROID_ID`,
`Build.DEVICE`, `Build.HARDWARE`; populates `DeviceModel`; calls
`CertificatePinner$Builder.add`.

Binary hardening is sound — FULL RELRO + `BIND_NOW`, stack canary, FORTIFY on
all three ABIs — and the library **does** implement its own AES-256 (forward
S-box `0x128b0`, inverse `0x139b0`, rcon `0x13b10`; proven by Unicorn execution:
112 S-box reads, **14 rcon reads** = AES-256, a 240-byte FIPS-197 schedule). But
there is **no TLS stack and no crypto *import*** (`DT_NEEDED` = libz/libandroid/
liblog/libm/libdl/libc), and the AES is not reachable from Java — none of the 22
JNI natives is `([B)[B`. So every *protection* executes by calling back into
Java, placing the entire integrity story on the wrong side of the JNI boundary.
The AES key is derived at runtime and matches no byte window of the 1.8 MB file
(5.4 M candidates brute-forced, zero hits), so it is recoverable only from live
memory (Frida script 09).

### 5.4 Local storage

Room DB `t_f_d_b_f_v_c`, opened with a plain builder — **no SQLCipher, no
`SupportFactory` passphrase, no Jetpack Security anywhere in the DEX.**

| Table | Sensitive columns |
|---|---|
| `device` | `coin`, `gem`, `hash_key`, `nonce`, `token`, `fcm_token` |
| `instagram_accounts` (42 cols) | **`u_w` (password)**, **`u_a` (bearer)**, `token`, `claim`, `rur`, `mid`, `fbid_v2`, `interop_messaging_user_fbid`, nav-chains, `collected_coins`, `is_vip`, `last_login` |
| `two_factors` | **`u_p` (password)**, **`s_k` (TOTP seed)** |
| `app_info` | `coin_per_*`, `min_*_order`, `action_delay`, `download_link`, `shop_link`, `support_link`, `channel_link` |

`TOPFVC_Shared`: `Pin`, `PinActive`, `Sign`, `RD`, `RID`, `SND`, `RIT`, `AIT`,
`Aid`, `DeviceId`, `ActiveID`, `ATFLogged`, `SingleTasking`, `NewTaskType`,
`Language`, `ShowShop`.

Backup: `allowBackup="true"` with `fullBackupContent` → `res/Qq.xml` =
`<full-backup-content/>` and `dataExtractionRules` → `res/4j.xml` =
`<data-extraction-rules><cloud-backup/></data-extraction-rules>`.
**Neither contains a single `<exclude>` element**, so the default
include-everything behaviour applies.

### 5.5 IPC / manifest

Only three exported components: `ui.TopActivity` (MAIN/LAUNCHER, unguarded),
`FirebaseInstanceIdReceiver` (guarded by `com.google.android.c2dm.permission.SEND`),
`ProfileInstallReceiver` (guarded by `android.permission.DUMP`). No deep links,
no exported services or providers. `TaskActionReceiver` and `DoTasksService`
are **not** exported. `usesCleartextTraffic="false"`; no
`networkSecurityConfig`. Permissions: INTERNET, FOREGROUND_SERVICE(_SPECIAL_USE),
POST_NOTIFICATIONS, ACCESS_NETWORK_STATE, WAKE_LOCK, c2dm.RECEIVE.

This is a genuinely small surface — the exposure is in the credential and money
logic, not in IPC.

### 5.6 WebView

`WebViewActivity` loads `https://www.instagram.com/` for the cookie-harvest
login path and renders hCaptcha from an embedded HTML template using
`https://js.hcaptcha.com/1/api.js`, exposing a `JSInterface` bridge with
`getConfig()`, `onPass(token)`, `onError()`, `onLoaded()`, `onOpen()`. A JS
bridge in a WebView holding a live Instagram session is a credential-exposure
channel; the captcha bridge lets a token be injected without solving anything.

---

## 6. Protection inventory — and how each one falls

| Control | Implementation | Bypass | Script |
|---|---|---|---|
| Signature self-check | `x0018d3f7` → `getPackageInfo(GET_SIGNATURES)` → reflective `MessageDigest("SHA-256")` → compare `d845591e…` | Hook `digest()` / `Signature.toByteArray()` | 01 |
| Play Store cert gate | `d8.f.a(Signature[])` vs Google's Phonesky pins | One-line hook → `true` | 01 |
| Anti-Frida / Xposed | `/proc/self/maps` keyword scan (XOR `0x5A`) + base64 Frida markers + `(deleted)` / `rwxp` heuristics + TCP 27042/27043 | Sanitise `read()`/`fgets()` line-by-line; neuter `strstr`/`strcmp`; refuse port connects | 01 |
| Root detection | nine hard-coded `su` paths via `open`/`access`/`stat`/`File.exists` | Force ENOENT; `exists()` → false | 01 |
| Emulator detection | `Build.DEVICE`, `Build.HARDWARE` | Overwrite the statics — the app already hard-codes SM-E625F for Instagram | 01 |
| Play Integrity | gate `SND==true && RID==3850153`; token cached 6 h; nonce `RD + q.j() + 877665803231`; sent as `x2` | Hook `SharedPreferencesImpl.getBoolean/getInt` | 01, 08 |
| Certificate pinning | OkHttp `CertificatePinner` built from native via JNI | Replace `check()` with a no-op | 02 |
| Native obfuscation | OLLVM CFF ×22, XOR `0x55`/`0x5A`, nested base64, scrambled DEX `map_list`, JNI-only exports | Resolve 943 PIC thunks → 760 data refs; brute-force 127 XOR keys; intercept `RegisterNatives` | 07 |
| Kill switches | `System.exit`, `Process.killProcess`, `Runtime.exit` | All suppressed | 01 |
| Local "encryption" | `glide.d.p()/q()` — XOR `0x6C` → rotl 3 → reverse → XOR `(i*37)^0xA5` | **Keyless.** Invert in Python. | 04 |

**Common thread:** every control is *detection*, executed in Java, over state
the client owns. None of them changes what the server is willing to trust.

---

## 7. Money path — where verification actually happens

```
 EARN                                            SPEND
 ────                                            ─────
 ja.e performs IG action                         UI: user picks count
   │                                               │
   ▼                                               ▼
 InstagramResponse (in-memory object)             cost = app_info.coin_per_X * count
   │                                               │
   ▼                                               ▼
 ha.c.onReady(JsonObject)                         if (device.coin < cost)
   │  get_coin = status=="ok" ? "true":"false"       buyButton.setOnClickListener(null)
   │  order_value = order.getOrder_value()        else
   │  x4 = "TFjMTZRk5rMHdTVR"   ← CONSTANT           buyButton.setOnClickListener(...)
   │  x5 = q.a(gson(response))  ← client-side        │
   │  x6 = order_stamp          ← server nonce       ▼
   │  x7 = response.getMessage()                   q.s(username, count, type)
   ▼                                                  → set_order_stamp
 POST order/syncOrder.php                             │
   │                                                  ▼
   ▼                                               POST order/submitOrder.php
 server credits coins
```

Four independent breaks on the earn side:

1. **`get_coin` is a client assertion** derived from an in-memory object's
   `getStatus()`. One Frida overload forces `"ok"` → the client claims payment
   for actions that failed or never ran. *(BIZ-01)*
2. **`order_value` — the payout amount — comes from the client's `Order`.**
   *(BIZ-02)*
3. **`x4`, the anti-replay token, is a compile-time constant**, identical on
   every install forever. *(BIZ-06, CRYP-03)*
4. **The whole payload is assembled on-device** by `q.t`/`q.i`/`q.u`/`q.v` with
   no server-issued per-attempt challenge. *(BIZ-07)*

And two on the spend side:

5. **Price is computed client-side** from a server-pushed rate × a
   client-chosen count. *(BIZ-03)*
6. **Affordability is checked against a local unencrypted SQLite row**, and the
   enforcement is a UI click-listener. *(BIZ-03, BIZ-05)*

The design *did* reach for replay protection — `order_stamp`, `order_stamp2`,
`order_stamp3` and `sign` are genuine server-issued nonces. It fails because
they authenticate the **order**, not the **completion**, and the money switch
sits outside all of them.

`set_order_stamp = q.s(username, order_count, type)` covers exactly three
fields. Balance, currency, account identity, timestamp and any server nonce are
all outside the signature — so a valid stamp proves nothing about whether the
buyer could pay. *(BIZ-04)*

---

## 8. Cryptographic material

| Constant | Value | Origin | Assessment |
|---|---|---|---|
| Pin / tamper digest | `d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e` | `.rodata` XOR `0x55` | **= SHA-256 of the APK signing certificate.** One constant doing two unrelated jobs; pins nothing about the server's TLS key. |
| Integrity constant | `d83fb7ce7f9a73922d2262ce3d7c8c78e4c1211da17f45b990a348d405b58677` | `helper/a0.x()` — literal concat + base64 | Matches no SHA-256 of the APK, DEX, `.so`, package name or backend URL. A bare comparison constant → patch-one-byte bypass. |
| Claim challenge `x4` | `TFjMTZRk5rMHdTVR` | `helper/a0.x4()` — `"VkVacVRW" + b64d(...) + "UldVZz09"`, double-decoded | **Static.** No device, time or server input. |
| Signing-cert SPKI pin | `sha256/4xnmMuV3jXL9RYz2ZVYtWWrkkv/6wSuz8SkHAHAV5Uo=` | derived | What a real OkHttp pin would look like — the app pins the cert digest instead. |
| GCP project | `877665803231` | `d3.d.l()` | Appended to the integrity nonce → nonce is predictable. |
| Integrity gate | `RID == 3850153`, `SND == true` | `d3.d.java:494` | Client-writable attestation switch. |
| Play Store pins | `8P1sW0EPJcslw7UzRsiXL64w-O50Ed-RBICtay1g24M`, `GXWy8XF3vIml3_MfnmSmyuKBpT3B0dWbHRR_4cgq-gA` | `d8.f.a()` | Google's own release / dev-key certs. |
| Keystore alias | `top_key_4286` | literal | Constant across installs; ECDSA P-256. |
| UUID literal | `3bbeeba8e-beaa-4458-ac60-6d9a61b2be9e` | `.rodata` XOR `0x55` | Malformed UUID beside a `sha256/` tail. |

Signing identity: self-signed RSA-2048, subject = issuer
`CN=Maryam Ahmadi, OU=Android Developer, O=NivaRoid, L=Shiraz, ST=Fars, C=IR`,
**serial 1**, valid 2023-12-15 → **2048-12-08**. No v1/JAR signature — v2
block only, plus a verity padding block.

---

## 9. Attack trees

### 9.1 Free engagement (money) — *malicious user*

```
GOAL: coins without performing Instagram actions
│
├─ Spawn with 01 + 02 so the bootstrap passes clean
├─ Attach 06
│   └─ Force InstagramResponse.getStatus() -> "ok"
│       └─ ha.c emits get_coin="true" for failed/never-run tasks
├─ (optional) Rewrite Order.getOrder_value() to choose the payout
├─ x4 is a constant -> nothing blocks replay
└─ POST order/syncOrder.php  ->  coins credited
    └─ Spend via 05: DeviceModel.getCoin() -> 999999999, Buy button live
```
**Cost:** one Frida overload. **Server-side signal:** none, unless the server
independently re-fetches the target's follower/like state.

### 9.2 Fleet-wide credential capture — *network attacker*

```
GOAL: Instagram passwords + session tokens for the whole user base
│
├─ Route A (opportunistic): MITM the device
│   └─ Attach 02 -> CertificatePinner.check() is a no-op
│       └─ Read the Token: header (live IG session) on every backend call
│
└─ Route B (clean, persistent): hijack ServerCheck      ← preferred
    ├─ Intercept the bootstrap response
    ├─ Set {url: attacker-host, pin: attacker-pin, pin_active: true}
    ├─ App writes SP "Pin"/"PinActive"
    ├─ ha.h rebuilds Retrofit via native q.k()
    └─ Every later call — including instagramLogin.php carrying the
       user's password — goes to the attacker, who is already pinned
```
**Why it works:** the transport trust anchor is network-supplied (Boundary 3).
Route B needs no device access at all beyond one response.

### 9.3 Offline credential theft — *no root, no device*

```
GOAL: passwords, bearers, TOTP seeds
│
├─ allowBackup=true, both rule files empty
├─ Cloud backup / D2D migration copies t_f_d_b_f_v_c + TOPFVC_Shared.xml
├─ sqlite3: select username, u_w, u_a from instagram_accounts;
│           select u_n, u_p, s_k from two_factors;
└─ Invert the keyless cipher (XOR 0x6C -> rotl3 -> reverse -> XOR (i*37)^0xA5)
```
**Attacker needs:** the Google account, or brief physical access during a
migration. **Never touches the app's runtime protections.**

### 9.4 Repackaging — *trojanised build*

```
GOAL: modified APK that passes every self-check
│
├─ Route A: spawn with 01
│   ├─ MessageDigest.digest() returns d845591e…
│   ├─ d8.f.a() returns true
│   ├─ maps / root / Frida probes filtered
│   └─ System.exit / killProcess suppressed
│
└─ Route B: static patch
    └─ Replace the embedded constant with your own cert digest (CRYP-02)
```

---

## 10. Risk summary

| Risk | Likelihood | Impact | Driver |
|---|---|---|---|
| Vendor-side mass account takeover | **Certain** (by design) | Critical | CRED-04, CRED-05 |
| Coin fraud / free engagement | **High** (one hook) | Critical | BIZ-01, BIZ-02, BIZ-06 |
| Fleet redirect via ServerCheck | Medium (needs MITM/CDN) | Critical | TRAN-02, CRYP-04, BIZ-12 |
| Offline credential theft via backup | Medium–High | Critical | STOR-02, STOR-01, CRYP-01 |
| Full MITM of IG + backend traffic | **High** (Java-side pinner) | High | TRAN-01, CRYP-05 |
| Mass Instagram bans of the user base | **High** | High | CRED-06, CRED-07, CRED-08 |
| Repackaged/trojanised build in the wild | Medium | High | INTE-01, CRYP-02, INTE-12 |
| SSRF against the vendor backend | Medium | Medium | STOR-05 |
| Privacy / tracking exposure | High | Medium | INTE-11, STOR-06, CRED-10 |

---

## 11. Existential risk — not fixable in code

These are properties of the product, not defects in its implementation:

- **Impersonating Instagram's private mobile API** (`b.i.instagram.com/api/v1/`,
  `i.instagram.com/api/v2/`, the Bloks/CAA login flow) violates Instagram's
  Platform Policy and Terms of Use. The hard-coded `x-ig-app-id`,
  `x-bloks-version-id` and device fingerprint make every user of the app
  trivially identifiable and bannable.
- **Forging `x-ig-nav-chain`, `x-ig-salt-ids` and `x-fb-rmd`**, plus a
  jittered warm-up burst, is engineered evasion of fraud detection. There is no
  legitimate framing for it.
- **Driving N user accounts in parallel from one device** for paid engagement
  is the product. `DoTasksService` + the `SingleTasking` flag is a farming
  engine by construction.
- **Automating DM interop and Threads** extends the abuse past follower
  exchange into cross-product manipulation, and exposes Facebook-side
  identifiers (`fbid_v2`, `interop_messaging_user_fbid`) that link the two
  accounts.

---

## 12. Priority remediation

**P0 — days.** Stop accepting Instagram passwords (remove `u_w`, `two_factors.u_p`/`s_k`,
`instagramLogin.php`); move to official OAuth with PKCE. Delete the `Token` and
`Active-Id` headers from `d.t()`. Remove the WebView cookie harvester. Set
`allowBackup="false"` or populate both rule files with real exclusions — a
one-line change closing an offline mass-exposure path. Encrypt Room with
SQLCipher under an AndroidKeyStore key.

**P1 — weeks.** Delete `get_coin` and `order_value` from the request; compute
rewards server-side. Verify completion independently by re-fetching the
target's state. Replace `x4` with a single-use server nonce bound to
`order_id` + attestation. Widen `set_order_stamp` to the canonical full body.
Enforce price and balance server-side. Add rate limits and server-issued
idempotency keys. Validate captcha tokens against the provider's siteverify API.

**P2 — weeks.** Hard-code the base URL and pins; remove `Pin`/`PinActive` from
SharedPreferences and `url`/`pin` from `ServerCheckModel`. Pin real SPKI values
with a backup pin and an expiry. Add `network_security_config.xml`. Ship
updates through Play's in-app update API. Separate the Instagram and backend
trust domains.

**P3 — months.** Move to Play App Signing; retire the serial-1 self-signed key
running to 2048. Make Play Integrity mandatory server-side with a random
per-request nonce and single-use tokens. Validate `appRecognitionVerdict` /
`deviceRecognitionVerdict` on the server. Treat maps/root/Frida detection as
telemetry for risk scoring, not as gates. Replace the keyless cipher
everywhere. Minimise data collection and gate Crashlytics behind consent. Parse
JSON properly instead of substring-matching login responses.

Full detail, finding by finding, in section 18 of the HTML report.

---

## 13. Guidance for users of this app

> **Change your Instagram password now and revoke the session.**
>
> This app has stored your password in a reversible form, may have forwarded it
> to a third-party server, may have uploaded it to your Google cloud backup,
> and has been acting on your account autonomously. Also: revoke third-party
> sessions in Instagram → *Accounts Center → Password and security → Where
> you're logged in*; re-enrol 2FA (the app may hold your current seed); and
> expect that the account may be actioned by Instagram for automation.

---

## 14. Scope & ethics

Defensive security research on a single APK supplied for analysis. **No
requests were sent** to `top.nivafollower.app`, to any Instagram endpoint, or
to any third party during this engagement. Everything documented comes from
static examination of the supplied binary plus instrumentation written for the
analyst's own device. No real user data appears in this repository. The
private-API detail is documented because it *is* the vulnerability surface —
not as a recipe; using it to automate accounts you do not own violates
Instagram's Terms of Use and, in many jurisdictions, computer-misuse law.
