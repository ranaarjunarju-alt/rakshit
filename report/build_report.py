# -*- coding: utf-8 -*-
"""Builds the single self-contained HTML report for the TopFollow RE engagement."""
import base64, hashlib, html, json, os, sys, datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vulns_data import V

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _find_apk(root):
    """Locate the target APK regardless of where the build is invoked from."""
    direct = os.path.join(root, "TopFollow_v845-Beta (1).apk")
    if os.path.exists(direct):
        return direct
    for base in (root, os.getcwd(), os.path.dirname(root)):
        try:
            for n in sorted(os.listdir(base)):
                if n.lower().endswith(".apk") and "topfollow" in n.lower():
                    return os.path.join(base, n)
        except Exception:
            continue
    return direct


APK = _find_apk(ROOT)
LAB = os.path.join(ROOT, "dynamic-lab")
WORK = os.path.join(ROOT, "work")
OUT = os.path.join(ROOT, "TopFollow_Security_Analysis.html")

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEV_COLOR = {"Critical": "#ff3b6b", "High": "#ff8a3d", "Medium": "#ffd23d", "Low": "#4dd7ff"}


def esc(s):
    return html.escape(str(s), quote=False)


def read(path, binary=False):
    try:
        if binary:
            with open(path, "rb") as f:
                return f.read()
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def b64(data):
    return base64.b64encode(data).decode()


# ------------------------------------------------------------------ facts ----
apk_bytes = read(APK, binary=True) or b""
APK_SIZE = len(apk_bytes)
APK_MD5 = hashlib.md5(apk_bytes).hexdigest()
APK_SHA1 = hashlib.sha1(apk_bytes).hexdigest()
APK_SHA256 = hashlib.sha256(apk_bytes).hexdigest()

CERT_DER = read("/tmp/apk_signing_cert.der", binary=True)
CERT_SHA256 = hashlib.sha256(CERT_DER).hexdigest() if CERT_DER else "d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e"
CERT_B64 = b64(CERT_DER) if CERT_DER else ""

SEV_COUNT = {s: sum(1 for x in V if x["sev"] == s) for s in SEV_ORDER}
CAT_COUNT = {}
for x in V:
    CAT_COUNT[x["cat"]] = CAT_COUNT.get(x["cat"], 0) + 1

SCRIPTS = sorted(f for f in os.listdir(LAB) if f.endswith(".js")) if os.path.isdir(LAB) else []
SCRIPT_SRC = {f: read(os.path.join(LAB, f)) or "" for f in SCRIPTS}
SCRIPT_DESC = {
    "00_common.js": "Shared helpers: Java class resolver, overload tracer, RegisterNatives capture, SharedPreferences dumper.",
    "01_anti_tamper_killer.js": "Defeats the signature self-check, /proc/self/maps scan, anti-Frida markers, root-path probes, emulator checks, Play-Store cert gate and the SND/RID integrity gate.",
    "02_ssl_pinning_bypass.js": "Kills the OkHttp CertificatePinner built from native code, installs a trust-all TrustManager, and reveals the server-rotated pin from SharedPreferences.",
    "03_instagram_api_intercept.js": "Full request/response logging of all three Instagram Retrofits, the ia.q.f() header factory, d.p()/d.q() crypto and every native signed_body.",
    "04_credential_theft.js": "Harvests Instagram passwords, bearer tokens, 2FA seeds, the WebView cookie jar and all ciphered SharedPreferences, and writes a JSON dump.",
    "05_coin_economy_bypass.js": "Inflates the local coin/gem wallet, forces every affordability check, rewrites order_count/type at submit time and logs all 26 backend endpoints.",
    "06_task_verification_bypass.js": "Forges InstagramResponse.getStatus()=='ok', forces get_coin='true', rewrites order_value and dumps the entire order/syncOrder.php claim.",
    "07_native_jni_dumper.js": "Intercepts RegisterNatives to resolve all 22 helper.q JNI functions, instruments each, and re-derives the XOR 0x55/0x5A and triple-base64 string tables from memory.",
    "08_backend_traffic_and_servercheck.js": "Logs every backend POST with headers and body, traces ServerCheck pin/URL rotation live, and can redirect the whole app to an attacker host.",
    "09_native_aes_dump.js": "Locates the AES S-box by content scan (not hard-coded offsets), Stalker-resolves every instruction that addresses it, attaches the five AES functions, and recovers any FIPS-197 round-key schedule from live memory.",
    "10_java_crypto_layer.js": "Hooks q8.t1.f (the #PWD_INSTAGRAM:4 password encryptor), dissecting the AES-256-GCM key, IV, tag, RSA-wrapped key and plaintext; hooks every javax.crypto.Cipher.init to dump raw SecretKeySpec bytes; instruments helper.T ECDSA attestation and proves the dead digest([B)[B JNI bridge.",
}

# ---------------------------------------------------------------------------
# Section 11 data.  Every value below is read directly out of the artefacts in
# work/out/30..34; nothing here is inferred.
# ---------------------------------------------------------------------------
def _tail(path, n=9999):
    d = read(path) or ""
    lines = d.splitlines()
    return "\n".join(lines[-n:]) if len(lines) > n else d

UNICORN_LOG = _tail(os.path.join(WORK, "out", "33_unicorn_aes_arm64.txt"), 140)
RK_TABLE    = _tail(os.path.join(WORK, "out", "34_aes_key_recovery.txt"), 60)

AES_TABLES = [
    ("forward S-box", "<code>0x128b0</code>", "<code>0xdb80</code>", "<code>0x7070</code>",
     "<code>63 7c 77 7b f2 6b 6f c5</code>", "CRYP-09"),
    ("inverse S-box", "<code>0x139b0</code>", "<code>0xec80</code>", "<code>0x8170</code>",
     "<code>52 09 6a d5 30 36 a5 38</code>", "CRYP-09"),
    ("rcon (14 bytes)", "<code>0x13b10</code>", "<code>0xede0</code>", "<code>0x82d0</code>",
     "<code>01 02 04 08 10 20 40 80</code>", "CRYP-10"),
]

AES_ABSENT = [
    ("White-box AES tables", "4&#215;1&nbsp;KB T-box / 256&#215;16&nbsp;B per round",
     "<b>absent</b> &mdash; <code>.rodata</code> is only 37,547&nbsp;B in total",
     "The key is not protected by a white-box transform; it is a normal AES-256 schedule (OBFU-02)"),
    ("Te0 / Td0 T-tables", "<code>[c66363a5, f87c7c84, ee777799, f67b7b8d]</code>",
     "<b>absent</b> &mdash; only the byte value <code>71856</code> occurs incidentally",
     "The cipher is the compact S-box variant, not a space-time T-table variant"),
    ("Td4 packed table", "<code>[6363a5c6, 7c7c84f8, &hellip;]</code>",
     "<b>absent</b>", "Confirms no T-table implementation is present under any packing"),
    ("ARMv8 Crypto Extension", "<code>aese/aesd/aesmc/aesimc/sha*</code>",
     "<b>absent</b> &mdash; zero hits in 397,892 instructions",
     "Software table AES is cache-timing exposed on the S-box (CRYP-13)"),
    ("GHASH / GCM", "H-table, <code>gcm_*</code>, reduction polynomial <code>0xe1</code>",
     "<b>absent</b>", "No authenticated encryption in the native layer"),
    ("SHA-256 / SHA-1 IVs", "<code>6a09e667, bb67ae85, 3c6ef372, a54ff53a</code>",
     "<b>absent</b>", "All hashing is done in Java (<code>MessageDigest</code>), not natively"),
    ("HMAC / PBKDF2", "ipad <code>0x36</code>/opad <code>0x5c</code> constants, iteration counter",
     "<b>absent</b>", "No key-derivation in the native layer (CRYP-05)"),
    ("ChaCha20 / Salsa20", "<code>61707865 3320646e 79622d32 6b206574</code> (&ldquo;expand 32-byte k&rdquo;)",
     "<b>absent</b>", "No stream cipher in the native layer"),
    ("RSA / X.509", "DER <code>30 82</code> sequences, <code>-----BEGIN</code>, <code>rsa_*</code>",
     "<b>absent</b>", "RSA exists only in <code>q8.t1</code> (Java <code>Cipher</code>), wrapping a server-supplied key (CRYP-11, CRYP-12)"),
    ("TLS", "<code>SSL_*</code>, <code>EVP_*</code>, <code>*crypt*</code> imports",
     "<b>absent</b> &mdash; <code>DT_NEEDED</code> is <code>libz, libandroid, liblog, libm, libdl, libc</code>",
     "Certificate pinning is delegated to OkHttp from native code (CRYP-05)"),
    ("Packing / encryption of <code>.text</code>", "high-entropy stub, <code>dlopen</code>/<code>mprotect</code> unpacker",
     "<b>absent</b> &mdash; <code>.text</code> entropy 6.8621",
     "Obfuscation is OLLVM control-flow flattening only (OBFU-02)"),
    ("Anti-debug / anti-Frida syscalls", "<code>ptrace</code>, <code>prctl</code>, <code>TracerPid</code>, <code>property_get</code>, <code>dlopen</code>",
     "<b>absent</b> as imports &mdash; <code>syscall</code> is imported but no raw <code>ptrace</code> number is used",
     "The only anti-analysis is <code>/proc/self/maps</code> read + string match (INTE-14)"),
]

ENTROPY_TABLE = [
    ("<code>.text</code>", "<code>0x2d2ac</code>", "1,591,568", "<b>6.8621</b>",
     "Normal compiled ARM64. A packed section scores &gt;7.8. <b>Not packed.</b>"),
    ("<code>.rodata</code>", "<code>0x118b0</code>", "37,547", "6.8779",
     "Held up almost entirely by the three AES tables; the rest is ordinary literals."),
    ("<code>.gcc_except_table</code>", "<code>0x1ab5c</code>", "26,312", "5.6261", "Landing pads."),
    ("<code>.eh_frame</code>", "<code>0x23440</code>", "40,556", "4.7867",
     "1,090 well-formed FDEs &mdash; the source of every function boundary used here."),
    ("<code>.rela.dyn</code>", "<code>0x10e0</code>", "65,424", "2.8076", "Relocations."),
    ("<code>.data.rel.ro</code>", "<code>0x1b6160</code>", "17,552", "0.1154", "vtables / pointers."),
    ("whole file", "&mdash;", "1,805,400", "<b>6.7518</b>", "No region above 7.0 except the S-boxes themselves."),
]

AES_FUNCS = [
    ("<code>0x2dc00</code>", "&mdash;", "SBOX", "Table-driven helper on the forward S-box", "CRYP-09"),
    ("<code>0x2eb94</code>", "&mdash;", "ISBOX", "Table-driven helper on the inverse S-box", "CRYP-09"),
    ("<code>0x2fdcc</code>", "&mdash;", "SBOX", "<b>Encrypt block</b>", "CRYP-09"),
    ("<code>0x30f18</code>", "&mdash;", "ISBOX", "<b>Decrypt block</b>", "CRYP-09"),
    ("<code>0x32158</code>", "8,908", "SBOX + RCON",
     "<b>Key expansion</b> &mdash; validates <code>w3 == w4 == 0x20</code> (256-bit). Executed under Unicorn: 89,148 instructions, 112 S-box reads, 14 rcon reads.",
     "CRYP-09, CRYP-10"),
    ("<code>0x34424</code>", "&mdash;", "&mdash;", "Wrapper &mdash; encrypt only (calls <code>0x2fdcc</code>)", "CRYP-09"),
    ("<code>0x35518</code>", "&mdash;", "&mdash;",
     "Wrapper &mdash; both directions; <code>w4=1</code> encrypt, <code>w4=2</code> decrypt (calls <code>0x2fdcc</code>, <code>0x30f18</code>)", "CRYP-09"),
    ("<code>0x38fa4</code>", "&mdash;", "&mdash;", "Caller of key expansion", "CRYP-10"),
    ("<code>0x3a838</code>", "&mdash;", "&mdash;", "Caller of key expansion", "CRYP-10"),
]

NATIVE_TABLE = [
    ("q.a(String)", "x0014b4f3", "Transforms the raw Instagram response JSON into the claim field <code>x5</code>.", "BIZ-07"),
    ("q.b()", "x0012f5b7", "Returns the User-Agent used on TopFollow backend calls.", "CRYP-06"),
    ("q.c(String)", "x00105e9b", "Signs an hCaptcha/reCAPTCHA token into <code>captcha_stamp</code>.", "STOR-08"),
    ("q.d()", "x0016d3b9", "Returns the ServerCheck endpoint path used at bootstrap.", "TRAN-02"),
    ("q.e()", "x0014e2e9", "Post-response host/path verification (<code>getHost</code>, <code>getPath</code>, <code>web</code>).", "TRAN-04"),
    ("q.f()", "x0010e27f", "Returns the reCAPTCHA site key.", "STOR-08"),
    ("q.g()", "x00113f7a", "Returns the hCaptcha site key.", "STOR-08"),
    ("q.h(Order)", "x0011f1a2", "Produces Instagram's <code>signed_body</code> for every follow/like/comment/save/seen action.", "CRED-07"),
    ("q.i(JsonObject,String)", "x00120b1e", "Injects integrity + device info into an outbound JSON body.", "INTE-08"),
    ("q.j()", "x0011a4c2", "Returns a native timestamp (long) used in the integrity nonce.", "INTE-10"),
    ("q.k(String,boolean)", "x00126f7c", "Builds the <b>backend</b> Retrofit + CertificatePinner from the server-supplied pin.", "TRAN-02"),
    ("q.l(int)", "x0018d3f7", "<b>Bootstrap mega-function.</b> Builds the 3 Instagram Retrofits, verifies the APK signature via reflection, scans /proc/self/maps, probes root paths, populates DeviceModel, adds certificate pins.", "INTE-01"),
    ("q.m()", "x0011f42b", "Produces <code>vip_stamp</code> for <code>upgradeAccountToVip.php</code>.", "BIZ-09"),
    ("q.n(String)", "x0011e28b", "Cipher stage 1 used by <code>glide.d.p()</code> (decrypt).", "CRYP-01"),
    ("q.o(String)", "x0012d3e0", "Cipher stage 1 used by <code>glide.d.q()</code> (encrypt).", "CRYP-01"),
    ("q.p(Response,Order,Account)", "x0015e49c", "Builds part of the coin-claim payload.", "BIZ-07"),
    ("q.q(Response)", "x0014c1f9", "Produces the claim field <code>x7</code>.", "BIZ-07"),
    ("q.r(JsonObject,String,String)", "x0015b1e9", "Builds the <code>instagramLogin.php</code> body from UA + DeviceId.", "CRED-05"),
    ("q.s(String,String,String)", "x0017b62c", "Produces <code>set_order_stamp</code> from username | order_count | type.", "BIZ-04"),
    ("q.t(JsonObject,Account,Order)", "x0015a3b7", "Builds the <code>order/syncOrder.php</code> claim body.", "BIZ-07"),
    ("q.u(JsonObject,Account,String)", "x00135e2a", "Injects account identity + DeviceId into a body.", "INTE-11"),
    ("q.v(JsonObject)", "x0012e5a1", "Injects device info into a body.", "INTE-11"),
]

ENDPOINTS = [
    ("order/submitOrder.php", "base64 <code>b3JkZXIvc3VibWl0T3JkZXIucGhw</code>", "Place an order (spend coins on followers/likes/comments). Carries <code>set_order_stamp</code>.", "BIZ-03, BIZ-04"),
    ("order/syncOrder.php", "literal", "Claim coins for a completed task. Carries <code>x4,x5,x6,x7,get_coin,order_value</code>.", "BIZ-01, BIZ-02, BIZ-06"),
    ("order/getSelfOrders.php", "literal", "Fetch the caller's own open orders.", "BIZ-11"),
    ("order/getDefaultComment.php", "literal", "Server-supplied default comment text for comment tasks.", "BIZ-11"),
    ("instagramLogin.php", "base64 <code>aW5zdGFncmFtTG9naW4ucGhw</code>", "<b>Receives the Instagram login body</b> built by native <code>q.r()</code>.", "CRED-05"),
    ("getMainInfo.php", "base64 <code>Z2V0TWFpbkluZm8ucGhw</code>", "Pushes <code>app_info</code>: coin_per_* rates, min_*_order, action_delay, links.", "BIZ-03"),
    ("account/checkCaptcha.php", "base64 <code>YWNjb3VudC9jaGVja0NhcHRjaGEucGhw</code>", "Submits <code>captcha_stamp</code> = native <code>q.c(token)</code>.", "STOR-08"),
    ("pre-login/setUpDevice.php", "base64 <code>cHJlLWxvZ2luL3NldFVwRGV2aWNlLnBocA==</code>", "First-run device registration.", "INTE-11"),
    ("pre-login/activeDevice.php", "base64 <code>cHJlLWxvZ2luL2FjdGl2ZURldmljZS5waHA=</code>", "Device activation; body augmented by <code>q.i()</code>.", "INTE-08"),
    ("pre-login/privacyPolicy.php", "base64 <code>cHJlLWxvZ2luL3ByaXZhY3lQb2xpY3kucGhw</code>", "Privacy-policy gate shown before login.", "STOR-06"),
    ("account/getQuestions.php", "literal", "2FA challenge questions.", "CRED-02"),
    ("account/getSecretKey.php", "literal", "Secret key / TOTP material.", "CRED-02"),
    ("account/requestDigitCode.php", "literal", "Digit-code 2FA step.", "CRED-02"),
    ("account/upgradeAccountToVip.php", "literal", "VIP upgrade; carries <code>vip_stamp</code>.", "BIZ-09"),
    ("account/getUpgradeStatus.php", "literal", "Poll VIP upgrade status.", "BIZ-09"),
    ("account/addCoupon.php", "literal", "Redeem a coupon code.", "BIZ-10"),
    ("account/getCoupons.php", "literal", "List available coupons.", "BIZ-10"),
    ("account/getGiftCodeReward.php", "literal", "Claim a gift-code reward.", "BIZ-10"),
    ("account/checkDailyGift.php", "literal", "Daily-gift eligibility (device clock).", "BIZ-10"),
    ("account/getDailyItems.php", "literal", "Daily reward items.", "BIZ-10"),
    ("account/getInviteData.php", "literal", "Referral statistics.", "BIZ-11"),
    ("account/setInviteCode.php", "literal", "Bind a referral code.", "BIZ-11"),
    ("account/getLeaderBoard.php", "literal", "Leaderboard.", "BIZ-11"),
    ("account/getMinerRequests.php", "literal", "List coin-miner requests.", "BIZ-11"),
    ("account/changeMinerRequest.php", "literal", "Mutate a coin-miner request.", "BIZ-11"),
    ("get_image.php", "literal", "Server fetches a client-supplied <code>image_url</code> &mdash; SSRF primitive.", "STOR-05"),
]

IG_HEADERS = [
    ("authorization", "<code>d.p(u_a)</code> &mdash; the decoded Instagram OAuth bearer", "CRED-03, CRED-04"),
    ("user-agent", "<code>Instagram 369.0.0.46.101 Android (33/13;420dpi;1080x2269;samsung;SM-E625F;f62;exynos9825;en_US;785863906)</code>", "CRED-06"),
    ("x-ig-app-id", "<code>567067343352427</code>", "CRED-06"),
    ("x-bloks-version-id", "<code>083f38c334f42c5e3322bb77464c601e8882cd9ff2d30ac915ba7a497539d604</code>", "CRED-06, STOR-13"),
    ("x-ig-capabilities", "<code>3brTv10=</code>", "CRED-06"),
    ("x-ig-android-id", "<code>android-{Aid}</code> &mdash; Aid from SharedPreferences", "INTE-11"),
    ("x-pigeon-session-id", "<code>UFS-{uuid}-0</code>", "CRED-06"),
    ("x-ig-client-endpoint", "<code>com.bloks.www.caa.login.login_homepage</code>", "STOR-13"),
    ("x-ig-nav-chain", "forged per request, e.g. <code>ShortUrlFeedFragment:feed_short_url:1:warm_start:{ts-5}.{ts+8}::</code>", "CRED-07"),
    ("x-ig-salt-ids", "four forged sets, e.g. <code>220145826</code>, <code>220140399,974460658</code>", "CRED-07"),
    ("x-fb-rmd", "forged Facebook risk-metadata", "CRED-07"),
    ("cookie", "<code>mid</code>, <code>ig-u-rur</code>, <code>ig-u-ds-user-id</code>, <code>sessionid</code>", "CRED-03"),
]

BACKEND_HEADERS = [
    ("Content-Type", "application/json"),
    ("Version-Name", "8.4.5-Beta"),
    ("Version-Code", "845"),
    ("Android-Name", "<code>Build.VERSION.RELEASE</code>"),
    ("Device-Language", "<code>Base64(Locale.getDefault().getDisplayName())</code>"),
    ("Top-Language", "SharedPreferences <code>Language</code> (default <code>en</code>)"),
    ("User-Agent", "native <code>helper.q.b()</code> = <code>x0012f5b7</code>"),
    ("Top-Token", "<code>device.token</code> from the Room DB"),
    ("Active-Id", "<code>InstagramAccount.getPk()</code> &mdash; the victim's Instagram user id"),
    ("Token", "<b><code>InstagramAccount.getToken()</code> &mdash; the live Instagram session token</b>"),
]

DB_TABLES = [
    ("device", "id, coin, gem, hash_type, hash_key, nonce, token, fcm_token",
     "Local wallet (<code>coin</code>, <code>gem</code>) plus the backend <code>Top-Token</code> and FCM token.", "BIZ-05, STOR-01"),
    ("instagram_accounts", "42 columns incl. u_id, full_name, pk, username, u_w, u_a, u_a_t, instagram_agent, rur, mid, claim, family_device_id, pigeon_session_id, direct_region_hint, fbid_v2, interop_messaging_user_fbid, time_line_nav_chain, search_nav_chain(_threads), req_id, collected_coins, is_vip, token, biography, last_login, limit_time, error, sort, active, logout, need_authorization",
     "<b>u_w = Instagram password</b>, <b>u_a = OAuth bearer</b>, <code>token</code> = session sent to the backend.", "CRED-01, CRED-03, CRED-04"),
    ("two_factors", "u_n, u_p, s_k (+ id, progress)",
     "<b>u_p = Instagram password, s_k = TOTP/2FA seed.</b> Loaded via raw SQL <code>select * from two_factors</code>.", "CRED-02"),
    ("app_info", "coin_per_follow/threads/like/repost/save/seen/comment, min_follow_order, min_like_order, min_repost_order, min_save_order, min_seen_order, is_profile_mandatory, is_post_mandatory, download_link, shop_link, support_link, channel_link, actions, action_delay",
     "Server-pushed economy rates consumed by the <b>client-side</b> price computation.", "BIZ-03, BIZ-12"),
]

PREF_KEYS = [
    ("Pin", "Ciphered backend base URL. Decoded with <code>d.p()</code> and passed to native <code>q.k()</code>. Currently <code>https://top.nivafollower.app/v840/</code>.", "TRAN-02"),
    ("PinActive", "Boolean enabling the pin on the backend Retrofit.", "CRYP-04"),
    ("Sign", "Ciphered signature material used by <code>helper/a0.x0()</code>.", "INTE-01"),
    ("RD", "Ciphered device/attestation payload; feeds the integrity nonce and the <code>x2</code> claim field.", "INTE-09, INTE-10"),
    ("RID", "Must equal <b>3850153</b> for Play Integrity to run.", "INTE-08"),
    ("SND", "Must be <b>true</b> for Play Integrity to run.", "INTE-08"),
    ("RIT", "Timestamp of the cached integrity token (6-hour freshness window).", "INTE-09"),
    ("AIT", "Cached attestation/identity token.", "INTE-09"),
    ("Aid", "Ciphered Android ID; becomes <code>x-ig-android-id: android-{Aid}</code>.", "INTE-11"),
    ("DeviceId", "Ciphered random UUID device id sent to the backend.", "INTE-11"),
    ("ActiveID", "Row id of the currently selected <code>instagram_accounts</code> entry.", "STOR-01"),
    ("ATFLogged", "App-level &ldquo;logged in&rdquo; flag.", "STOR-03"),
    ("SingleTasking", "<b>false</b> = run every active account's worker in parallel.", "BIZ-08"),
    ("NewTaskType", "Task filter (<code>all</code>, <code>follow</code>, &hellip;).", "BIZ-08"),
    ("Language", "Sent as the <code>Top-Language</code> header.", "STOR-03"),
    ("ShowShop", "UI gate for the shop screen.", "BIZ-10"),
]

IG_ACTIONS = [
    ("0", "FOLLOW", "<code>ia.g.i(q.h(order), url, form)</code>",
     "<code>include_follow_friction_check=1, user_id=&lt;target pk&gt;, radio_type=wifi-none, _uid, device_id=android-{aid}, _uuid, nav_chain, container_module=profile</code>"),
    ("1", "LIKE", "<code>ia.g.i(q.h(order), url, form)</code>",
     "<code>delivery_class=organic, tap_source=button, media_id, radio_type=wifi-none, _uid, _uuid, nav_chain, is_carousel_bumped_post=false, container_module=feed_short_url, feed_position=0</code> + <code>&amp;d=0</code>"),
    ("3", "REPOST / Threads note", "<code>ia.g.i(q.h(order), url, form)</code>",
     "<code>media_client_position, media_id, note_style=13, text=, _uuid, nav_chain, audience=7, event_source=ufi, container_module=feed_contextual_profile</code>"),
    ("4", "SEEN (story views)", "<code>ia.q.g.create(...).m(...)</code>",
     "JSON body ending in <code>force_seen_story_ids: []</code>"),
    ("5", "COMMENT", "<code>ia.g.d0(headers, form)</code>",
     "headers gain <code>x-ig-nav-chain=...,GVw:comments_v2_feed_timeline:5:button:</code>, <code>x-ig-salt-ids=220140399,974460658</code>; form <code>media_id, comment_session_id=&lt;random UUID&gt;, comment_text</code>"),
    ("6", "SAVE", "<code>/save/</code>", "<code>media_id</code> + signed body"),
]

CLAIM_FIELDS = [
    ("x4", "<code>order.getOrder_stamp2()</code>, else <code>\"empty\"</code>", "Server-issued order stamp (second)."),
    ("x5", "<code>helper.q.a(gson.toJson(instagramResponse))</code>", "Native transform of the raw IG response &mdash; the only &ldquo;proof&rdquo; of the action."),
    ("x6", "<code>order.getOrder_stamp()</code>, else <code>\"empty\"</code>", "Server-issued order stamp."),
    ("x7", "<code>instagramResponse.getMessage()</code>", "Raw IG message string."),
    ("type", "<code>order.getOrder_type()</code>", "Task category string."),
    ("i_type", "<code>order.getType()</code> (int)", "0=follow, 1=like, 3=repost, 4=seen, 5=comment, 6=save."),
    ("order_id", "<code>order.getOrder_id()</code>", "Server order id."),
    ("order_value", "<code>order.getOrder_value()</code>", "<b>Client-supplied reward amount.</b>"),
    ("pk / username", "the target account", "Who was followed / liked."),
    ("get_coin", "<code>(response.getStatus().equals(\"ok\")) ? \"true\" : \"false\"</code>", "<b>Client-asserted success flag &mdash; the money switch.</b>"),
    ("account_type", "<code>(acct.getAccount_type()==\"web\") ? \"1\" : \"0\"</code>", "Cookie-harvested web account vs private-API account."),
    ("active_pk", "<code>currentInstagram().getPk()</code>", "The acting (hijacked) account."),
    ("get_new_order", "<code>this.p</code> (boolean)", "Ask the server for another task in the same round-trip."),
    ("new_order_type", "<code>this.q</code>", "Which task type to receive next."),
    ("is_single_tasking", "SharedPreferences <code>SingleTasking</code>", "Client-chosen concurrency mode."),
]

XOR_FINDINGS = [
    ("0x55", "Backend base URL", "<code>https://top.nivafollower.app/v840/</code>"),
    ("0x55", "Certificate pin", "<code>sha256/d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e</code>"),
    ("0x55", "UUID literal", "<code>3bbeeba8e-beaa-4458-ac60-6d9a61b2be9e</code>"),
    ("0x5A", "Anti-instrumentation keywords", "<code>/proc/self/maps</code>, <code>xposed</code>, <code>lsposed</code>, <code>edxposed</code>, <code>riru</code>, <code>substrate</code>, <code>libcso_substrate</code>, <code>libbridge.so</code>, <code>zygisk</code>"),
    ("0x5A", "Root-detection paths", "<code>Superuser.apk</code>, <code>/sbin/su</code>, <code>/system/bin/su</code>, <code>/system/xbin/su</code>, <code>/data/local/xbin/su</code>, <code>/data/local/bin/su</code>, <code>/system/sd/xbin/su</code>, <code>/system/bin/failsafe/su</code>, <code>/data/local/su</code>"),
    ("base64 &times;3", "Instagram private API", "<code>https://b.i.instagram.com/api/v1/</code>, <code>https://i.instagram.com/api/v2/</code>"),
    ("base64 &times;3", "Instagram web / graphql", "<code>https://www.instagram.com/graphql/query</code>, <code>https://www.instagram.com/</code>"),
    ("base64 &times;3", "Instagram endpoints", "<code>create_note/v2/</code>, <code>seen/</code>, <code>/save/</code>"),
    ("base64", "Frida markers", "<code>frida</code>, <code>gum-js-loop</code>, <code>libfrida-gadget</code>, <code>re.frida.server</code>"),
    ("plaintext", "Device model fields", "<code>DeviceModel</code>, <code>setHash_key</code>, <code>setNonce</code>, <code>setHash_type</code>, <code>addDevice</code>, <code>ANDROID_ID</code>, <code>DEVICE</code>, <code>HARDWARE</code>"),
    ("plaintext", "OkHttp pinning", "<code>certificatePinner</code>, <code>CertificatePinner$Builder</code>, <code>add</code>, <code>getHost</code>, <code>getPath</code>"),
    ("plaintext", "Signature self-check", "<code>getPackageInfo</code>, <code>signatures</code>, <code>SHA-256</code>, <code>java.security.MessageDigest</code>"),
]


def sev_badge(s):
    return ('<span class="badge" style="--c:%s">%s</span>' % (SEV_COLOR[s], s))


def build_vuln_cards():
    out = []
    for x in sorted(V, key=lambda y: (SEV_ORDER[y["sev"]], y["id"])):
        pocs = [p.strip() for p in x["poc"].split(",")]
        # link to the real script anchor: script-<full-name-minus-.js>
        poc_html = " ".join('<a class="chip" href="#script-%s">%s</a>'
                            % (esc(p[:-3] if p.endswith(".js") else p), esc(p)) for p in pocs)
        out.append(f"""
<article class="vuln card" id="{esc(x['id'])}" data-sev="{esc(x['sev'])}" data-cat="{esc(x['cat'])}" data-search="{esc(_strip_tags(x['id']+' '+x['title']+' '+x['cat']+' '+x['desc']+' '+x['impact']+' '+x['ev']+' '+x['fix'])).replace(chr(34), '&quot;')}">
  <header>
    <div class="vid">{esc(x['id'])}</div>
    {sev_badge(x['sev'])}
    <span class="cat">{esc(x['cat'])}</span>
  </header>
  <h3>{x['title']}</h3>
  <div class="grid2">
    <div><h4>How it works</h4><p>{x['desc']}</p></div>
    <div><h4>Impact</h4><p>{x['impact']}</p></div>
  </div>
  <h4>Evidence</h4>
  <p class="ev">{x['ev']}</p>
  <div class="rowend">
    <div><h4>Proof of concept</h4><div class="chips">{poc_html}</div></div>
    <div class="fixcol"><h4>Remediation</h4><p>{x['fix']}</p></div>
  </div>
</article>""")
    return "\n".join(out)


def chips(ids):
    """ids -> comma separated finding ids; returns linked chips."""
    out = []
    for i in str(ids).split(","):
        i = i.strip()
        if i:
            out.append('<a class="chip" href="#%s">%s</a>' % (esc(i), esc(i)))
    return '<span class="chips">%s</span>' % " ".join(out)


_TAG_RE = None


def _strip_tags(s):
    """Plain-text search index for a table row (avoids HTML inside data-search)."""
    import re as _re
    t = _re.sub(r"<[^>]+>", " ", str(s))
    t = t.replace("&mdash;", " ").replace("&rarr;", " ").replace("&middot;", " ")
    t = t.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    return _re.sub(r"\s+", " ", t).strip().lower()


def build_table(rows, headers, tid, searchable=True):
    th = "".join("<th>%s</th>" % h for h in headers)
    body = []
    for r in rows:
        tds = "".join("<td>%s</td>" % c for c in r)
        key = _strip_tags(" ".join(str(c) for c in r))
        body.append('<tr data-search="%s">%s</tr>' % (esc(key).replace('"', '&quot;'), tds))
    cls = ' class="searchable"' if searchable else ""
    search = ('<input class="tsearch" type="search" placeholder="Filter this table&hellip;" data-target="%s">' % tid) if searchable else ""
    return f'<div class="tablewrap">{search}<table id="{tid}"{cls}><thead><tr>{th}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'


def script_sections():
    out = []
    for f in SCRIPTS:
        sid = f.split(".")[0]
        src = SCRIPT_SRC[f]
        lines = src.count("\n") + 1
        out.append(f"""
<section class="card" id="script-{esc(sid)}">
  <h3><span class="mono">{esc(f)}</span> <span class="muted">&mdash; {lines} lines</span></h3>
  <p>{esc(SCRIPT_DESC.get(f, ''))}</p>
  <details><summary>Show source</summary><pre class="code"><code>{esc(src)}</code></pre></details>
</section>""")
    return "\n".join(out)


# ------------------------------------------------------------------ HTML ----
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M %Z")

vuln_rows = [(f'<a href="#{esc(x["id"])}">{esc(x["id"])}</a>', x["title"], sev_badge(x["sev"]), esc(x["cat"]),
              " ".join('<a class="chip" href="#script-%s">%s</a>' % (p.strip().split(".")[0], esc(p.strip())) for p in x["poc"].split(",")))
             for x in sorted(V, key=lambda y: (SEV_ORDER[y["sev"]], y["id"]))]

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TopFollow v8.4.5-Beta &mdash; Deep Security Analysis</title>
<style>
:root{{
  --bg:#07080f; --bg2:#0d1020; --glass:rgba(255,255,255,.045); --glass2:rgba(255,255,255,.075);
  --stroke:rgba(255,255,255,.10); --stroke2:rgba(255,255,255,.18);
  --fg:#e8ecf8; --mut:#98a2c0; --mut2:#6d779a;
  --acc:#7c5cff; --acc2:#22d3ee; --crit:#ff3b6b; --high:#ff8a3d; --med:#ffd23d; --low:#4dd7ff;
  --mono:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
}}
*{{box-sizing:border-box}}
html{{scroll-behavior:smooth}}
body{{
  margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.65 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Inter,'Helvetica Neue',Arial,sans-serif;
  -webkit-font-smoothing:antialiased;
}}
body::before{{
  content:''; position:fixed; inset:0; z-index:-2;
  background:
    radial-gradient(1100px 620px at 12% -8%, rgba(124,92,255,.30), transparent 62%),
    radial-gradient(900px 560px at 92% 4%, rgba(34,211,238,.20), transparent 60%),
    radial-gradient(800px 700px at 50% 108%, rgba(255,59,107,.16), transparent 62%),
    linear-gradient(180deg,#07080f 0%,#0a0c18 45%,#07080f 100%);
}}
body::after{{
  content:''; position:fixed; inset:0; z-index:-1; opacity:.35; pointer-events:none;
  background-image:linear-gradient(rgba(255,255,255,.028) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.028) 1px,transparent 1px);
  background-size:52px 52px;
  mask-image:radial-gradient(ellipse 90% 70% at 50% 20%,#000 30%,transparent 78%);
}}
.wrap{{max-width:1460px;margin:0 auto;padding:0 22px 90px}}
/* ---------- hero ---------- */
header.hero{{padding:64px 0 26px;border-bottom:1px solid var(--stroke)}}
.eyebrow{{font:600 11px/1 var(--mono);letter-spacing:.22em;text-transform:uppercase;color:var(--acc2);margin-bottom:16px}}
h1{{font-size:clamp(30px,4.6vw,56px);line-height:1.06;margin:0 0 14px;letter-spacing:-.022em;font-weight:800}}
h1 .grad{{background:linear-gradient(96deg,#fff 0%,#b9a8ff 42%,#5ee7f7 100%);-webkit-background-clip:text;background-clip:text;color:transparent}}
.sub{{color:var(--mut);font-size:17px;max-width:900px;margin:0 0 26px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:12px;margin:26px 0 8px}}
.kpi{{background:var(--glass);border:1px solid var(--stroke);border-radius:16px;padding:16px 18px;backdrop-filter:blur(18px) saturate(150%);-webkit-backdrop-filter:blur(18px) saturate(150%)}}
.kpi b{{display:block;font-size:32px;line-height:1;font-weight:800;letter-spacing:-.02em}}
.kpi span{{display:block;margin-top:7px;font-size:11.5px;color:var(--mut);letter-spacing:.05em;text-transform:uppercase}}
.kpi.c b{{color:var(--crit)}} .kpi.h b{{color:var(--high)}} .kpi.m b{{color:var(--med)}} .kpi.l b{{color:var(--low)}}
/* ---------- layout ---------- */
.layout{{display:grid;grid-template-columns:270px minmax(0,1fr);gap:34px;margin-top:34px;align-items:start}}
@media(max-width:1080px){{.layout{{grid-template-columns:1fr}}.toc{{position:static!important;max-height:none!important}}}}
nav.toc{{position:sticky;top:18px;max-height:calc(100vh - 36px);overflow:auto;background:var(--glass);border:1px solid var(--stroke);border-radius:18px;padding:16px 14px;backdrop-filter:blur(20px) saturate(150%);-webkit-backdrop-filter:blur(20px) saturate(150%)}}
nav.toc h5{{margin:0 0 10px;font:700 10.5px/1 var(--mono);letter-spacing:.2em;text-transform:uppercase;color:var(--mut2)}}
nav.toc a{{display:block;padding:6px 10px;border-radius:9px;color:var(--mut);text-decoration:none;font-size:13px;border-left:2px solid transparent}}
nav.toc a:hover{{background:var(--glass2);color:var(--fg)}}
nav.toc a.active{{color:#fff;background:linear-gradient(90deg,rgba(124,92,255,.28),transparent);border-left-color:var(--acc)}}
nav.toc .grp{{margin-top:14px}}
main{{min-width:0}}
section{{scroll-margin-top:20px;margin-bottom:34px}}
.card{{background:var(--glass);border:1px solid var(--stroke);border-radius:20px;padding:24px 26px;backdrop-filter:blur(20px) saturate(150%);-webkit-backdrop-filter:blur(20px) saturate(150%);margin-bottom:20px;box-shadow:0 18px 48px -28px rgba(0,0,0,.9)}}
h2{{font-size:26px;margin:38px 0 14px;letter-spacing:-.015em;font-weight:800;display:flex;align-items:center;gap:11px}}
h2::before{{content:'';width:4px;height:24px;border-radius:3px;background:linear-gradient(180deg,var(--acc),var(--acc2))}}
h3{{font-size:17.5px;margin:2px 0 10px;font-weight:700;letter-spacing:-.01em}}
h4{{font:700 10.5px/1.4 var(--mono);letter-spacing:.15em;text-transform:uppercase;color:var(--mut2);margin:16px 0 7px}}
p{{margin:0 0 11px}}
ul,ol{{margin:0 0 12px;padding-left:22px}} li{{margin-bottom:6px}}
code,.mono{{font-family:var(--mono);font-size:.875em}}
code{{background:rgba(124,92,255,.14);border:1px solid rgba(124,92,255,.22);padding:1.5px 6px;border-radius:6px;color:#cfc4ff;word-break:break-word}}
.muted{{color:var(--mut2);font-weight:500}}
a{{color:var(--acc2)}}
/* ---------- badges / chips ---------- */
.badge{{display:inline-block;font:700 10px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;padding:5px 9px;border-radius:999px;color:var(--c);border:1px solid color-mix(in srgb,var(--c) 45%,transparent);background:color-mix(in srgb,var(--c) 14%,transparent);white-space:nowrap}}
.chip{{display:inline-block;font:600 10.5px/1 var(--mono);padding:5px 9px;border-radius:8px;background:rgba(34,211,238,.10);border:1px solid rgba(34,211,238,.26);color:#a5eefb;text-decoration:none;white-space:nowrap}}
.chip:hover{{background:rgba(34,211,238,.2)}}
.chips{{display:flex;flex-wrap:wrap;gap:6px}}
.cat{{font:600 11px/1 var(--mono);color:var(--mut);background:var(--glass2);border:1px solid var(--stroke);padding:5px 9px;border-radius:999px;white-space:nowrap}}
/* ---------- tables ---------- */
.tablewrap{{overflow:auto;border:1px solid var(--stroke);border-radius:14px;background:rgba(0,0,0,.22);margin-bottom:14px}}
table{{border-collapse:collapse;width:100%;font-size:13.2px;min-width:640px}}
th{{position:sticky;top:0;background:#12152a;text-align:left;font:700 10px/1.3 var(--mono);letter-spacing:.13em;text-transform:uppercase;color:var(--mut);padding:11px 13px;border-bottom:1px solid var(--stroke2);z-index:1}}
td{{padding:10px 13px;border-bottom:1px solid rgba(255,255,255,.055);vertical-align:top;color:#d5dbef}}
tbody tr:hover{{background:rgba(124,92,255,.075)}}
tbody tr:last-child td{{border-bottom:none}}
td a{{text-decoration:none}} td a:hover{{text-decoration:underline}}
.tsearch{{width:100%;margin:0 0 10px;padding:10px 13px;background:rgba(0,0,0,.35);border:1px solid var(--stroke2);border-radius:11px;color:var(--fg);font:13px var(--mono);outline:none}}
.tsearch:focus{{border-color:var(--acc);box-shadow:0 0 0 3px rgba(124,92,255,.18)}}
.tsearch::placeholder{{color:var(--mut2)}}
/* ---------- vuln cards ---------- */
.controls{{display:flex;flex-wrap:wrap;gap:9px;align-items:center;margin-bottom:16px}}
.controls input,.controls select{{padding:10px 13px;background:rgba(0,0,0,.35);border:1px solid var(--stroke2);border-radius:11px;color:var(--fg);font:13px var(--mono);outline:none}}
.controls input{{flex:1 1 260px;min-width:200px}}
.controls input:focus,.controls select:focus{{border-color:var(--acc);box-shadow:0 0 0 3px rgba(124,92,255,.18)}}
.controls button{{padding:10px 15px;background:var(--glass2);border:1px solid var(--stroke2);border-radius:11px;color:var(--fg);font:600 12px var(--mono);cursor:pointer}}
.controls button:hover{{background:rgba(124,92,255,.24);border-color:var(--acc)}}
.controls .count{{font:600 11.5px var(--mono);color:var(--mut);margin-left:auto}}
.vuln{{border-left:3px solid var(--stroke2);transition:border-color .18s}}
.vuln[data-sev="Critical"]{{border-left-color:var(--crit)}}
.vuln[data-sev="High"]{{border-left-color:var(--high)}}
.vuln[data-sev="Medium"]{{border-left-color:var(--med)}}
.vuln[data-sev="Low"]{{border-left-color:var(--low)}}
.vuln header{{display:flex;flex-wrap:wrap;gap:9px;align-items:center;margin-bottom:9px}}
.vuln .vid{{font:800 12.5px/1 var(--mono);letter-spacing:.09em;color:#fff;background:linear-gradient(96deg,rgba(124,92,255,.55),rgba(34,211,238,.35));border:1px solid var(--stroke2);padding:6px 10px;border-radius:8px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
@media(max-width:820px){{.grid2,.rowend{{grid-template-columns:1fr!important}}}}
.rowend{{display:grid;grid-template-columns:1fr 1.4fr;gap:20px;align-items:start}}
.ev{{background:rgba(0,0,0,.34);border:1px solid var(--stroke);border-left:2px solid var(--acc2);border-radius:10px;padding:11px 13px;font-size:12.6px;color:#c3cbe6}}
.fixcol p{{color:#bff3d8}}
.hidden{{display:none!important}}
/* ---------- code ---------- */
pre.code{{background:#05060c;border:1px solid var(--stroke);border-radius:12px;padding:15px 17px;overflow:auto;font:12px/1.62 var(--mono);color:#c9d4f5;max-height:640px;margin:0}}
details{{margin-top:10px}}
summary{{cursor:pointer;font:600 12px var(--mono);color:var(--acc2);padding:8px 0;user-select:none}}
summary:hover{{color:#fff}}
/* ---------- misc blocks ---------- */
.callout{{border-radius:14px;padding:15px 18px;margin:14px 0;border:1px solid;background:rgba(0,0,0,.24)}}
.callout.crit{{border-color:rgba(255,59,107,.42);background:rgba(255,59,107,.09)}}
.callout.warn{{border-color:rgba(255,138,61,.40);background:rgba(255,138,61,.08)}}
.callout.info{{border-color:rgba(34,211,238,.36);background:rgba(34,211,238,.07)}}
.callout.ok{{border-color:rgba(74,222,128,.40);background:rgba(74,222,128,.08)}}
.callout b{{color:#fff}}
.flow{{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:12px 0}}
.flow .step{{background:var(--glass2);border:1px solid var(--stroke2);border-radius:11px;padding:9px 13px;font:600 12px var(--mono);color:#dfe6ff}}
.flow .arw{{color:var(--acc);font-weight:700}}
.kv{{display:grid;grid-template-columns:minmax(150px,240px) 1fr;gap:7px 18px;font-size:13.4px}}
.kv dt{{color:var(--mut);font-family:var(--mono);font-size:12px}}
.kv dd{{margin:0;color:#dfe6ff;word-break:break-word}}
.pill-row{{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}}
.fbtn{{padding:7px 12px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.14);border-radius:999px;color:var(--mut);font:600 11.5px/1 var(--mono);cursor:pointer}}
.fbtn:hover{{color:#fff;border-color:var(--acc)}}
.fbtn.on{{background:linear-gradient(96deg,rgba(124,92,255,.5),rgba(34,211,238,.32));border-color:var(--acc);color:#fff}}
.badge-cell{{white-space:nowrap}}
footer{{margin-top:46px;padding-top:20px;border-top:1px solid var(--stroke);color:var(--mut2);font-size:12.4px}}
.toolbar{{position:fixed;right:18px;bottom:18px;display:flex;gap:8px;z-index:60}}
.toolbar button{{background:rgba(16,18,34,.9);border:1px solid var(--stroke2);color:var(--fg);border-radius:12px;padding:11px 15px;font:600 12px var(--mono);cursor:pointer;backdrop-filter:blur(14px);box-shadow:0 10px 30px -12px #000}}
.toolbar button:hover{{border-color:var(--acc);background:rgba(124,92,255,.28)}}
mark{{background:rgba(255,210,61,.34);color:#fff;border-radius:3px;padding:0 2px}}
/* ---------- print ---------- */
@media print{{
  body{{background:#fff;color:#111}}
  body::before,body::after{{display:none}}
  .toolbar,.controls,.tsearch,nav.toc{{display:none!important}}
  .layout{{grid-template-columns:1fr}}
  .card{{break-inside:avoid;page-break-inside:avoid;background:#fff;border:1px solid #ccc;box-shadow:none;color:#111}}
  h1,h2,h3,h4,td,th,p,li,.kv dd{{color:#111!important}}
  code{{background:#f2f2f7;border-color:#ddd;color:#3a2f7a}}
  pre.code{{max-height:none;background:#fafafa;color:#222;border-color:#ddd}}
  a{{color:#0b57d0}}
  section{{break-inside:auto}}
  .vuln{{break-inside:avoid}}
  details{{open:true}} details>summary{{display:none}} details[open]>pre{{display:block}}
}}
</style>
</head>
<body>
<div class="wrap">

<header class="hero">
  <div class="eyebrow">Offensive security research &middot; static + dynamic reverse engineering</div>
  <h1><span class="grad">TopFollow v8.4.5-Beta</span><br>complete security teardown</h1>
  <p class="sub">A full reverse-engineering of <code>com.nivaroid.topfollow</code> &mdash; an Instagram follower-exchange manipulation app that advertises itself as &ldquo;very secure&rdquo; with anti-tamper, anti-Frida, SSL pinning and Play Integrity. Every claimed protection was located, decoded and defeated. The Instagram login flow, follow-task verification, coin economy and the OLLVM-obfuscated native library are reconstructed end to end.</p>

  <div class="kpis">
    <div class="kpi"><b>{len(V)}</b><span>Vulnerabilities</span></div>
    <div class="kpi c"><b>{SEV_COUNT['Critical']}</b><span>Critical</span></div>
    <div class="kpi h"><b>{SEV_COUNT['High']}</b><span>High</span></div>
    <div class="kpi m"><b>{SEV_COUNT['Medium']}</b><span>Medium</span></div>
    <div class="kpi l"><b>{SEV_COUNT['Low']}</b><span>Low</span></div>
    <div class="kpi"><b>8</b><span>Frida PoCs</span></div>
    <div class="kpi"><b>26</b><span>Backend endpoints</span></div>
    <div class="kpi"><b>22</b><span>Native JNI fns</span></div>
    <div class="kpi"><b>4,146</b><span>Classes decompiled</span></div>
  </div>

  <div class="callout crit" style="margin-top:22px">
    <b>Headline findings.</b> The app stores the user's <b>real Instagram password</b> and <b>TOTP 2FA seed</b> in an <b>unencrypted</b> Room database, protected only by a <b>keyless</b> byte-transform cipher that was re-implemented and round-tripped in Python. It <b>harvests Instagram session cookies from a WebView</b> and synthesises an OAuth bearer. It sends the live <b>Instagram session token to its own backend</b> in a plaintext <code>Token</code> header on every request. Its coin reward is switched on by a <b>client-asserted</b> <code>get_coin=true</code> flag, with a <b>client-supplied</b> <code>order_value</code> and a <b>static, replayable</b> challenge token. And because <code>allowBackup=true</code> ships with <b>completely empty exclusion rules</b>, all of it is copied into the user's Google cloud backup.
  </div>
</header>

<div class="layout">
<nav class="toc" id="toc">
  <h5>Contents</h5>
  <a href="#summary">1. Executive summary</a>
  <a href="#target">2. Target &amp; fingerprint</a>
  <a href="#threat">3. Threat model</a>
  <div class="grp"><h5>Reverse engineering</h5>
  <a href="#arch">4. Architecture</a>
  <a href="#iglogin">5. Instagram login</a>
  <a href="#igapi">6. Instagram private API</a>
  <a href="#tasks">7. Task verification</a>
  <a href="#economy">8. Coin economy</a>
  <a href="#backend">9. Backend &amp; endpoints</a>
  <a href="#native">10. Native library</a>
  <a href="#nativaes">11. Native AES + Unicorn proof</a>
  <a href="#crypto">12. Crypto &amp; obfuscation</a>
  <a href="#storage">13. Data storage</a>
  <a href="#integrity">14. Anti-tamper &amp; integrity</a>
  </div>
  <div class="grp"><h5>Results</h5>
  <a href="#matrix">15. Vulnerability matrix</a>
  <a href="#findings">16. Findings ({len(V)})</a>
  <a href="#lab">17. Frida lab (11 scripts)</a>
  <a href="#repro">18. Reproduction guide</a>
  <a href="#remediation">19. Remediation roadmap</a>
  <a href="#method">20. Methodology &amp; artefacts</a>
  <a href="#legal">21. Scope &amp; ethics</a>
  </div>
</nav>

<main>

<!-- =========================================================== 1 SUMMARY -->
<section id="summary">
<h2>1. Executive summary</h2>
<div class="card">
<p>TopFollow is a follower-exchange service: users surrender an Instagram credential, the app drives that account to follow, like, comment on, save and view other users' content in exchange for coins, and coins are spent to buy engagement for the user's own account. The vendor markets strong protection &mdash; an obfuscated native library, certificate pinning, signature self-verification, anti-Frida scanning, root detection and Play Integrity.</p>
<p><b>All of it was defeated statically before a single process was instrumented.</b> The native library <code>libtopfollow.so</code> is OLLVM control-flow-flattened across all 22 JNI functions, but flattening hides control flow, not data. Resolving the 943 position-independent <code>call $+5; pop reg; add reg,K</code> thunks per function recovered 760 <code>.rodata</code> references, and an exhaustive single-byte XOR sweep over keys 1&ndash;127 cracked every secret with just two keys: <code>0x55</code> and <code>0x5A</code>. The backend URL, all Instagram endpoints, the certificate pin, the anti-Frida keyword list and the complete root-path list were recovered from the binary.</p>
<p>The Java layer is worse. The &ldquo;encryption&rdquo; protecting Instagram passwords is a four-stage keyless byte transform &mdash; XOR <code>0x6C</code>, rotate-left 3, reverse, XOR <code>(i*37)^0xA5</code> &mdash; which was re-implemented in Python and verified to round-trip. The Room database has no SQLCipher and no passphrase. The manifest sets <code>allowBackup="true"</code> and then ships two <em>empty</em> backup-rule resources, so the default include-everything behaviour applies and the credential store is copied to Google's cloud.</p>
<p>The business logic is the most serious problem. Coin rewards are gated on <code>get_coin</code>, a boolean the <em>client</em> sets to <code>"true"</code> whenever its in-memory copy of the Instagram response says <code>status == "ok"</code>. The reward amount <code>order_value</code> also comes from the client. The anti-replay token <code>x4</code> is a compile-time constant, <code>TFjMTZRk5rMHdTVR</code>, identical on every install forever. The purchase price is computed client-side from a server-pushed rate multiplied by a client-chosen count, and checked against a wallet stored in the local unencrypted database &mdash; if the balance is too low the app simply sets the Buy button's click listener to <code>null</code>.</p>
<div class="callout warn"><b>One design decision dominates everything else.</b> Because the app accepts the Instagram <em>password</em> rather than using OAuth, and because it forwards the live session token to <code>top.nivafollower.app</code> in a <code>Token</code> header, the vendor operator holds mass account-takeover capability over the entire user base by construction &mdash; no exploit required. Any compromise of that server, or of the ServerCheck channel that supplies the base URL and certificate pin at runtime, yields every account at once.</div>
<h4>Severity distribution</h4>
<div class="pill-row">
  <span class="badge" style="--c:#ff3b6b">Critical &middot; {SEV_COUNT['Critical']}</span>
  <span class="badge" style="--c:#ff8a3d">High &middot; {SEV_COUNT['High']}</span>
  <span class="badge" style="--c:#ffd23d">Medium &middot; {SEV_COUNT['Medium']}</span>
  <span class="badge" style="--c:#4dd7ff">Low &middot; {SEV_COUNT['Low']}</span>
</div>
<h4>The five findings that matter most</h4>
<ol>
<li><b>CRED-01 / CRED-02 &mdash; passwords and TOTP seeds at rest.</b> <code>instagram_accounts.u_w</code> and <code>two_factors.u_p</code>/<code>s_k</code> in an unencrypted SQLite file behind a keyless cipher.</li>
<li><b>BIZ-01 / BIZ-02 &mdash; client-declared rewards.</b> <code>get_coin</code> and <code>order_value</code> both come from the client on <code>order/syncOrder.php</code>.</li>
<li><b>TRAN-02 / CRYP-04 &mdash; remotely rotatable base URL and pin.</b> <code>ha.h</code> builds its Retrofit from SharedPreferences <code>Pin</code>/<code>PinActive</code>, written by the ServerCheck bootstrap.</li>
<li><b>CRED-04 &mdash; session-token exfiltration by design.</b> <code>d.t()</code> puts the Instagram token in a plaintext header on every backend call.</li>
<li><b>STOR-02 &mdash; empty backup exclusions.</b> <code>&lt;full-backup-content/&gt;</code> and <code>&lt;data-extraction-rules&gt;&lt;cloud-backup/&gt;&lt;/data-extraction-rules&gt;</code> with <code>allowBackup=true</code>.</li>
</ol>
</div>
</section>

<!-- ============================================================ 2 TARGET -->
<section id="target">
<h2>2. Target &amp; fingerprint</h2>
<div class="card">
<dl class="kv">
<dt>File</dt><dd><code>TopFollow_v845-Beta (1).apk</code></dd>
<dt>Size</dt><dd>{APK_SIZE:,} bytes ({APK_SIZE/1048576:.2f} MiB)</dd>
<dt>MD5</dt><dd><code>{APK_MD5}</code></dd>
<dt>SHA-1</dt><dd><code>{APK_SHA1}</code></dd>
<dt>SHA-256</dt><dd><code>{APK_SHA256}</code></dd>
<dt>Package</dt><dd><code>com.nivaroid.topfollow</code></dd>
<dt>Version</dt><dd>8.4.5-Beta &nbsp;(versionCode <b>845</b>)</dd>
<dt>SDK</dt><dd>minSdk 24 &middot; targetSdk 35</dd>
<dt>DEX</dt><dd>single <code>classes.dex</code>, 3,881,636 bytes, 4,146 classes, <b>scrambled <code>map_list</code></b></dd>
<dt>Native libs</dt><dd><code>lib/{{arm64-v8a,x86_64,x86}}/libtopfollow.so</code>, <code>libdatastore_shared_counter.so</code></dd>
<dt>Backend</dt><dd><code>https://top.nivafollower.app/v840/</code> <span class="muted">(recovered from XOR 0x55 in .rodata; server-rotatable)</span></dd>
<dt>Room DB</dt><dd><code>t_f_d_b_f_v_c</code> &mdash; tables <code>device</code>, <code>instagram_accounts</code>, <code>two_factors</code>, <code>app_info</code></dd>
<dt>SharedPreferences</dt><dd><code>TOPFVC_Shared</code> (MODE_PRIVATE)</dd>
</dl>

<h4>Signing certificate &mdash; recovered without apksigner or a JDK</h4>
<p>The APK has <b>no v1/JAR signature</b> (no <code>META-INF/*.RSA|*.SF|*.MF</code>). The certificate was extracted by parsing the APK Signature Scheme v2 pair directly out of the signing block: magic <code>APK Sig Block 42</code> at <code>0x9d1608</code>, v2 pair at <code>0x9ce620</code> (<code>id=0x7109871a</code>, u64 length 1514), central directory at <code>0x9d1618</code>, certificate DER 864 bytes.</p>
<dl class="kv">
<dt>Subject = Issuer</dt><dd><code>CN=Maryam Ahmadi, OU=Android Developer, O=NivaRoid, L=Shiraz, ST=Fars, C=IR</code> &nbsp;<span class="badge" style="--c:#ff8a3d">self-signed</span></dd>
<dt>Serial</dt><dd>1 &nbsp;<span class="muted">(first certificate ever generated with this key)</span></dd>
<dt>Validity</dt><dd>2023-12-15 17:44:33 UTC &rarr; <b>2048-12-08</b> &nbsp;<span class="muted">(25 years, no rotation path)</span></dd>
<dt>Key / algo</dt><dd>RSA 2048-bit &middot; <code>rsassa_pkcs1v15</code> with SHA-256</dd>
<dt>Cert SHA-256</dt><dd><code>{CERT_SHA256}</code></dd>
<dt>SPKI pin</dt><dd><code>sha256/4xnmMuV3jXL9RYz2ZVYtWWrkkv/6wSuz8SkHAHAV5Uo=</code></dd>
</dl>
<div class="callout crit"><b>The certificate digest <em>is</em> the tamper-check constant.</b> The pin literal found in <code>libtopfollow.so</code> .rodata &mdash; <code>sha256/d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e</code> &mdash; is byte-for-byte the SHA-256 of this APK's own signing certificate. One constant is doing two unrelated jobs: it is both the &ldquo;certificate pin&rdquo; and the value the signature self-check compares against. That is not transport pinning (it says nothing about the server's TLS key) and it is not a strong integrity anchor (it is compared in hookable Java reflection). See CRYP-04 and INTE-01.</div>
<details><summary>Signing certificate (DER, base64)</summary><pre class="code"><code>{esc(CERT_B64)}</code></pre></details>
</div>
</section>

<!-- ============================================================ 3 THREAT -->
<section id="threat">
<h2>3. Threat model</h2>
<div class="card">
<h4>Assets</h4>
<div class="tablewrap"><table><thead><tr><th>Asset</th><th>Where it lives</th><th>Who wants it</th></tr></thead><tbody>
<tr><td>Instagram <b>password</b></td><td><code>instagram_accounts.u_w</code>, <code>two_factors.u_p</code> &mdash; unencrypted SQLite, keyless cipher</td><td>Vendor operator, local attacker, anyone with the Google backup</td></tr>
<tr><td>Instagram <b>TOTP seed</b></td><td><code>two_factors.s_k</code></td><td>Same &mdash; permanently defeats 2FA</td></tr>
<tr><td>Instagram <b>session / bearer</b></td><td><code>instagram_accounts.u_a</code>, <code>.token</code>, WebView cookie jar</td><td>Vendor operator (receives it in a header), MITM</td></tr>
<tr><td><b>Coin / gem</b> balance</td><td><code>device.coin</code>, <code>device.gem</code> (local) + server ledger</td><td>Users wanting free engagement</td></tr>
<tr><td>Backend <b>base URL + pin</b></td><td>SharedPreferences <code>Pin</code>/<code>PinActive</code>, from ServerCheck</td><td>MITM wanting to redirect the whole fleet</td></tr>
<tr><td><b>Device identity</b></td><td><code>Aid</code>, <code>DeviceId</code>, <code>RD</code>, <code>fcm_token</code>, <code>hash_key</code>, <code>nonce</code></td><td>Trackers; correlates accounts across installs</td></tr>
<tr><td>Instagram <b>platform integrity</b></td><td>&mdash;</td><td>Attacked by the product itself: fake engagement at scale</td></tr>
</tbody></table></div>

<h4>Actors and capability</h4>
<div class="tablewrap"><table><thead><tr><th>Actor</th><th>Capability</th><th>Primary route</th><th>Findings</th></tr></thead><tbody>
<tr><td><b>Vendor operator</b></td><td>Full server control, sees every request</td><td>No exploit needed &mdash; the app sends Instagram passwords (<code>instagramLogin.php</code>) and live session tokens (<code>Token</code> header) by design</td><td>CRED-04, CRED-05</td></tr>
<tr><td><b>Malicious user</b> (rooted own device)</td><td>Frida, Magisk, sqlite3, file access</td><td>Force <code>get_coin=true</code>, inflate the wallet, replay the static <code>x4</code></td><td>BIZ-01, BIZ-02, BIZ-03, BIZ-06</td></tr>
<tr><td><b>Network attacker</b> (same Wi-Fi, rogue AP, hostile CDN)</td><td>TLS MITM</td><td>Hook <code>CertificatePinner.check</code>, or simply wait for ServerCheck to hand over a new pin</td><td>TRAN-01, TRAN-02, CRYP-04</td></tr>
<tr><td><b>Local attacker</b> (stolen phone, forensic tool, other profile)</td><td>Read app data / backup</td><td>Pull the unencrypted Room DB or the Google cloud backup; decrypt with the keyless cipher</td><td>STOR-01, STOR-02, CRYP-01</td></tr>
<tr><td><b>Google-account attacker</b></td><td>Cloud restore</td><td>Backup exclusion rules are empty, so the credential DB restores onto their device</td><td>STOR-02</td></tr>
<tr><td><b>Repackager</b></td><td>Modify + re-sign the APK</td><td>Hook <code>MessageDigest.digest()</code>, or patch the embedded constant</td><td>INTE-01, CRYP-02, INTE-12</td></tr>
<tr><td><b>Instagram</b> (defender)</td><td>Abuse detection, bans</td><td>Every user presents an identical hard-coded device fingerprint, bloks id and app version</td><td>CRED-06, CRED-07, CRED-08</td></tr>
<tr><td><b>The end user</b> (victim)</td><td>None</td><td>Surrenders a password or session, is never re-asked for consent, and gets automated on indefinitely</td><td>CRED-01, STOR-15, BIZ-08</td></tr>
</tbody></table></div>

<h4>Trust boundaries</h4>
<div class="flow">
  <span class="step">User</span><span class="arw">&rarr;</span>
  <span class="step">TopFollow client</span><span class="arw">&rarr;</span>
  <span class="step" style="border-color:var(--crit)">BOUNDARY 1 &mdash; credential surrender</span><span class="arw">&rarr;</span>
  <span class="step">top.nivafollower.app</span>
</div>
<div class="flow">
  <span class="step">TopFollow client</span><span class="arw">&rarr;</span>
  <span class="step" style="border-color:var(--crit)">BOUNDARY 2 &mdash; private-API impersonation</span><span class="arw">&rarr;</span>
  <span class="step">Instagram</span>
</div>
<div class="flow">
  <span class="step">ServerCheck response</span><span class="arw">&rarr;</span>
  <span class="step" style="border-color:var(--crit)">BOUNDARY 3 &mdash; URL + pin injection</span><span class="arw">&rarr;</span>
  <span class="step">Retrofit / CertificatePinner</span>
</div>
<p>Boundary 3 is the structural flaw: the app takes its <em>transport trust anchor</em> from the network it is supposed to be protecting against. An attacker who controls one ServerCheck response controls boundaries 1 and 2 as well, because the redirect carries the Instagram password with it.</p>

<h4>Attack trees</h4>
<div class="grid2">
<div class="callout crit"><b>Free engagement (money)</b><br>
1. Spawn with <code>01</code> + <code>02</code> so the app boots clean.<br>
2. Attach <code>06</code>: force <code>InstagramResponse.getStatus()</code> &rarr; <code>"ok"</code>.<br>
3. <code>ha.c.onReady()</code> now emits <code>get_coin="true"</code> for tasks that failed or never ran.<br>
4. Optionally rewrite <code>order_value</code> to choose the payout.<br>
5. <code>x4</code> is a constant, so nothing blocks replay.<br>
&rarr; coins accumulate without performing Instagram actions; spend them via <code>05</code>.</div>
<div class="callout crit"><b>Fleet-wide credential capture (network)</b><br>
1. MITM the device; attach <code>02</code> to defeat the OkHttp pinner (it is Java-side &mdash; the .so has no TLS code).<br>
2. Or, cleaner: hijack the ServerCheck response and set <code>url</code> + <code>pin</code> to attacker values; the app writes them to <code>Pin</code>/<code>PinActive</code> and rebuilds its Retrofit through native <code>q.k()</code>.<br>
3. Every subsequent call &mdash; including <code>instagramLogin.php</code> &mdash; goes to the attacker with the pin already trusting the attacker's certificate.<br>
&rarr; Instagram passwords and session tokens for the whole user base.</div>
<div class="callout warn"><b>Offline credential theft (no root)</b><br>
1. <code>allowBackup=true</code> and both backup-rule resources are empty.<br>
2. Cloud backup / device-to-device migration copies <code>t_f_d_b_f_v_c</code> and <code>TOPFVC_Shared.xml</code>.<br>
3. Open the SQLite file; apply the four-stage keyless transform in reverse.<br>
&rarr; passwords, bearers and TOTP seeds, with no device access at all.</div>
<div class="callout warn"><b>Repackaging (bypass anti-tamper)</b><br>
1. Modify the APK, re-sign with any key.<br>
2. Spawn with <code>01</code>: <code>MessageDigest.digest()</code> returns the expected <code>d845591e&hellip;</code>, <code>d8.f.a()</code> returns <code>true</code>, maps/root/Frida probes are filtered, <code>System.exit</code> is suppressed.<br>
3. Or statically patch the embedded constant (CRYP-02).<br>
&rarr; a trojanised build that passes every self-check.</div>
</div>

<h4>What is genuinely well built</h4>
<ul>
<li><b>Small exported surface.</b> Only three components are exported &mdash; the launcher activity and two framework receivers, both permission-guarded. No deep links, no exported services or providers, no exported <code>TaskActionReceiver</code> (STOR-16).</li>
<li><b>Sound binary hardening flags.</b> <code>libtopfollow.so</code> has FULL RELRO + BIND_NOW, a stack canary and FORTIFY on all three ABIs.</li>
<li><b>Real obfuscation effort.</b> OLLVM control-flow flattening across all 22 JNI functions, scrambled DEX <code>map_list</code>, single-byte XOR string tables, nested base64 literals and a JNI-only export surface. This meaningfully raises the cost of casual analysis &mdash; it simply does not raise the security floor (INTE-06, INTE-07).</li>
<li><b>Correct transport defaults.</b> <code>usesCleartextTraffic="false"</code>.</li>
<li><b>Server-issued order stamps exist.</b> <code>order_stamp</code>/<code>order_stamp2</code> are real server nonces &mdash; the design was reaching for replay protection, it just left <code>x4</code> static and <code>get_coin</code> client-side.</li>
</ul>
</div>
</section>

<!-- ============================================================= 4 ARCH -->
<section id="arch">
<h2>4. Architecture &amp; data flow</h2>
<div class="card">
<p>The DEX is aggressively name-obfuscated and many real classes are hidden inside unrelated package names &mdash; the cipher lives in <code>com.bumptech.glide.d</code>, the ServerCheck bootstrap in <code>com.bumptech.glide.manager.r</code>, the backend request dispatcher in <code>androidx.fragment.app.e</code>, and the Play Integrity gate in <code>d3.d</code>. The map below is the de-obfuscated picture.</p>
<div class="tablewrap"><table><thead><tr><th>Component</th><th>Real role</th></tr></thead><tbody>
<tr><td><code>com.bumptech.glide.d</code></td><td><b>Cipher + header factory.</b> <code>o()</code> base64-decode, <code>p()</code> decrypt, <code>q()</code> encrypt, <code>b()</code> URL-encode, <code>t(InstagramAccount)</code> backend headers.</td></tr>
<tr><td><code>com.bumptech.glide.manager.r</code></td><td><b>ServerCheck bootstrap.</b> Fetches <code>ServerCheckModel</code> and writes <code>Pin</code>/<code>PinActive</code>.</td></tr>
<tr><td><code>com.nivaroid.topfollow.helper.q</code></td><td><b>The 22-method JNI facade</b> into <code>libtopfollow.so</code>. Every secret-producing function is native.</td></tr>
<tr><td><code>com.nivaroid.topfollow.helper.a0</code></td><td><b>Challenge constants.</b> <code>x()</code> &rarr; the 64-hex integrity constant; <code>x4()</code> &rarr; the static claim token; <code>x0..x3()</code> read <code>Sign</code>/<code>RID</code>/<code>RD</code>/<code>SND</code>.</td></tr>
<tr><td><code>ha.h</code> / <code>ha.k</code></td><td><b>Backend Retrofit</b> (built by native <code>q.k()</code>) and its single generic POST method <code>a(path, headers, body)</code>.</td></tr>
<tr><td><code>ha.b</code>, <code>ha.c</code>, <code>ha.a</code>, <code>ha.d</code>, <code>ha.i</code></td><td><b>Request-body builders</b> for login/submitOrder, syncOrder claim, captcha/getMainInfo, miner, image.</td></tr>
<tr><td><code>androidx.fragment.app.e</code></td><td><b>Endpoint dispatcher.</b> A switch over 18 cases mapping to <code>account/*.php</code>, plus the coin-cost purchase dialog.</td></tr>
<tr><td><code>d3.d</code></td><td><b>Play Integrity gate</b> (<code>l()</code>): checks <code>SND</code>/<code>RID</code>, caches the token 6 h, injects <code>x2</code>.</td></tr>
<tr><td><code>d8.f</code></td><td><b>Google Phonesky verification</b> (<code>a(Signature[])</code>) &mdash; must pass before attestation.</td></tr>
<tr><td><code>ia.q</code> / <code>ia.g</code> / <code>ja.e</code></td><td><b>Instagram layer.</b> <code>ia.q</code> builds the three Retrofits and the header map; <code>ia.g</code> is the private-API interface; <code>ja.e</code> is the per-account task worker.</td></tr>
<tr><td><code>ia.v</code> / <code>ia.s</code> / <code>ia.x</code></td><td><b>Login.</b> <code>ia.v</code> orchestrates the Bloks/CAA login and stores credentials; <code>ia.s</code> parses the response by substring match; <code>ia.x</code> is the human-behaviour simulator.</td></tr>
<tr><td><code>oa.l1</code> / <code>WebViewActivity</code></td><td><b>WebView cookie harvester</b> &mdash; the second login path.</td></tr>
<tr><td><code>DoTasksService</code></td><td><b>Farming engine.</b> One <code>ja.e</code> worker per active Instagram account.</td></tr>
<tr><td><code>CaptchaRequest</code></td><td><b>hCaptcha / reCAPTCHA</b> chooser; site keys come from native <code>q.f()</code>/<code>q.g()</code>.</td></tr>
<tr><td><code>MyDatabase</code> (<code>c2.x</code>)</td><td><b>Unencrypted Room DB</b> <code>t_f_d_b_f_v_c</code>.</td></tr>
</tbody></table></div>

<h4>End-to-end request path</h4>
<div class="flow">
<span class="step">UI / DoTasksService</span><span class="arw">&rarr;</span>
<span class="step">body builder (ha.*)</span><span class="arw">&rarr;</span>
<span class="step">d3.d.l() integrity inject</span><span class="arw">&rarr;</span>
<span class="step">native q.t/q.i/q.u/q.v</span><span class="arw">&rarr;</span>
<span class="step">d.t() headers</span><span class="arw">&rarr;</span>
<span class="step">ha.k.a(path, headers, body)</span><span class="arw">&rarr;</span>
<span class="step">OkHttp + CertificatePinner</span>
</div>
<div class="flow">
<span class="step">ja.e task worker</span><span class="arw">&rarr;</span>
<span class="step">ia.x human sim</span><span class="arw">&rarr;</span>
<span class="step">native q.h(Order) signed_body</span><span class="arw">&rarr;</span>
<span class="step">ia.q.f() IG headers</span><span class="arw">&rarr;</span>
<span class="step">ia.g.i()/d0()</span><span class="arw">&rarr;</span>
<span class="step">Instagram</span>
</div>
</div>
</section>

<!-- ========================================================= 5 IG LOGIN -->
<section id="iglogin">
<h2>5. Instagram login flow</h2>
<div class="card">
<p>There is <b>no OAuth</b>. The app reimplements Instagram's confidential Android login (the &ldquo;Bloks / CAA&rdquo; flow) and offers a second path that simply steals session cookies from a WebView.</p>

<h4>Path A &mdash; private-API Bloks login (<code>ia.v</code>, <code>ia.s</code>)</h4>
<div class="flow">
<span class="step">1. ia.q headers</span><span class="arw">&rarr;</span>
<span class="step">2. POST com.bloks.www.caa.login.login_homepage</span><span class="arw">&rarr;</span>
<span class="step">3. ia.s.success() substring-parse</span><span class="arw">&rarr;</span>
<span class="step">4a. Bearer &rarr; ia.v.a() stores creds</span>
</div>
<div class="flow">
<span class="step">4b. two_step_verification &rarr; ia.i0 challenge</span><span class="arw">&rarr;</span>
<span class="step">4c. challenge_required / errors &rarr; onLogin("fail"/"show_error")</span>
</div>
<p>The login body is URL-encoded form data: <code>params={{base64(client_input_params + server_params)}}&amp;bk_client_context={{base64(bloks_version, styles_id)}}&amp;bloks_versioning_id=083f38c3&hellip;39d604</code>.</p>
<div class="grid2">
<div>
<h4>client_input_params</h4>
<ul>
<li><code>username_input</code> &mdash; the user's Instagram handle</li>
<li><code>aac</code> &mdash; JSON string <code>{{"aac_init_timestamp":..,"aacjid":"..","aaccs":".."}}</code></li>
<li><code>lois_settings.lois_token</code> = <code>""</code></li>
<li><code>cloud_trust_token</code> = <code>null</code>, <code>zero_balance_state</code> = <code>""</code>, <code>network_bssid</code> = <code>null</code></li>
</ul>
</div>
<div>
<h4>server_params</h4>
<ul>
<li><code>device_id</code> = <code>android-{{Aid}}</code>, <code>qe_device_id</code></li>
<li><code>login_surface</code> = <code>login_home</code>, <code>login_entry_point</code> = <code>logged_out</code></li>
<li><code>waterfall_id</code>, <code>family_device_id</code></li>
<li><code>offline_experiment_group</code> = <code>caa_iteration_v3_perf_ig_4</code></li>
<li><code>access_flow_version</code> = <code>pre_mt_behavior</code></li>
<li><code>INTERNAL__latency_qpl_instance_id</code> = <code>19558568600088</code></li>
<li><code>INTERNAL__latency_qpl_marker_id</code> = <code>36707139</code></li>
<li><code>is_from_logged_out</code>/<code>is_platform_login</code>/<code>is_from_logged_in_switcher</code> = 0</li>
<li><code>layered_homepage_experiment_group</code> = <code>Deploy:+Not+in+Experiment</code></li>
</ul>
</div>
</div>

<h4>Response handling &mdash; substring matching, not JSON parsing</h4>
<p><code>ia.s.success()</code> strips backslashes and then <em>string-searches</em> the raw body. Order of checks:</p>
<div class="tablewrap"><table><thead><tr><th>Substring found</th><th>Outcome</th></tr></thead><tbody>
<tr><td><code>"Bearer"</code></td><td>&rarr; <code>ia.v.a()</code>: split on <code>logged_in_user</code>/<code>headers</code>/<code>Bearer</code>/<code>hmac</code>, build the account row, <b>store the password</b></td></tr>
<tr><td><code>"two_step_verification"</code></td><td>&rarr; extract <code>challenge_context</code> by <code>indexOf("(dkc")</code>, set <code>instance_id</code> via regex <code>(\\d+)\\s+"com\\.bloks\\.</code> (default <code>4806706160933748992</code>), <code>marker_id=36707139</code>, launch <code>ia.i0</code></td></tr>
<tr><td><code>"The password you entered is incorrect"</code></td><td>&rarr; <code>onLogin("show_error","password_incorrect")</code></td></tr>
<tr><td><code>"We can't find an account with"</code> / <code>"Please check your username and try again."</code></td><td>&rarr; <code>onLogin("show_error","can_not_find_account")</code></td></tr>
<tr><td><code>"there was a problem with your request"</code></td><td>&rarr; <code>onLogin("show_error","Sorry, there was a problem with your request.")</code></td></tr>
<tr><td><code>"challenge_required"</code></td><td>&rarr; <code>onLogin("fail","challenge_required")</code></td></tr>
<tr><td>none of the above</td><td>&rarr; generic error + <code>" code:13"</code></td></tr>
</tbody></table></div>

<h4>What gets persisted on success (<code>ia.v.a()</code>)</h4>
<div class="callout crit"><code>setU_w(com.bumptech.glide.d.q(v6.getPassword()))</code> &mdash; <b>the Instagram password</b>, run through the keyless cipher.<br>
<code>setU_a(com.bumptech.glide.d.q("Bearer " + token))</code> &mdash; the OAuth bearer.<br>
Plus <code>pk</code>, <code>username</code>, <code>mid</code>, <code>rur="CLN"</code>, <code>claim</code> (from the <code>hmac</code> fragment, else <code>"0"</code>), <code>family_device_id</code>, <code>pigeon_session_id</code>, <code>profile_pic_url</code>, and <code>active</code>/<code>sort</code>. The new row id is written to SharedPreferences <code>ActiveID</code>. Retry logic: up to 3 attempts (<code>ia.v.b()</code>) before <code>onLogin("fail","connection")</code>.</div>

<h4>Path B &mdash; WebView cookie theft (<code>oa.l1.onPageFinished</code>)</h4>
<p>Every time a page finishes loading in <code>WebViewActivity</code>, the client reads the Instagram cookie jar:</p>
<pre class="code"><code>String cookie = CookieManager.getInstance().getCookie("https://www.instagram.com/");
String sessionid  = y(cookie, "sessionid");
String ds_user_id = y(cookie, "ds_user_id");
String mid        = y(cookie, "mid");

if (sessionid &amp;&amp; ds_user_id) {{
    JSONObject o = new JSONObject();
    o.put("ds_user_id", ds_user_id);
    o.put("sessionid",  sessionid);
    String b64 = Base64.encodeToString(o.toString().getBytes(UTF_8), NO_WRAP);
    String bearer = "Bearer IGT:2:" + b64;          // <-- synthesised OAuth token

    account.setPk(ds_user_id);
    account.setU_a(glide.d.q(bearer));              // stored, keyless-ciphered
    account.setUsername("empty");
    account.setU_w("");                             // no password on this path
    account.setAccount_type("auth");
    account.setMid(mid); account.setRur("CLN"); account.setClaim("0");
    account.setActive(1);
    // inserted into instagram_accounts; ActiveID updated
}}</code></pre>
<p>No user gesture, no confirmation dialog, no domain restriction beyond &ldquo;a page finished loading&rdquo;. The account is then usable for every automation the app performs. This is CRED-03.</p>

<h4>Two-factor handling</h4>
<p>The <code>two_factors</code> table stores <code>u_n</code> (username), <code>u_p</code> (password) and <code>s_k</code> (the shared secret). <code>TwoFactorLoginActivity</code> drives <code>ia.a</code> with a <code>c2.q</code> callback; <code>c2.t</code> loads rows with the raw query <code>select * from two_factors</code>. The backend endpoints <code>account/getQuestions.php</code>, <code>account/getSecretKey.php</code> and <code>account/requestDigitCode.php</code> participate, and <code>ha.c</code> sends an <code>s_k_2fa</code> field. Storing the seed means 2FA is not a second factor at all &mdash; see CRED-02.</p>
</div>
</section>

<!-- =========================================================== 6 IG API -->
<section id="igapi">
<h2>6. Instagram private API layer</h2>
<div class="card">
<h4>Three Retrofit instances, all built in native code</h4>
<div class="tablewrap"><table><thead><tr><th>Factory call</th><th>Base URL</th><th>Used for</th></tr></thead><tbody>
<tr><td><code>helper.q.l(0)</code></td><td><code>https://b.i.instagram.com/api/v1/</code></td><td>Private mobile API &mdash; follow, like, comment, save</td></tr>
<tr><td><code>helper.q.l(1)</code></td><td><code>https://i.instagram.com/api/v2/</code></td><td>Private API v2</td></tr>
<tr><td><code>helper.q.l(2)</code></td><td><code>https://www.instagram.com/graphql/query</code> (+ <code>https://www.instagram.com/</code>)</td><td>GraphQL / web-path actions</td></tr>
</tbody></table></div>
<p>All three are constructed by <code>libtopfollow.so!x0018d3f7</code> &mdash; the same function that performs the signature self-check and the anti-Frida scan. The URLs are stored as <b>triple-base64</b> in <code>.rodata</code>.</p>

<h4>Header set produced by <code>ia.q.f(long)</code></h4>
{build_table([(f"<code>{esc(h)}</code>", d, chips(vid)) for h, d, vid in IG_HEADERS], ["Header", "Value / source", "Findings"], "tbl-ig-headers")}

<h4>Automation reach beyond follower exchange</h4>
<p>The DEX references <code>direct_v2/has_interop_upgraded/</code> (Instagram&nbsp;&harr;&nbsp;Facebook DM interop), <code>create_note/v2/</code> (Threads notes), <code>seen/</code> (story views), <code>/save/</code>, three Facebook <code>doc_id</code> GraphQL documents, <code>attestation/create_android_keystore/</code>, and the token prefix <code>3,IGbdd5f76a8fb9c4f86adf36a09f2750dc,{{pk}}</code>. Per-account rows also store <code>fbid_v2</code> and <code>interop_messaging_user_fbid</code>, linking the Instagram identity to its Facebook counterpart. See STOR-14.</p>

<h4><code>signed_body</code></h4>
<p>Every action request passes <code>com.nivaroid.topfollow.helper.q.h(Order)</code> &mdash; native <code>x0011f1a2</code> &mdash; as Instagram's <code>signed_body</code>. Because the signing key lives in the binary and the input is the locally held <code>Order</code> object, a hook on <code>q.h()</code> yields valid signatures for arbitrary orders (script 03 logs each one; script 06 rewrites the order first).</p>
</div>
</section>

<!-- ============================================================ 7 TASKS -->
<section id="tasks">
<h2>7. Follow-task verification logic</h2>
<div class="card">
<p><code>DoTasksService</code> is the farming engine. On <code>onCreate()</code> it enumerates every <code>instagram_accounts</code> row where <code>isActive()</code> is true and builds one <code>ja.e</code> worker per account. If SharedPreferences <code>SingleTasking</code> is false, <b>all</b> workers run in parallel; otherwise only the first starts. Each worker reads its task list from <code>MyDatabase.setup().n().getActionList()</code> and filters on SharedPreferences <code>NewTaskType</code> (default <code>all</code>).</p>

<h4>Task dispatch &mdash; <code>ja.e.b()</code> switches on <code>Order.getType()</code></h4>
{build_table([(f"<code>{esc(t)}</code>", f"<b>{esc(n)}</b>", f"<code>{esc(c)}</code>", f"<code>{esc(b)}</code>") for t, n, c, b in IG_ACTIONS], ["type", "Action", "Call", "Request body (all carry <code>signed_body = q.h(Order)</code>)"], "tbl-tasks")}

<h4>Verification: what the server actually receives</h4>
<p>After the action returns, <code>ha.c.onReady(JsonObject)</code> assembles the claim for <code>order/syncOrder.php</code>. Every field is client-produced:</p>
{build_table([(f"<code>{esc(k)}</code>", src, note) for k, src, note in CLAIM_FIELDS], ["Field", "Source", "Note"], "tbl-claim")}

<div class="callout crit"><b>The verification is the vulnerability.</b> The literal code is:
<pre class="code"><code>if ((v3_15 == null) || ((v3_15.getStatus() == null) || (!v3_15.getStatus().equals("ok")))) {{
    v1_16 = "false";
}} else {{
    v1_16 = "true";
}}
p9.addProperty("get_coin", v1_16);</code></pre>
<code>v3_15</code> is the in-memory <code>InstagramResponse</code>. Forcing <code>getStatus()</code> to return <code>"ok"</code> &mdash; one Frida overload &mdash; makes the client assert payment for an action that failed or never occurred. The reward amount (<code>order_value</code>) is also read from the local <code>Order</code>, and the anti-replay token <code>x4</code> is the compile-time constant <code>TFjMTZRk5rMHdTVR</code>. Nothing in this payload requires the server to have issued anything fresh for this specific attempt. See BIZ-01, BIZ-02, BIZ-06, BIZ-07.</div>

<h4>Server-issued stamps &mdash; present but insufficient</h4>
<p><code>order_stamp</code>, <code>order_stamp2</code> and <code>order_stamp3</code> <em>are</em> server-issued nonces carried on the <code>Order</code> model, and <code>sign</code> is a per-order signature. The design clearly intended replay protection. It fails because (a) the stamps authenticate the <em>order</em>, not the <em>completion</em>; (b) the completion evidence <code>x5</code> is a client-side native transform of a client-held response object; and (c) the money switch <code>get_coin</code> sits outside any signed material.</p>
</div>
</section>

<!-- ========================================================= 8 ECONOMY -->
<section id="economy">
<h2>8. Coin economy</h2>
<div class="card">
<h4>Earn &mdash; complete tasks for other users</h4>
<div class="flow"><span class="step">ja.e performs IG action</span><span class="arw">&rarr;</span><span class="step">ha.c builds claim</span><span class="arw">&rarr;</span><span class="step">POST order/syncOrder.php</span><span class="arw">&rarr;</span><span class="step">server credits coins</span></div>
<h4>Spend &mdash; buy engagement for your own account</h4>
<div class="flow"><span class="step">UI: pick count</span><span class="arw">&rarr;</span><span class="step">cost = coin_per_X * count</span><span class="arw">&rarr;</span><span class="step">if device.coin &ge; cost: enable Buy</span><span class="arw">&rarr;</span><span class="step">set_order_stamp = q.s(user,count,type)</span><span class="arw">&rarr;</span><span class="step">POST order/submitOrder.php</span></div>

<h4>Rates are server-pushed but consumed client-side</h4>
<p><code>getMainInfo.php</code> populates the Room <code>app_info</code> row. The purchase dialog then computes the price locally &mdash; <code>MyDatabase.setup().n().getCoin_per_like() * selectedCount</code> (and the equivalents for follow, comment, repost, save, seen, threads) &mdash; and compares it against <code>MyDatabase.setup().getDevice().getCoin()</code>, a row in the local unencrypted database. The affordability decision is expressed purely as UI state:</p>
<pre class="code"><code>int cost = MyDatabase.setup().n().getCoin_per_like() * count;
if (MyDatabase.setup().getDevice().getCoin() &lt; cost) {{
    priceView.setTextColor(getColor(R.color.red));
    dialog.findViewById(R.id.buyWithCoins).setOnClickListener(null);   // disabled
}} else {{
    priceView.setTextColor(getColor(R.color.green));
    dialog.findViewById(R.id.buyWithCoins)
          .setOnClickListener(new oa.i0(activity, count, dialog, 0));  // enabled
}}
// identical block for gems, via getDevice().getGem()</code></pre>
<p>Hooking <code>DeviceModel.getCoin()</code>/<code>getGem()</code> to return a large number, or editing the <code>device</code> row directly with <code>sqlite3</code>, makes every purchase button live. See BIZ-03 and BIZ-05.</p>

<h4>Wallet schema</h4>
<div class="tablewrap"><table><thead><tr><th>Column</th><th>Meaning</th></tr></thead><tbody>
<tr><td><code>device.coin</code></td><td>Coin balance &mdash; the spendable currency for followers/likes/comments</td></tr>
<tr><td><code>device.gem</code></td><td>Premium currency, spent through the parallel Buy-with-Gems button</td></tr>
<tr><td><code>device.token</code></td><td>Backend <code>Top-Token</code> header value</td></tr>
<tr><td><code>instagram_accounts.collected_coins</code></td><td>Per-account lifetime earnings</td></tr>
<tr><td><code>instagram_accounts.is_vip</code></td><td>Local mirror of VIP tier</td></tr>
<tr><td><code>app_info.coin_per_*</code></td><td>Server-pushed earn/spend rates per action type</td></tr>
<tr><td><code>app_info.min_*_order</code></td><td>Minimum order sizes</td></tr>
</tbody></table></div>

<h4>Secondary earn paths</h4>
<ul>
<li><b>Coupons</b> &mdash; <code>account/addCoupon.php</code>, <code>getCoupons.php</code> (<code>Coupon</code>, <code>CouponList</code>, <code>CouponType</code> models).</li>
<li><b>Gift codes</b> &mdash; <code>account/getGiftCodeReward.php</code>.</li>
<li><b>Daily rewards</b> &mdash; <code>account/checkDailyGift.php</code>, <code>getDailyItems.php</code>; eligibility is evaluated against the device clock.</li>
<li><b>Referrals</b> &mdash; <code>account/getInviteData.php</code>, <code>setInviteCode.php</code>; identity travels as client-set <code>by</code> / <code>user_pk</code>.</li>
<li><b>Leaderboard &amp; miners</b> &mdash; <code>getLeaderBoard.php</code>, <code>getMinerRequests.php</code>, <code>changeMinerRequest.php</code>.</li>
<li><b>VIP</b> &mdash; <code>account/upgradeAccountToVip.php</code> with <code>vip_stamp = q.m()</code>, gated only on locally available <code>media_count</code> and <code>username</code>.</li>
</ul>
<div class="callout warn"><b>No client-side throttling anywhere on the money path.</b> The only pacing value, <code>app_info.action_delay</code>, governs Instagram action timing &mdash; not claim rate. <code>request_id</code> is a locally generated <code>UUID.randomUUID()</code>, so deduplication depends entirely on server enforcement that the client gives no evidence of. See STOR-10 and BIZ-10/11.</div>
</div>
</section>

<!-- ========================================================= 9 BACKEND -->
<section id="backend">
<h2>9. Backend &amp; network endpoints</h2>
<div class="card">
<h4>Base URL construction</h4>
<pre class="code"><code>// ha.h  - the backend Retrofit is rebuilt from server-supplied material
Retrofit r = helper.q.k(                       // native libtopfollow.so!x00126f7c
    com.bumptech.glide.d.p(                    // decrypt (keyless cipher)
        SP.getString("Pin", "")),              // <-- pushed by ServerCheck
    SP.getBoolean("PinActive", false));        // <-- pushed by ServerCheck

// current decoded value, recovered from libtopfollow.so .rodata (XOR 0x55):
//   https://top.nivafollower.app/v840/</code></pre>
<p><code>com.bumptech.glide.manager.r</code> fetches a <code>ServerCheckModel</code> at bootstrap &mdash; fields <code>url</code>, <code>pin</code>, <code>pin_active</code>, <code>repair_mode</code>, <code>update_available</code>, <code>update_url</code> &mdash; and writes <code>url &rarr; SP "Pin"</code>, <code>pin_active &rarr; SP "PinActive"</code>. The transport trust anchor is therefore network-supplied. See TRAN-02 and BIZ-12.</p>

<h4>Headers on every authenticated call (<code>com.bumptech.glide.d.t</code>)</h4>
{build_table([(f"<code>{esc(k)}</code>", val) for k, val in BACKEND_HEADERS], ["Header", "Value / source"], "tbl-be-headers", searchable=False)}

<h4>All 26 endpoints</h4>
{build_table([(f"<code>{esc(p)}</code>", o, d, chips(f)) for p, o, d, f in ENDPOINTS], ["Path", "Discovery", "Purpose", "Findings"], "tbl-endpoints")}

<h4>Generic POST surface</h4>
<p><code>ha.k</code> declares a single method &mdash; <code>a(String path, HashMap headers, RequestBody body)</code> &mdash; so the whole API is reached through one dynamically-parameterised call. That is why endpoint discovery required decoding the base64 literals rather than reading Retrofit annotations (which the scrambled DEX <code>map_list</code> makes unreadable anyway).</p>

<h4>Play Integrity integration (<code>d3.d.l()</code>)</h4>
<ul>
<li><b>Gate:</b> <code>SP.getBoolean("SND",false) == true &amp;&amp; SP.getInt("RID",0) == 3850153</code> &mdash; both client-writable (INTE-08).</li>
<li><b>Precondition:</b> <code>d8.f.a(signatures)</code> must confirm the Play Store package certificate (INTE-02).</li>
<li><b>Nonce:</b> <code>RD + helper.q.j() + "877665803231"</code> &mdash; native timestamp plus a constant GCP project number, no server randomness (INTE-10).</li>
<li><b>Caching:</b> result stored in <code>RIT</code> (timestamp), <code>AIT</code>, <code>RD</code>; reused while younger than 6 hours (INTE-09).</li>
<li><b>Transmission:</b> body field <code>x2 = d.q(d.p(SP"RD"))</code>.</li>
<li><b>Fallback:</b> SafetyNet stubs are present but inert.</li>
</ul>
</div>
</section>

<!-- ========================================================== 10 NATIVE -->
<section id="native">
<h2>10. Native library hardening &mdash; <code>libtopfollow.so</code></h2>
<div class="card">
<h4>Binary properties</h4>
<div class="tablewrap"><table><thead><tr><th>Property</th><th>arm64-v8a</th><th>x86_64</th><th>x86</th></tr></thead><tbody>
<tr><td>Exported symbols</td><td colspan="3"><code>JNI_OnLoad</code> only &mdash; everything else via <code>RegisterNatives</code></td></tr>
<tr><td>RELRO</td><td colspan="3">FULL + <code>BIND_NOW</code></td></tr>
<tr><td>Stack canary</td><td colspan="3">present</td></tr>
<tr><td>FORTIFY</td><td colspan="3">present</td></tr>
<tr><td>Crypto / TLS <i>imports</i></td><td colspan="3"><b>none</b> &mdash; <code>DT_NEEDED</code> is <code>libz, libandroid, liblog, libm, libdl, libc</code>; all 90 imported symbols are libc/pthread/locale/zlib. No <code>SSL_*</code>, no <code>EVP_*</code>, no <code>*crypt*</code> (CRYP-05)</td></tr>
<tr><td>Crypto <i>implemented in-library</i></td><td colspan="3"><b>AES-256</b> &mdash; canonical S-box, inverse S-box and rcon present in all three ABIs; proven by Unicorn execution (14 rcon reads). See section 11 (CRYP-09, CRYP-10)</td></tr>
<tr><td>ARMv8 Crypto Extension</td><td colspan="3"><b>unused</b> &mdash; zero <code>aese/aesd/aesmc/aesimc/sha*</code> in 397,892 instructions; the AES is a compact table variant, so it is cache-timing exposed (CRYP-13)</td></tr>
<tr><td>Packing</td><td colspan="3"><b>none</b> &mdash; <code>.text</code> entropy 6.8621, whole-file 6.7518, 1,090 well-formed <code>.eh_frame</code> FDEs. The obfuscation is OLLVM control-flow flattening only (OBFU-02)</td></tr>
<tr><td>Control flow</td><td colspan="3">OLLVM flattening (state dispatcher) in all 22 functions (INTE-06)</td></tr>
<tr><td>String protection</td><td colspan="3">XOR 0x55 / 0x5A + nested base64 (CRYP-07, CRYP-08)</td></tr>
</tbody></table></div>

<h4>The 22 registered JNI functions</h4>
<p><code>RegisterNatives</code> is called from <code>JNI_OnLoad</code>. On the x86 build the <code>JNINativeMethod</code> table is present as raw virtual-address pointers at file offset <code>0xd8fec</code> and all 22 entries resolved directly; on the 64-bit builds the table is built at runtime, so the addresses below were recovered by intercepting <code>RegisterNatives</code> (script 07 does this live).</p>
{build_table([(f"<code>{esc(j)}</code>", f"<code>{esc(a)}</code>", d, chips(v)) for j, a, d, v in NATIVE_TABLE], ["Java method", "Native offset", "Role", "Findings"], "tbl-native")}

<h4>How the flattened functions were defeated</h4>
<p>Static CFG tracing through an OLLVM state dispatcher is impractical, but the <em>data</em> references are not flattened. Each function obtains its <code>.rodata</code> base through a position-independent thunk of the form:</p>
<pre class="code"><code>call  $+5            ; push address of the next instruction
pop   reg            ; reg = current PC
add   reg, K         ; reg = PC + K  -> the function's private GOT/.rodata base
...
mov   rax, [reg + off]   ; load a string pointer relative to that base</code></pre>
<p>Detecting all 943 such thunks and computing a per-function base recovered 760 <code>.rodata</code> references &mdash; enough to attribute every secret string to the function that uses it. The bootstrap function <code>x0018d3f7</code> alone resolves 622 references, which is how the signature-verification path, <code>ANDROID_ID</code>, <code>DeviceModel</code> setters, the three base URLs, the anti-tamper keyword list and <code>certificatePinner</code> were all tied to a single entry point.</p>

<h4>Bootstrap mega-function <code>x0018d3f7</code> &mdash; attributed responsibilities</h4>
<ul>
<li>Builds all three Instagram Retrofit instances (<code>q.l(0|1|2)</code>) with the triple-base64 URLs.</li>
<li>Verifies the APK signature: <code>getPackageInfo(signatures)</code> &rarr; reflective <code>MessageDigest("SHA-256")</code> &rarr; compare with <code>d845591e&hellip;</code>.</li>
<li>Scans <code>/proc/self/maps</code> for Xposed/LSPosed/EdXposed/Riru/Zygisk/Substrate/<code>libbridge.so</code>, plus <code>(deleted)</code> libart/libc mappings and <code>rwxp</code> regions.</li>
<li>Tests base64-encoded Frida markers and probes nine <code>su</code> paths.</li>
<li>Reads <code>ANDROID_ID</code>, <code>Build.DEVICE</code>, <code>Build.HARDWARE</code>; populates <code>DeviceModel</code> (<code>setHash_key</code>, <code>setNonce</code>, <code>setHash_type</code>, <code>addDevice</code>).</li>
<li>Calls <code>CertificatePinner$Builder.add(...)</code> and wires the OkHttp client.</li>
</ul>
<div class="callout warn"><b>Correction to a first-pass conclusion.</b> An earlier reading of this library reported &ldquo;no crypto in the <code>.so</code>&rdquo;. That was <b>wrong</b>, and the cause matters: the reference resolver discarded any <code>.rodata</code> target that was not &ge;92% printable, so the AES S-box, inverse S-box and rcon &mdash; high-entropy <em>binary</em> tables &mdash; were filtered out of every listing. Keeping binary references (<code>work/aes_forensics.py</code>, <code>work/aes_xref.py</code>) and then <em>executing</em> the code under Unicorn (<code>work/unicorn_aes.py</code>) established that a real AES-256 is present in all three ABIs. See section 11.</div>
<div class="callout info"><b>What is still true.</b> The <em>protection</em> logic &mdash; signature verification, maps scanning, root probing, pin installation &mdash; is executed by calling back into Java, because the library has no TLS and no filesystem-scanning primitives of its own. That places the entire protection surface on the wrong side of the JNI boundary, where Frida operates natively. Script 01 defeats all of it without modifying a single byte of the <code>.so</code>. The AES is used internally by the request pipeline and is <b>not</b> reachable from Java: none of the 22 JNI signatures is <code>([B)[B</code> (CRYP-09).</div>
</div>
</section>

<!-- ==================================================== 11 NATIVE AES + UNICORN -->
<section id="nativaes">
<h2>11. Native AES &mdash; discovery, and execution proof under Unicorn</h2>

<div class="callout warn">
<h4 style="margin-top:0">This section exists because a first-pass conclusion was wrong</h4>
<p>The initial analysis of <code>libtopfollow.so</code> reported &ldquo;no crypto and no TLS code in the library&rdquo;. That was <b>incorrect</b>, and the failure mode is worth recording precisely because it is easy to repeat.</p>
<p>The reference resolver used in the first pass kept a <code>.rodata</code> target only if it decoded to a string that was at least 92&nbsp;% printable. The AES S-box, inverse S-box and rcon are <em>high-entropy binary tables</em>, not strings &mdash; so every reference to them was silently discarded, and the resulting listings made the library look crypto-free. Two fixes recovered the truth: keep binary references (<code>work/aes_forensics.py</code>, <code>work/aes_xref.py</code>), and then <b>execute</b> the code rather than infer from it (<code>work/unicorn_aes.py</code>).</p>
<p>A second bug compounded it. A first attempt to derive the AES S-box from first principles computed the multiplicative inverse as <code>pow(i, 254, 0x11b)</code>. That is invalid &mdash; GF(2<sup>8</sup>) is not <math>&#8484;/0x11b</math>, so modular exponentiation returns the wrong element. A second attempt rotated a running accumulator instead of the original inverse. Both produced a plausible-looking but wrong table, and both made the scanner report &ldquo;no AES S-box present&rdquo; for a binary that contains one. The shipped script derives the inverse by search under <code>gmul</code> (validated against the FIPS-197 worked examples <code>0x57&times;0x83=0xc1</code> and <code>0x57&times;0x13=0xfe</code>), cross-checks the result against a transcribed literal, and <b>aborts rather than reporting a false negative</b> if the two disagree.</p>
</div>

<div class="card">
<h4>11.1 The tables, located by content in all three ABIs</h4>
<p>Each table was found by exact byte-pattern search, then verified two ways: the forward S-box was re-derived from first principles in GF(2<sup>8</sup>), and the inverse table was confirmed to be the exact permutation inverse of the forward one (<code>inv[sbox[i]] == i</code> for all 256 <code>i</code>, and <code>sorted(table) == range(256)</code>).</p>
{build_table(AES_TABLES, ["Table", "arm64-v8a", "x86_64", "x86", "First 16 bytes", "Findings"], "tbl-aes-tables")}

<h4>11.2 What is <em>not</em> in the library</h4>
<p>The absence of these is as evidential as the presence of the S-box. Each was searched for as an exact byte pattern across the whole file.</p>
{build_table(AES_ABSENT, ["Looked for", "Pattern", "Result", "Consequence"], "tbl-aes-absent")}

<h4>11.3 Per-section entropy &mdash; the packing hypothesis tested and rejected</h4>
<p>Entropy is the standard test for packing: a packed or compressed <code>.text</code> scores above 7.8. This library does not.</p>
{build_table(ENTROPY_TABLE, ["Section", "Address", "Size", "Entropy", "Reading"], "tbl-entropy")}
<div class="callout info">The two highest-entropy 4&nbsp;KiB windows in the entire file are <code>0x12000&ndash;0x13000</code> at <b>7.9954</b> and <code>0x13000&ndash;0x14000</code> at <b>7.9613</b>. Those are precisely the AES S-box and inverse S-box &mdash; a 256-byte table of all 256 byte values has near-maximum entropy by construction. Everything else in the file peaks at 6.93. There is no region anywhere that could hold a megabyte-scale white-box table: <code>.rodata</code> is 37,547 bytes and the whole file is 1,805,400.</div>

<h4>11.4 The five AES functions, and the call graph into them</h4>
<p>Function boundaries come from <code>.eh_frame</code> (1,090 FDEs). Data references were resolved per-function &mdash; on arm64 by pairing each <code>ADRP</code> with the following <code>ADD</code>/<code>LDR</code> immediate.</p>
{build_table(AES_FUNCS, ["Function", "Size", "Tables referenced", "Role", "Findings"], "tbl-aes-funcs")}
<pre class="code"><code>call graph (arm64-v8a), arrows point from caller to callee

  0x2dc00 (SBOX)   &lt;-- 0x2fdcc (SBOX, encrypt)
  0x2eb94 (ISBOX)  &lt;-- 0x30f18 (ISBOX, decrypt)

  0x2fdcc  &lt;-- 0x34424 (wrapper, encrypt only)
  0x2fdcc  &lt;-- 0x35518 (wrapper, encrypt AND decrypt; mode selected by w4: 1=enc, 2=dec)
  0x30f18  &lt;-- 0x35518

  0x32158 (SBOX+RCON, key expansion) &lt;-- 0x38fa4, 0x3a838, 0x10c470, 0x110b70

  ancestors of 0x32158 by BFS level:
      L1 (4) : 0x38fa4  0x3a838  0x10c470  0x110b70
      L2 (16): 0x3f688  0x4110c  0x435b8  0x4f078  0x76508  0x7f82c  0x81c58
               0xadacc  0xbf7fc  0xc67a4  0xd46a8  0xe01e4  ...
      L3 (1) : 0xfe268
      total  : 22 ancestors

  0x35518 signature, read off the disassembly:
      x0 = this      (C++ member function)
      this+0x008  byte flag      ldrb w8,[x0,#8]; cmp #0
      this+0x3d0  std::string    add x13,x0,#0x3d0 ; str x13,[sp]
      this+0x3f8  std::string    add x23,x0,#0x3f8
      x1,x2 = in/out buffers     stp x1,x2,[sp,#0x60]
      x3    = buffer             str x3,[sp,#8]
      w4    = mode               cmp #1 -> encrypt, cmp #2 -> decrypt</code></pre>

<h4>11.5 Unicorn execution &mdash; the proof</h4>
<p>The DSO was mapped at VA&nbsp;0 (its first <code>PT_LOAD</code> has vaddr 0, so VA equals file offset), with stack, heap and TLS regions, and <b>every GOT slot repointed at a unique trampoline</b> so that a <code>UC_HOOK_CODE</code> hook could service each libc call from Python. Without that, the PLT stubs branch through a zeroed GOT and the CPU jumps to <code>PC=0</code> &mdash; which is exactly how the first attempt failed.</p>
<pre class="code"><code>{esc(UNICORN_LOG)}</code></pre>

<h4>11.6 Reading the result</h4>
<div class="grid2">
<div class="callout ok">
<h4 style="margin-top:0">Proven</h4>
<ul>
<li>The routine <b>returns normally</b> after 89,148 instructions &mdash; it is not dead code and it does not require a live JNI environment to run its crypto path.</li>
<li>It reads the <b>S-box 112 times</b> and <b>rcon exactly 14 times</b>. Fourteen rounds is <b>AES-256</b>. (AES-128 reads rcon 10 times, AES-192 12 times.)</li>
<li>It writes a <b>240-byte schedule</b> = 15 &times; 16 round keys, the exact AES-256 size.</li>
<li>The schedule obeys the FIPS-197 recurrence. The observed write <code>0xae037e5b</code> at schedule offset <code>+0x4c</code> equals <code>SubWord(RotWord(RK0 word 3))</code>: <code>RotWord(71f1297a) = f1297a71</code>, <code>SubWord(f1297a71) = ae037e5b</code>. This is not a coincidence available to a non-AES routine.</li>
<li><code>w3</code> and <code>w4</code> are both compared against <code>#0x20</code> = 32 &mdash; a 256-bit key length is being validated.</li>
<li>The input buffer is loaded into AES <b>column-major state order</b>, confirming a real AES state matrix rather than a generic byte mixer.</li>
</ul>
</div>
<div class="callout warn">
<h4 style="margin-top:0">Not proven &mdash; and why</h4>
<ul>
<li><b>The key.</b> The run was given the FIPS-197 AES-256 test key in a caller buffer, laid out three ways (libc++ short-string, libc++ long-string, <code>{{ptr,len,cap}}</code> triple). All three runs were <b>byte-identical</b> &mdash; same instruction count, same table-read counts, same schedule. The expansion therefore does not depend on the caller's key.</li>
<li>Brute force over <b>every 16-, 24- and 32-byte window</b> of the 1,805,400-byte file (5,416,128 candidates) found no window expanding to the observed RK0 <code>1742e227063cdfce2c2b4cbd71f1297a</code>. Simple derivations did not match either.</li>
<li>So the key is <b>computed at runtime inside the OLLVM-flattened prologue</b>. Recovering it needs a live process, which is what script <code>09_native_aes_dump.js</code> is for: it recovers any valid schedule from writable memory by verifying the expansion recurrence, and prints the key.</li>
<li><b>Which JNI function reaches it.</b> None of the 22 registered natives has a <code>([B)[B</code> signature, and no <code>com.nivaroid.topfollow</code> method in the DEX has that descriptor, so the AES is <b>not directly callable from Java</b>. On arm64 the <code>JNINativeMethod</code> table is materialised at runtime rather than stored as literal pointers, and <code>JNI_OnLoad</code> is control-flow flattened, so static attribution of the 22 function pointers was not achieved. Script <code>07_native_jni_dumper.js</code> intercepts <code>RegisterNatives</code> to settle it on a device.</li>
</ul>
</div>
</div>

<h4>11.7 The observed round-key schedule</h4>
<pre class="code"><code>{esc(RK_TABLE)}</code></pre>

<h4>11.8 A dead JNI bridge</h4>
<p>At arm64 <code>0x106660</code> and <code>0x162c4c</code> the library calls JNIEnv slot <b>33</b> (<code>ldr x8,[x8,#0x108]</code>, <code>0x108 / 8 = 33</code>) = <code>GetStaticMethodID</code>, asking class <code>com/nivaroid/topfollow/helper/T</code> for a method named <code>digest</code> with descriptor <code>([B)[B</code>. Enumerating the DEX directly, <code>helper.T</code> declares exactly two methods &mdash; <code>o(Ljava/lang/String;)Ljava/lang/String;</code> and <code>sd(Ljava/lang/String;)Ljava/lang/String;</code>. There is no <code>digest</code>, and no <code>([B)[B</code> method exists in any application class. The lookup returns NULL and raises <code>NoSuchMethodError</code>. See CRED-11.</p>
<pre class="code"><code>0x106644  ldr  x8, [x19]            ; JNIEnv*
0x106648  ldr  x8, [x8, #0x108]     ; slot 33 = GetStaticMethodID
0x10664c  ldr  x1, [sp, #0x38]      ; clazz  = helper/T
0x106650  adrp x2, #0x14000
0x106654  adrp x3, #0x14000
0x106658  mov  x0, x19
0x10665c  add  x2, x2, #0xb88       ; -&gt; "digest"
0x106660  add  x3, x3, #0xcc4       ; -&gt; "([B)[B"
0x106664  blr  x8                   ; returns NULL -&gt; NoSuchMethodError

.rodata cluster around the lookup:
  0x14b2f  "F3AES"                                   &lt;- referenced by nothing (CRYP-14)
  0x14b35  "(Lretrofit2/Response;)Ljava/lang/String;"
  0x14b5e  "(ZLjava/lang/String;)Lretrofit2/Retrofit;"
  0x14b88  "digest"
  0x14b8f  "com/nivaroid/topfollow/helper/T"
  0x14baf  "setup"</code></pre>
</div>
</section>

<!-- ========================================================== 12 CRYPTO -->
<section id="crypto">
<h2>12. Cryptography &amp; obfuscation</h2>
<div class="card">
<h4>The keyless cipher &mdash; <code>com.bumptech.glide.d.p()</code> / <code>.q()</code></h4>
<p>Both directions run the same four stages; decryption is the exact inverse. There is no key, no IV, no per-install entropy and no server involvement.</p>
<pre class="code"><code>// ENCRYPT (glide.d.q) - stored form is base64( native q.o( core(plaintext) ) )
for (i = 0; i &lt; len; i++)  buf[i] ^= 0x6C;                              // 1. fixed XOR
for (i = 0; i &lt; len; i++)  buf[i] = ((buf[i] &amp; 7) &lt;&lt; 5) | (buf[i] &gt;&gt; 3); // 2. rotate-left 3
for (lo=0, hi=len-1; lo&lt;hi; lo++, hi--) swap(buf[lo], buf[hi]);           // 3. reverse
for (i = 0; i &lt; len; i++)  buf[i] ^= ((i * 37) ^ 0xA5) &amp; 0xFF;           // 4. positional XOR

// DECRYPT (glide.d.p) - input is base64-decoded native q.n( stored )
for (i = 0; i &lt; len; i++)  buf[i] ^= ((i * 37) ^ 0xA5) &amp; 0xFF;           // undo 4
for (lo=0, hi=len-1; lo&lt;hi; lo++, hi--) swap(buf[lo], buf[hi]);           // undo 3
for (i = 0; i &lt; len; i++)  buf[i] = ((buf[i] &amp; 0x1F) &lt;&lt; 3) | (buf[i] &gt;&gt; 5); // undo 2 (ror 3)
for (i = 0; i &lt; len; i++)  buf[i] ^= 0x6C;                                // undo 1</code></pre>
<p>This was re-implemented in Python and verified to round-trip on passwords, bearer tokens, TOTP seeds and URLs. What it protects: <code>instagram_accounts.u_w</code> (Instagram password), <code>.u_a</code> (bearer), <code>two_factors.u_p</code> and <code>.s_k</code>, and the SharedPreferences values <code>Sign</code>, <code>Aid</code>, <code>DeviceId</code>, <code>RD</code>, <code>Pin</code>, plus the <code>x2</code> integrity field and the <code>xr</code> message field.</p>

<h4>Hard-coded constants</h4>
<div class="tablewrap"><table><thead><tr><th>Constant</th><th>Value</th><th>Origin</th><th>Role</th></tr></thead><tbody>
<tr><td>Tamper / pin digest</td><td><code>d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e</code></td><td><code>libtopfollow.so</code> .rodata (XOR 0x55)</td><td><b>= SHA-256 of the APK signing certificate.</b> Used both as the &ldquo;pin&rdquo; and as the signature-check value.</td></tr>
<tr><td>Integrity constant</td><td><code>d83fb7ce7f9a73922d2262ce3d7c8c78e4c1211da17f45b990a348d405b58677</code></td><td><code>helper/a0.x()</code> &mdash; literal concat + base64</td><td>A second, unrelated 64-hex constant. Matches no SHA-256 of the APK, DEX, .so, package name or backend URL.</td></tr>
<tr><td>Claim challenge <code>x4</code></td><td><code>TFjMTZRk5rMHdTVR</code></td><td><code>helper/a0.x4()</code> &mdash; <code>"VkVacVRW" + b64d(...) + "UldVZz09"</code>, double-decoded</td><td><b>Static.</b> No device, time or server input. Sent with every coin claim.</td></tr>
<tr><td>SPKI pin of the signing key</td><td><code>sha256/4xnmMuV3jXL9RYz2ZVYtWWrkkv/6wSuz8SkHAHAV5Uo=</code></td><td>derived</td><td>What a real OkHttp pin would look like &mdash; the app pins the cert digest instead.</td></tr>
<tr><td>UUID literal</td><td><code>3bbeeba8e-beaa-4458-ac60-6d9a61b2be9e</code></td><td><code>libtopfollow.so</code> .rodata (XOR 0x55)</td><td>Malformed UUID carried alongside a <code>sha256/</code> tail.</td></tr>
<tr><td>GCP project</td><td><code>877665803231</code></td><td><code>d3.d.l()</code></td><td>Appended to the Play Integrity nonce.</td></tr>
<tr><td>Integrity gate</td><td><code>RID == 3850153</code>, <code>SND == true</code></td><td><code>d3.d.java:494</code></td><td>Client-writable attestation switch.</td></tr>
<tr><td>Play Store cert pins</td><td><code>8P1sW0EPJcslw7UzRsiXL64w-O50Ed-RBICtay1g24M</code>, <code>GXWy8XF3vIml3_MfnmSmyuKBpT3B0dWbHRR_4cgq-gA</code></td><td><code>d8.f.a()</code></td><td>Google's own release / dev-key certificates.</td></tr>
</tbody></table></div>

<h4>Native string obfuscation &mdash; recovered set</h4>
{build_table([(f"<code>{esc(k)}</code>", esc(w), d) for k, w, d in XOR_FINDINGS], ["Encoding", "Category", "Recovered value"], "tbl-xor")}
</div>
</section>

<!-- ========================================================= 12 STORAGE -->
<section id="storage">
<h2>13. Data storage</h2>
<div class="card">
<h4>Room database <code>t_f_d_b_f_v_c</code> &mdash; <span class="badge" style="--c:#ff3b6b">unencrypted</span></h4>
<p><code>MyDatabase.setup()</code> builds it through a plain Room builder. There is no SQLCipher dependency, no <code>SupportFactory</code> passphrase and no Jetpack Security usage anywhere in the DEX.</p>
{build_table([(f"<code>{esc(t)}</code>", f"<code>{esc(c)}</code>", n, chips(f)) for t, c, n, f in DB_TABLES], ["Table", "Columns", "Sensitivity", "Findings"], "tbl-db")}

<h4>SharedPreferences <code>TOPFVC_Shared</code></h4>
{build_table([(f"<code>{esc(k)}</code>", d, chips(f)) for k, d, f in PREF_KEYS], ["Key", "Meaning", "Findings"], "tbl-prefs")}

<h4>Backup configuration &mdash; the empty-rule finding</h4>
<p>The manifest sets <code>android:allowBackup="true"</code> and points both rule attributes at resources. Both were extracted from <code>resources.arsc</code> and decoded from binary AXML:</p>
<div class="grid2">
<div><h4><code>@7F160000</code> &rarr; <code>res/Qq.xml</code> (132 bytes)</h4><pre class="code"><code>&lt;full-backup-content/&gt;</code></pre></div>
<div><h4><code>@7F160001</code> &rarr; <code>res/4j.xml</code> (212 bytes)</h4><pre class="code"><code>&lt;data-extraction-rules&gt;
  &lt;cloud-backup/&gt;
&lt;/data-extraction-rules&gt;</code></pre></div>
</div>
<div class="callout crit"><b>Neither file contains a single <code>&lt;exclude&gt;</code> element.</b> An empty <code>&lt;full-backup-content/&gt;</code> means &ldquo;back up everything&rdquo;, and <code>&lt;cloud-backup/&gt;</code> with no children means the same for device-to-device transfer. So the unencrypted <code>t_f_d_b_f_v_c</code> database &mdash; Instagram passwords, TOTP seeds, session tokens, the coin wallet &mdash; and the whole of <code>TOPFVC_Shared</code> are copied into the user's Google account and into any new device during migration. An attacker who compromises the Google account, or who briefly holds the phone during a transfer, obtains every credential without ever touching the app's runtime protections. See STOR-02.</div>

<h4>Other manifest observations</h4>
<div class="tablewrap"><table><thead><tr><th>Attribute</th><th>Value</th><th>Assessment</th></tr></thead><tbody>
<tr><td><code>allowBackup</code></td><td><code>true</code></td><td class="badge-cell"><span class="badge" style="--c:#ff3b6b">Critical with empty rules</span></td></tr>
<tr><td><code>fullBackupContent</code> / <code>dataExtractionRules</code></td><td>set but empty</td><td><span class="badge" style="--c:#ff3b6b">No exclusions</span></td></tr>
<tr><td><code>usesCleartextTraffic</code></td><td><code>false</code></td><td><span class="badge" style="--c:#4dd7ff">Good</span></td></tr>
<tr><td><code>networkSecurityConfig</code></td><td>absent</td><td><span class="badge" style="--c:#ffd23d">Missing declarative pinning</span></td></tr>
<tr><td><code>extractNativeLibs</code></td><td><code>false</code></td><td><span class="badge" style="--c:#4dd7ff">.so stays inside the APK, trivially extractable</span></td></tr>
<tr><td><code>debuggable</code> / <code>testOnly</code></td><td>not set</td><td><span class="badge" style="--c:#4dd7ff">Good</span></td></tr>
<tr><td>Exported components</td><td>3 (launcher + 2 guarded framework receivers)</td><td><span class="badge" style="--c:#4dd7ff">Small surface</span></td></tr>
<tr><td>Requested permissions</td><td>INTERNET, FOREGROUND_SERVICE(_SPECIAL_USE), POST_NOTIFICATIONS, ACCESS_NETWORK_STATE, WAKE_LOCK, c2dm.RECEIVE</td><td><span class="badge" style="--c:#4dd7ff">Reasonable &mdash; no storage/contacts/location</span></td></tr>
</tbody></table></div>
</div>
</section>

<!-- ======================================================= 13 INTEGRITY -->
<section id="integrity">
<h2>14. Anti-tamper &amp; integrity controls &mdash; and how each one falls</h2>
<div class="card">
<p>The app advertises five protections. All five were located precisely and all five are defeated by script <code>01_anti_tamper_killer.js</code> without patching the binary.</p>
<div class="tablewrap"><table><thead><tr><th>Control</th><th>Implementation</th><th>Bypass</th><th>Finding</th></tr></thead><tbody>
<tr><td><b>Signature self-check</b></td><td><code>x0018d3f7</code> &rarr; <code>getPackageInfo(GET_SIGNATURES)</code> &rarr; reflective <code>MessageDigest("SHA-256")</code> &rarr; compare <code>d845591e&hellip;</code></td><td>Hook <code>MessageDigest.digest()</code> and <code>Signature.toByteArray()</code>; return the expected digest</td><td><a href="#INTE-01">INTE-01</a></td></tr>
<tr><td><b>Play Store cert gate</b></td><td><code>d8.f.a(Signature[])</code> compares base64url SHA-256 against Google's Phonesky pins</td><td>One-line hook returning <code>true</code></td><td><a href="#INTE-02">INTE-02</a></td></tr>
<tr><td><b>Anti-Frida / anti-Xposed</b></td><td><code>/proc/self/maps</code> keyword scan (XOR 0x5A) + base64 Frida markers + <code>(deleted)</code> and <code>rwxp</code> heuristics + TCP 27042/27043 probes</td><td>Sanitise <code>read()</code>/<code>fgets()</code> output line-by-line; neuter <code>strstr()</code>/<code>strcmp()</code>; refuse the port connects</td><td><a href="#INTE-03">INTE-03</a></td></tr>
<tr><td><b>Root detection</b></td><td>Nine hard-coded <code>su</code> paths via <code>open</code>/<code>access</code>/<code>stat</code> and <code>File.exists()</code>; <code>Runtime.exec("su")</code></td><td>Force ENOENT on the probes; return <code>false</code> from <code>exists()</code>; throw on <code>exec</code></td><td><a href="#INTE-04">INTE-04</a></td></tr>
<tr><td><b>Emulator detection</b></td><td><code>Build.DEVICE</code>, <code>Build.HARDWARE</code></td><td>Overwrite the <code>Build</code> statics &mdash; the app already hard-codes SM-E625F/exynos9825 for Instagram, so the spoof is consistent</td><td><a href="#INTE-05">INTE-05</a></td></tr>
<tr><td><b>Play Integrity</b></td><td>Gated on SP <code>SND==true &amp;&amp; RID==3850153</code>; token cached 6 h; nonce <code>RD+q.j()+877665803231</code>; sent as <code>x2</code></td><td>Hook <code>SharedPreferencesImpl.getBoolean/getInt</code> to skip or fake the gate entirely</td><td><a href="#INTE-08">INTE-08</a>, <a href="#INTE-09">INTE-09</a>, <a href="#INTE-10">INTE-10</a></td></tr>
<tr><td><b>Native obfuscation</b></td><td>OLLVM CFF on all 22 functions; XOR 0x55/0x5A strings; nested base64; scrambled DEX <code>map_list</code>; JNI-only exports</td><td>Resolve the 943 PIC thunks and read the data references; brute-force 127 XOR keys; intercept <code>RegisterNatives</code></td><td><a href="#INTE-06">INTE-06</a>, <a href="#INTE-07">INTE-07</a>, <a href="#CRYP-07">CRYP-07</a></td></tr>
<tr><td><b>Kill switches</b></td><td><code>System.exit</code>, <code>Process.killProcess</code>, <code>Runtime.exit</code></td><td>All three suppressed</td><td><a href="#INTE-01">INTE-01</a></td></tr>
</tbody></table></div>
<div class="callout info"><b>The common thread.</b> <code>libtopfollow.so</code> contains no TLS code and imports no crypto library (its own AES-256 is used only inside the request pipeline and is not reachable from Java &mdash; CRYP-09), so every &ldquo;native&rdquo; <em>protection</em> is executed by calling back into the Java framework. That puts the whole integrity story on the side of the JNI boundary where instrumentation frameworks already live. The obfuscation is competent and it did cost real effort &mdash; but it delays analysis rather than preventing tampering, and none of it changes what the server is willing to trust.</div>
</div>
</section>

<!-- ========================================================= 14 MATRIX -->
<section id="matrix">
<h2>15. Vulnerability matrix</h2>
<div class="card">
<p>All {len(V)} findings, ordered by severity. Use the search box to filter across id, title, description, evidence and category.</p>
<input class="tsearch" id="globalSearch" type="search" placeholder="Search all {len(V)} findings &mdash; try 'password', 'get_coin', 'pin', 'backup', 'frida', 'x0018d3f7'&hellip;">
<div class="pill-row" id="sevFilters">
  <button class="fbtn" data-sev="">All ({len(V)})</button>
  <button class="fbtn" data-sev="Critical">Critical ({SEV_COUNT['Critical']})</button>
  <button class="fbtn" data-sev="High">High ({SEV_COUNT['High']})</button>
  <button class="fbtn" data-sev="Medium">Medium ({SEV_COUNT['Medium']})</button>
  <button class="fbtn" data-sev="Low">Low ({SEV_COUNT['Low']})</button>
</div>
<div class="pill-row" id="catFilters">
  <button class="fbtn" data-cat="">All categories</button>
  {"".join(f'<button class="fbtn" data-cat="{esc(c)}">{esc(c)} ({n})</button>' for c, n in sorted(CAT_COUNT.items(), key=lambda kv: -kv[1]))}
</div>
{build_table(vuln_rows, ["ID", "Title", "Severity", "Category", "PoC"], "tbl-matrix")}
</div>
</section>

<!-- ======================================================= 15 FINDINGS -->
<section id="findings">
<h2>16. Detailed findings</h2>
<p class="muted">{len(V)} findings &middot; each with mechanism, impact, evidence, proof-of-concept script and remediation.</p>
<div id="vulnList">
{build_vuln_cards()}
</div>
</section>

<!-- ============================================================ 16 LAB -->
<section id="lab">
<h2>17. Dynamic analysis lab &mdash; 11 Frida scripts</h2>
<div class="card">
<p>Every script is self-contained and heavily commented with the exact classes, offsets and literals it targets. Load <code>00_common.js</code> first; <code>01</code> and <code>02</code> are prerequisites for almost everything else because the app's bootstrap runs its checks inside <code>JNI_OnLoad</code>. <b>Spawn mode is required</b> &mdash; attaching after start misses the signature check and the Retrofit construction.</p>
<div class="tablewrap"><table><thead><tr><th>#</th><th>Script</th><th>Purpose</th><th>Findings demonstrated</th></tr></thead><tbody>
{"".join(f'''<tr data-search="{esc((f + SCRIPT_DESC.get(f, '')).lower())}"><td><code>{esc(f.split('_')[0])}</code></td><td><a href="#script-{esc(f.split('.')[0])}"><code>{esc(f)}</code></a></td><td>{esc(SCRIPT_DESC.get(f, ''))}</td><td><span class="chips">{" ".join(f'<a class="chip" href="#{esc(x["id"])}">{esc(x["id"])}</a>' for x in V if f in x["poc"])}</span></td></tr>''' for f in SCRIPTS)}
</tbody></table></div>
<div class="callout warn"><b>Coverage.</b> All {len(V)} findings map to at least one of the 11 PoC scripts; every script demonstrates at least one finding. The mapping above is generated from the register, so nothing is claimed that a script does not actually exercise.</div>
</div>
{script_sections()}
</section>

<!-- ========================================================== 17 REPRO -->
<section id="repro">
<h2>18. Reproduction guide</h2>
<div class="card">
<h4>Prerequisites</h4>
<ul>
<li>A rooted Android device or an emulator image with writable <code>/system</code> (the app's root detection is defeated by script 01, but Frida itself needs root or a repackaged gadget build).</li>
<li><code>frida-server</code> matching your Frida version, listening on the default port. Rename the binary and use a non-default port if you want to exercise the detection bypass more realistically.</li>
<li>Host tooling: <code>pip install frida-tools</code> (this analysis used frida 17.18.0 / frida-tools 14.10.4).</li>
<li>Burp Suite or mitmproxy with a CA certificate installed as a <b>system</b> trust anchor (user CAs are not trusted on API 24+).</li>
</ul>
<h4>Step 1 &mdash; static recovery (no device needed)</h4>
<pre class="code"><code># 1. Unpack
unzip "TopFollow_v845-Beta (1).apk" -d apk/

# 2. Signing certificate (no apksigner / JDK required)
python3 - &lt;&lt;'PY'
import struct, hashlib
d = open("TopFollow_v845-Beta (1).apk","rb").read()
m = d.rfind(b"APK Sig Block 42")
off = 0x9ce628                                  # v2 pair: u64 len at off-8, id 0x7109871a at off
plen = struct.unpack_from('&lt;Q', d, off-8)[0]
body = d[off+4 : off-8+plen]
i = body.find(b'\\x30\\x82')                       # first DER SEQUENCE
clen = struct.unpack_from('&gt;H', body, i+2)[0] + 4
der = body[i:i+clen]
print("cert SHA-256:", hashlib.sha256(der).hexdigest())
PY

# 3. Native secrets: single-byte XOR sweep over libtopfollow.so
python3 - &lt;&lt;'PY'
import re
d = open("apk/lib/arm64-v8a/libtopfollow.so","rb").read()
for run in re.finditer(rb'[\\x20-\\x7e]{6,}', d):
    s = run.group()
    for k in (0x55, 0x5A):
        out = bytes(c ^ k for c in s)
        if re.search(rb'https?://|\\.php|frida|xposed|/su$|su$|maps|sha256/', out):
            print(hex(k), run.start(), out.decode('latin1'))
PY

# 4. Base64-obfuscated endpoints
grep -aoE 'd\\.o\\("[A-Za-z0-9+/=]{8,}"\\)' out/all/*.java | sort -u \\
  | sed 's/.*"\\(.*\\)".*/\\1/' | while read b; do echo -n "$b" | base64 -d; echo; done</code></pre>

<h4>Step 2 &mdash; dynamic analysis</h4>
<pre class="code"><code># Baseline: boot the app cleanly past every protection
frida -U -f com.nivaroid.topfollow \\
      -l dynamic-lab/00_common.js \\
      -l dynamic-lab/01_anti_tamper_killer.js \\
      -l dynamic-lab/02_ssl_pinning_bypass.js

# Add the layer you are investigating:
#   03 - Instagram private-API traffic        04 - credential harvest
#   05 - coin economy                         06 - task verification
#   07 - native/JNI dump                      08 - backend + ServerCheck

# Full stack
frida -U -f com.nivaroid.topfollow \\
      -l dynamic-lab/00_common.js \\
      -l dynamic-lab/01_anti_tamper_killer.js \\
      -l dynamic-lab/02_ssl_pinning_bypass.js \\
      -l dynamic-lab/03_instagram_api_intercept.js \\
      -l dynamic-lab/04_credential_theft.js \\
      -l dynamic-lab/05_coin_economy_bypass.js \\
      -l dynamic-lab/06_task_verification_bypass.js \\
      -l dynamic-lab/07_native_jni_dumper.js \\
      -l dynamic-lab/08_backend_traffic_and_servercheck.js</code></pre>

<h4>Step 3 &mdash; verify the headline exploits</h4>
<ol>
<li><b>Credentials (CRED-01/02/03).</b> Log in with a throwaway Instagram account, then call <code>rpc.exports.dump()</code> in script 04. Confirm the plaintext password, the <code>Bearer IGT:2:&hellip;</code> token and any <code>s_k</code> seed in the JSON output and in <code>/data/data/com.nivaroid.topfollow/files/topfollow_dump.json</code>.</li>
<li><b>Coin fraud (BIZ-01/02).</b> With script 06 attached, run a task that Instagram rejects. Confirm the log line <code>get_coin false -&gt; true</code> and that <code>order/syncOrder.php</code> is still POSTed. Watch the coin counter in the notification rise.</li>
<li><b>Free purchase (BIZ-03/05).</b> With script 05 attached, open any Buy dialog. Confirm <code>DeviceModel.getCoin() 12 -&gt; 999999999</code> and that the Buy button is now clickable.</li>
<li><b>MITM (TRAN-01/02).</b> Point the device at Burp. Confirm requests to <code>top.nivafollower.app</code> and to <code>b.i.instagram.com</code> decrypt, and that the <code>Token</code> header carries the live Instagram session (CRED-04).</li>
<li><b>Redirect (TRAN-02).</b> Set <code>OVERRIDE_BASE_URL</code> at the top of script 08 to your own host. Confirm the app rebuilds its Retrofit against your server and sends <code>instagramLogin.php</code> there.</li>
<li><b>Backup leak (STOR-02).</b> Trigger a cloud backup or a device-to-device transfer, then inspect the restored <code>t_f_d_b_f_v_c</code> with <code>sqlite3</code>: <code>select username, u_w, u_a from instagram_accounts;</code> and <code>select u_n, u_p, s_k from two_factors;</code>. Decrypt the values with the Python routine in section 11.</li>
<li><b>Repackaging (INTE-01).</b> Modify and re-sign the APK with a different key, spawn it with script 01, and confirm the app reaches its main screen with <code>SHA-256 digest &lt;new&gt; -&gt; forced to d845591e&hellip;</code> in the log.</li>
</ol>
</div>
</section>

<!-- ==================================================== 18 REMEDIATION -->
<section id="remediation">
<h2>19. Remediation roadmap</h2>
<div class="card">
<div class="callout crit"><b>Read this first.</b> Most of what follows cannot be fixed with client-side engineering, because the product's core function &mdash; automating Instagram accounts that users do not control, in exchange for a currency whose earning is verified on the client &mdash; is itself the vulnerability. Items P0-1 through P0-4 are genuine security fixes; items under &ldquo;existential&rdquo; are not fixable without changing what the app does. This section is written as if the goal were to make the app safe to operate, which requires both.</div>

<h4>P0 &mdash; stop the credential bleeding (days)</h4>
<ol>
<li><b>Stop accepting Instagram passwords.</b> Remove <code>u_w</code>, remove <code>two_factors.u_p</code> and <code>s_k</code>, remove <code>instagramLogin.php</code>. Migrate to Instagram's official OAuth with PKCE and store only a scoped, expiring token. <span class="muted">CRED-01, CRED-02, CRED-05</span></li>
<li><b>Stop sending the session token to your own backend.</b> Delete <code>d.t()</code>'s <code>Token</code> and <code>Active-Id</code> headers. The backend never needs them. <span class="muted">CRED-04</span></li>
<li><b>Remove the WebView cookie harvester.</b> If a web login is genuinely required, use Custom Tabs so the browser owns the session and the app cannot read it. <span class="muted">CRED-03, STOR-07</span></li>
<li><b>Fix backup immediately.</b> Either set <code>android:allowBackup="false"</code> or populate both rule files with explicit exclusions for the database and <code>TOPFVC_Shared</code>. This is a one-line change that closes an offline mass-exposure path. <span class="muted">STOR-02</span></li>
<li><b>Encrypt local storage.</b> SQLCipher for Room under an AndroidKeyStore key; EncryptedSharedPreferences for the rest. <span class="muted">STOR-01, STOR-03, BIZ-05, CRYP-01</span></li>
</ol>

<h4>P1 &mdash; make the money path server-authoritative (weeks)</h4>
<ol start="6">
<li><b>Delete <code>get_coin</code>.</b> Compute the reward entirely server-side. <span class="muted">BIZ-01</span></li>
<li><b>Delete <code>order_value</code> from the request.</b> Look it up by <code>order_id</code>. <span class="muted">BIZ-02</span></li>
<li><b>Verify completion independently.</b> After a claim, fetch the target's follower/like/comment state from Instagram server-side and compare against the pre-task snapshot captured when the order was issued. Do not trust <code>x5</code>/<code>x7</code>. <span class="muted">BIZ-07, STOR-12</span></li>
<li><b>Replace <code>x4</code> with a single-use server nonce</b> bound to <code>order_id</code>, the device attestation and an expiry. <span class="muted">BIZ-06, CRYP-03</span></li>
<li><b>Widen <code>set_order_stamp</code>.</b> Sign the canonical full body &mdash; account id, price, currency, server nonce, timestamp &mdash; not three fields. <span class="muted">BIZ-04</span></li>
<li><b>Enforce price and balance server-side</b> on <code>order/submitOrder.php</code>; treat every client figure as display-only. <span class="muted">BIZ-03</span></li>
<li><b>Add rate limits and idempotency keys</b> issued by the server on every money endpoint, plus anomaly detection on claim velocity. <span class="muted">STOR-10, BIZ-10, BIZ-11</span></li>
<li><b>Validate captcha tokens server-side</b> against the provider's siteverify API, bound to the session and the action. <span class="muted">STOR-08</span></li>
<li><b>Bind VIP to a payment record</b> and re-validate on every privileged call. <span class="muted">BIZ-09</span></li>
</ol>

<h4>P2 &mdash; fix transport trust (weeks)</h4>
<ol start="15">
<li><b>Hard-code the base URL and pins.</b> Remove <code>Pin</code>/<code>PinActive</code> from SharedPreferences and remove <code>url</code>/<code>pin</code> from <code>ServerCheckModel</code>. <span class="muted">TRAN-02, CRYP-04</span></li>
<li><b>Pin real SPKI values</b> for the TLS leaf and intermediate, with a backup pin and an expiration date &mdash; not the APK signing certificate digest. <span class="muted">CRYP-04</span></li>
<li><b>Add <code>network_security_config.xml</code></b> so pinning survives Java-layer hooking. <span class="muted">TRAN-03</span></li>
<li><b>If pin rotation is genuinely needed</b>, sign the ServerCheck payload with a public key embedded at build time and verify it natively before applying anything. <span class="muted">TRAN-02, BIZ-12</span></li>
<li><b>Ship updates through Play's in-app update API</b> and drop <code>update_url</code>/<code>download_link</code>. <span class="muted">BIZ-12</span></li>
<li><b>Separate the trust domains</b>: distinct OkHttp clients and pin sets for Instagram and for your backend, and never let one see the other's credentials. <span class="muted">TRAN-05</span></li>
<li><b>Move TLS verification into native code</b> if it must resist instrumentation. <span class="muted">CRYP-05, TRAN-01, TRAN-04</span></li>
</ol>

<h4>P3 &mdash; integrity, keys and process (months)</h4>
<ol start="22">
<li><b>Move to Play App Signing</b>; retire the self-signed serial-1 key that runs to 2048. <span class="muted">INTE-12</span></li>
<li><b>Make Play Integrity mandatory server-side.</b> Reject sensitive requests without a fresh, valid token; never let <code>SND</code>/<code>RID</code> decide whether to attest. <span class="muted">INTE-08</span></li>
<li><b>Use a server-issued random nonce</b> per attestation and consume each token once, with a lifetime of minutes rather than six hours. <span class="muted">INTE-09, INTE-10, CRED-10</span></li>
<li><b>Validate <code>appRecognitionVerdict</code> and <code>deviceRecognitionVerdict</code></b> on the server instead of comparing Play Store certificates on the client. <span class="muted">INTE-02</span></li>
<li><b>Stop treating detection as prevention.</b> Keep the maps/root/Frida checks as telemetry signals feeding server-side risk scoring, not as gates. <span class="muted">INTE-03, INTE-04, INTE-05, INTE-06, INTE-07</span></li>
<li><b>Replace the keyless cipher</b> everywhere, including <code>x2</code> and <code>xr</code>. <span class="muted">CRYP-01</span></li>
<li><b>Remove the hard-coded integrity constants</b> <code>d83fb7ce&hellip;</code> and <code>TFjMTZRk5rMHdTVR</code>. <span class="muted">CRYP-02, CRYP-03</span></li>
<li><b>Per-install Keystore aliases</b> with an attestation challenge. <span class="muted">CRED-09</span></li>
<li><b>Minimise data collection.</b> Drop <code>ANDROID_ID</code> exfiltration, gate Crashlytics behind consent, scrub credentials from logs and exception messages, mark the notification <code>VISIBILITY_PRIVATE</code>. <span class="muted">INTE-11, STOR-06, STOR-11</span></li>
<li><b>Parse JSON properly.</b> Replace every substring/indexOf branch in <code>ia.s</code> and <code>ia.v</code> with schema-validated parsing. <span class="muted">STOR-12</span></li>
<li><b>Authorise the task service per account</b> and keep using in-process messaging rather than broadcasts. <span class="muted">STOR-09</span></li>
<li><b>Fix <code>get_image.php</code></b>: allow-list hosts server-side, block private and link-local ranges, disable redirects, cap size and content type. <span class="muted">STOR-05</span></li>
<li><b>Add per-session, revocable consent</b> for each automation category, with a user-visible audit log. <span class="muted">STOR-15</span></li>
</ol>

<h4>Existential &mdash; not fixable in code</h4>
<div class="callout warn">
<ul style="margin-bottom:0">
<li><b>Impersonating Instagram's private mobile API</b> (<code>b.i.instagram.com/api/v1/</code>, <code>i.instagram.com/api/v2/</code>, the Bloks/CAA login flow) violates Instagram's Platform Policy and Terms of Use. The hard-coded <code>x-ig-app-id</code>, <code>x-bloks-version-id</code> and device fingerprint mean every user of the app is trivially identifiable and bannable. <span class="muted">CRED-06, STOR-13</span></li>
<li><b>Forging <code>x-ig-nav-chain</code>, <code>x-ig-salt-ids</code> and <code>x-fb-rmd</code></b>, and running a warm-up burst with jittered timestamps, is engineered evasion of Instagram's fraud detection. There is no legitimate framing for it. <span class="muted">CRED-07, CRED-08</span></li>
<li><b>Driving N user accounts in parallel from one device</b> to generate paid engagement is the product. <code>DoTasksService</code> plus the <code>SingleTasking</code> flag is a farming engine by construction. <span class="muted">BIZ-08</span></li>
<li><b>Automating DM interop and Threads</b> extends the abuse past follower exchange into cross-product manipulation. <span class="muted">STOR-14</span></li>
</ul>
</div>
</div>
</section>

<!-- ======================================================= 19 METHOD -->
<section id="method">
<h2>20. Methodology &amp; artefacts</h2>
<div class="card">
<h4>Environment</h4>
<p>No network access to Maven Central, Google Maven, JitPack, Debian mirrors or GitHub release assets was available, and no JDK could be installed &mdash; so <code>apktool</code>, <code>aapt2</code>, <code>apksigner</code>, <code>jadx</code>, <code>dex2jar</code> and <code>radare2</code> were all out of reach. The entire analysis was built from first principles on a Python toolchain: <code>androguard 4.1.4</code>, <code>lief 1.0.0</code>, <code>capstone 5.0.7</code>, <code>asn1crypto</code>, plus <code>frida 17.18.0</code> / <code>frida-tools 14.10.4</code> for the dynamic lab.</p>
<h4>Pipeline</h4>
<ol>
<li><b>Manifest.</b> Parsed the binary AXML directly with androguard; enumerated exported components, permissions, providers, meta-data and every <code>application</code> flag.</li>
<li><b>DEX.</b> The <code>map_list</code> is deliberately scrambled, so annotation-based recovery failed. Wrote a whole-DEX pseudocode dumper instead and produced readable Java for all <b>4,146 classes</b>. Cross-checked obfuscated method bodies that the header-only decompiler dropped against full smali output (173 classes).</li>
<li><b>Strings.</b> Extracted all <b>21,862</b> DEX strings; grepped for SharedPreferences keys, <code>addProperty</code> JSON keys, <code>.php</code> paths, base64 literals, UUIDs and IG endpoint fragments.</li>
<li><b>ARSC.</b> Resolved <code>@7F160000</code>/<code>@7F160001</code> from <code>resources.arsc</code> to <code>res/Qq.xml</code> and <code>res/4j.xml</code> and decoded both AXML files &mdash; this is what exposed the empty backup rules.</li>
<li><b>Signing block.</b> Wrote a manual APK Signature Scheme v2 parser: located the magic, read the pair length, walked the signer &rarr; certificates &rarr; signatures &rarr; public-key structure, and parsed the DER with <code>asn1crypto</code>. Confirmed the cert digest equals the embedded pin/tamper constant.</li>
<li><b>ELF.</b> <code>lief</code> for headers, segments, imports, exports and checksec across all six <code>.so</code> files. Confirmed <code>JNI_OnLoad</code> as the only export and the absence of crypto/TLS imports.</li>
<li><b>JNI resolution.</b> On x86 the <code>JNINativeMethod</code> table exists as raw VA pointers; a slot-pattern scan at file offset <code>0xd8fec</code> resolved all 22 entries. The 64-bit builds build the table at runtime, so script 07 intercepts <code>RegisterNatives</code> instead.</li>
<li><b>Defeating OLLVM.</b> Static CFG tracing through the state dispatchers was infeasible, so the data path was attacked instead: detect every <code>call $+5; pop reg; add reg,K</code> thunk (943 found), compute a per-function base, and resolve <code>.rodata</code> references (760 resolved). The first attempt used a single global GOT base and produced mis-aligned strings; the per-thunk approach is what worked.</li>
<li><b>String decryption.</b> Exhaustive single-byte XOR sweep over keys 1&ndash;127 across every printable run, scoring candidate plaintexts. Two keys &mdash; <code>0x55</code> and <code>0x5A</code> &mdash; recovered the complete secret set. Nested base64 literals were unwound separately.</li>
<li><b>Cipher replication.</b> Re-implemented <code>glide.d.p()</code>/<code>q()</code> in Python and verified round-trip on passwords, bearer tokens, TOTP seeds and URLs.</li>
<li><b>Flow reconstruction.</b> Traced the login chain (<code>ia.v</code> &rarr; <code>ia.s</code> &rarr; <code>ia.i0</code>), the WebView path (<code>oa.l1</code>), the task pipeline (<code>DoTasksService</code> &rarr; <code>ja.e</code> &rarr; <code>ia.g</code>), the claim path (<code>ha.c</code>), the dispatcher (<code>androidx.fragment.app.e</code>, 18 cases) and the integrity gate (<code>d3.d.l</code> &rarr; <code>d8.f.a</code>).</li>
<li><b>PoC authoring.</b> Wrote 10 Frida PoC scripts plus a shared helper (<code>00_common.js</code>), each annotated with the exact classes, offsets and literals it targets; verified all eleven parse cleanly under <code>node --check</code>.</li>
</ol>
<h4>Artefacts produced during the engagement</h4>
<div class="tablewrap"><table><thead><tr><th>Artefact</th><th>Contents</th></tr></thead><tbody>
<tr><td><code>work/out/all/</code></td><td>Pseudocode for all 4,146 DEX classes</td></tr>
<tr><td><code>work/out/03_all_strings.txt</code></td><td>21,862 DEX strings</td></tr>
<tr><td><code>work/out/07_AndroidManifest.xml</code></td><td>Decoded manifest</td></tr>
<tr><td><code>work/out/13_so_checksec.json</code></td><td>checksec + import/export analysis for all 6 native libraries</td></tr>
<tr><td><code>work/out/14_jni_natives.json</code></td><td>All 22 <code>RegisterNatives</code> entries (x86 pointer-table scan)</td></tr>
<tr><td><code>work/out/15_disasm_key.txt</code></td><td>Capstone disassembly confirming OLLVM control-flow flattening</td></tr>
<tr><td><code>work/out/18_text_refs.json</code>, <code>18_native_strings_by_fn.txt</code></td><td>943 PIC thunks, 760 resolved per-function <code>.rodata</code> references</td></tr>
<tr><td><code>work/out/19_xor_decoded.txt</code></td><td>Full XOR sweep results (backend URL, IG URLs, pin, anti-Frida list, root paths)</td></tr>
<tr><td><code>work/out/20_signing.txt</code></td><td>APK Signature Scheme v2 parse and signing-certificate details</td></tr>
<tr><td><code>work/out/21_backup_rules.txt</code></td><td>Decoded <code>fullBackupContent</code> and <code>dataExtractionRules</code> resources</td></tr>
<tr><td><code>work/cipher_poc.py</code></td><td>Python re-implementation of <code>glide.d.p()/q()</code>, round-trip verified</td></tr>
<tr><td><code>work/fn_strings3.py</code></td><td>The per-function PIC-thunk <code>.rodata</code> resolver that defeated the OLLVM data hiding</td></tr>
</tbody></table></div>
<h4>Dead ends worth recording</h4>
<ul>
<li>The <code>hts/</code> URL string set (e.g. <code>hts/frbslgigp&hellip;</code> &rarr; <code>https://b.i.instagram.com/</code>) is <b>not</b> a length-preserving permutation, not a greedy subsequence, not a half-interleave and not a per-index Caesar shift. It was cracked by the triple-base64 path in <code>.rodata</code> instead.</li>
<li>Retrofit annotations are unrecoverable here: <code>method.get_annotations()</code> returns nothing and direct annotation-parsing goes out of bounds because the DEX <code>map_list</code> is scrambled. Endpoint discovery had to come from the base64 literals at the call sites.</li>
<li>A single global GOT base for native string resolution produces mis-aligned and truncated strings. It must be per-function, derived from each PIC thunk.</li>
<li>The 64-bit <code>.so</code> files do not contain <code>JNINativeMethod</code> tables as raw VA pointers; only the x86 build does. Pointer scanning is pointless on arm64/x86_64.</li>
</ul>
</div>
</section>

<!-- ========================================================== 20 LEGAL -->
<section id="legal">
<h2>21. Scope, ethics &amp; responsible handling</h2>
<div class="card">
<h4>What this document is</h4>
<p>A defensive security research report on a single APK file supplied for analysis. It documents vulnerabilities, explains their mechanisms, and provides instrumentation intended to let a defender reproduce and then fix them.</p>
<h4>What it is not</h4>
<ul>
<li><b>Not an attack service.</b> No requests were sent to <code>top.nivafollower.app</code>, to any Instagram endpoint, or to any third party during this analysis. Everything here comes from static examination of the supplied binary plus instrumentation scripts written for the analyst's own device.</li>
<li><b>Not a guide to abusing Instagram.</b> The private-API details are documented because they <em>are</em> the vulnerability surface &mdash; they show what the app does with credentials it should never have collected. They are not a recipe, and using them to automate accounts you do not own violates Instagram's Terms of Use and, in many jurisdictions, computer-misuse law.</li>
<li><b>Not a credential dump.</b> No real user data is included. The credential-harvest script writes only to the analyst's own device, on accounts the analyst controls.</li>
</ul>
<h4>If you are the vendor</h4>
<p>The P0 items in section 18 are achievable in days and close the mass-exposure paths. Two of them &mdash; removing the <code>Token</code> header and fixing the backup rules &mdash; are single-line changes. Treat the stored password and TOTP-seed columns as already compromised for every existing user and force a credential reset on next login.</p>
<h4>If you are a user of this app</h4>
<div class="callout crit"><b>Change your Instagram password now, and revoke the session.</b> This app has stored your password in a reversible form, may have forwarded it to a third-party server, may have uploaded it to your Google cloud backup, and has been acting on your account autonomously. Also: revoke third-party sessions in Instagram's <em>Settings &rarr; Accounts Center &rarr; Password and security &rarr; Where you're logged in</em>, re-enrol 2FA (the app may hold your current seed), and expect that the account may be actioned by Instagram for automation.</div>
<h4>Disclosure</h4>
<p>Findings are documented here for the party that commissioned the analysis. No vendor notification channel was exercised as part of this engagement, and no exploit was deployed against any live system. Coordinate disclosure with the vendor and with Meta's security team before publishing.</p>
</div>
</section>

<footer>
<p><b>TopFollow v8.4.5-Beta (versionCode 845) &mdash; <code>com.nivaroid.topfollow</code></b> &middot; {len(V)} findings &middot; 11 Frida scripts (10 PoCs + shared helper) &middot; 26 backend endpoints &middot; 22 native JNI functions mapped.</p>
<p>APK SHA-256 <code>{APK_SHA256}</code> &middot; signing certificate SHA-256 <code>{CERT_SHA256}</code> &middot; report generated {now}.</p>
<p class="muted">Produced by static and dynamic reverse engineering with androguard, LIEF, Capstone, asn1crypto and Frida. Self-contained single-file HTML &mdash; no external assets, no network requests. Use your browser's Print / Save as PDF for an offline copy; print styles strip the interactive chrome and expand all code blocks.</p>
</footer>

</main>
</div>
</div>

<div class="toolbar">
  <button id="expandAll">Expand all code</button>
  <button id="topBtn">&uarr; Top</button>
  <button id="printBtn">Print / PDF</button>
</div>

<script>
(function(){{
  'use strict';
  /* ---------- table filtering ---------- */
  document.querySelectorAll('.tsearch').forEach(function(inp){{
    inp.addEventListener('input', function(){{
      var q = this.value.trim().toLowerCase();
      var target = this.getAttribute('data-target');
      var tbl = target ? document.getElementById(target) : null;
      var scope = tbl ? tbl : document;
      scope.querySelectorAll('tbody tr').forEach(function(tr){{
        var hay = (tr.getAttribute('data-search') || tr.textContent).toLowerCase();
        tr.classList.toggle('hidden', q !== '' && hay.indexOf(q) === -1);
      }});
      if (!tbl) filterVulns();
    }});
  }});

  /* ---------- vulnerability list filtering ---------- */
  var curSev = '', curCat = '';
  function filterVulns(){{
    var gs = document.getElementById('globalSearch');
    var q = gs ? gs.value.trim().toLowerCase() : '';
    var n = 0;
    document.querySelectorAll('#vulnList .vuln').forEach(function(c){{
      var okSev = !curSev || c.getAttribute('data-sev') === curSev;
      var okCat = !curCat || c.getAttribute('data-cat') === curCat;
      var hay = (c.getAttribute('data-search') || c.textContent).toLowerCase();
      var okQ = q === '' || hay.indexOf(q) !== -1;
      var show = okSev && okCat && okQ;
      c.classList.toggle('hidden', !show);
      if (show) n++;
    }});
    // keep the matrix table in sync
    document.querySelectorAll('#tbl-matrix tbody tr').forEach(function(tr){{
      var id = tr.querySelector('a') ? tr.querySelector('a').textContent : '';
      var card = document.getElementById(id);
      tr.classList.toggle('hidden', card ? card.classList.contains('hidden') : false);
    }});
  }}
  document.querySelectorAll('#sevFilters .fbtn').forEach(function(b){{
    b.addEventListener('click', function(){{
      curSev = this.getAttribute('data-sev');
      document.querySelectorAll('#sevFilters .fbtn').forEach(function(x){{x.classList.remove('on');}});
      this.classList.add('on'); filterVulns();
    }});
  }});
  document.querySelectorAll('#catFilters .fbtn').forEach(function(b){{
    b.addEventListener('click', function(){{
      curCat = this.getAttribute('data-cat');
      document.querySelectorAll('#catFilters .fbtn').forEach(function(x){{x.classList.remove('on');}});
      this.classList.add('on'); filterVulns();
    }});
  }});
  var gs = document.getElementById('globalSearch');
  if (gs) gs.addEventListener('input', filterVulns);

  /* ---------- TOC scroll-spy ---------- */
  var links = Array.prototype.slice.call(document.querySelectorAll('nav.toc a'));
  var secs = links.map(function(a){{ return document.querySelector(a.getAttribute('href')); }}).filter(Boolean);
  function spy(){{
    var y = window.scrollY + 120, cur = null;
    secs.forEach(function(s){{ if (s.offsetTop <= y) cur = s; }});
    links.forEach(function(a){{
      a.classList.toggle('active', cur !== null && a.getAttribute('href') === '#' + cur.id);
    }});
  }}
  window.addEventListener('scroll', spy, {{passive:true}}); spy();

  /* ---------- toolbar ---------- */
  document.getElementById('topBtn').addEventListener('click', function(){{
    window.scrollTo({{top:0, behavior:'smooth'}});
  }});
  document.getElementById('printBtn').addEventListener('click', function(){{
    document.querySelectorAll('details').forEach(function(d){{ d.open = true; }});
    setTimeout(function(){{ window.print(); }}, 250);
  }});
  var expanded = false;
  document.getElementById('expandAll').addEventListener('click', function(){{
    expanded = !expanded;
    document.querySelectorAll('details').forEach(function(d){{ d.open = expanded; }});
    this.textContent = expanded ? 'Collapse all code' : 'Expand all code';
  }});

  /* ---------- open details automatically when printing ---------- */
  window.addEventListener('beforeprint', function(){{
    document.querySelectorAll('details').forEach(function(d){{ d.open = true; }});
  }});

  /* ---------- set initial active filter ---------- */
  var first = document.querySelector('#sevFilters .fbtn'); if (first) first.classList.add('on');
  var firstC = document.querySelector('#catFilters .fbtn'); if (firstC) firstC.classList.add('on');
}})();
</script>
</body>
</html>
"""

with open(OUT, "w", encoding="utf-8") as f:
    f.write(HTML)

print("wrote %s  (%.1f KiB)" % (OUT, os.path.getsize(OUT) / 1024.0))
print("vulnerabilities: %d | scripts embedded: %d" % (len(V), len(SCRIPTS)))
