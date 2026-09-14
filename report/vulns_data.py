# -*- coding: utf-8 -*-
"""TopFollow v8.4.5-Beta (com.nivaroid.topfollow) - vulnerability register.
Every entry is backed by a concrete artefact recovered during static RE.
ev = evidence (file:line or literal); poc = dynamic-lab script demonstrating it."""

V = []


def v(vid, title, sev, cat, desc, impact, ev, poc, fix):
    V.append(dict(id=vid, title=title, sev=sev, cat=cat, desc=desc,
                  impact=impact, ev=ev, poc=poc, fix=fix))


# ============================================================ CREDENTIALS ====
v("CRED-01", "Instagram account PASSWORD persisted on-device in a reversible cipher", "Critical", "Credentials",
  "The private-API login path stores the victim's real Instagram password in the Room table <code>instagram_accounts</code>, column <code>u_w</code>. The value passed to <code>setU_w()</code> is <code>com.bumptech.glide.d.q(password)</code> &mdash; a keyless static byte transform, not encryption. Any process or backup that can read the app's data directory recovers the password in one line.",
  "Full Instagram account takeover. The password (not just a session) is captured, so an attacker can also reset 2FA, change the e-mail and permanently lock the victim out. Every account the user ever adds is exposed.",
  "<code>ia.v.a(ia.v,String)</code> &rarr; <code>v7_1.setU_w(com.bumptech.glide.d.q(v6.getPassword()))</code>; Room DDL <code>instagram_accounts(... `u_w` TEXT ...)</code>",
  "04_credential_theft.js",
  "Never accept or store the user's Instagram password. Use Instagram's official OAuth (which this app does not); at absolute minimum store only a short-lived session token in Android Keystore-backed EncryptedSharedPreferences.")

v("CRED-02", "2FA seed / backup codes stored in the <code>two_factors</code> table", "Critical", "Credentials",
  "A second Room table <code>two_factors</code> holds <code>u_n</code> (username), <code>u_p</code> (password) and <code>s_k</code> (shared secret). <code>c2.t</code> issues the raw query <code>select * from two_factors</code> and populates <code>TwoFactorAccount.setU_p()</code>. <code>s_k</code> is the TOTP seed used by <code>account/getSecretKey.php</code> / <code>requestDigitCode.php</code>, and <code>ha.c</code> sends an <code>s_k_2fa</code> field to the backend.",
  "Defeats two-factor authentication entirely: with the seed an attacker generates valid 6-digit codes forever. Password (CRED-01) plus this seed is a complete, permanent compromise.",
  "<code>c2.t:627</code> <code>S(\"select * from two_factors\")</code>, <code>:660 setU_p(...)</code>; <code>models.TwoFactorAccount.getS_k()/getU_p()</code>; <code>addProperty(\"s_k_2fa\", ...)</code>",
  "04_credential_theft.js",
  "Never store a TOTP seed. If 2FA recovery is genuinely required, wrap it in an AndroidKeyStore AES-GCM key bound to user authentication with hardware attestation.")

v("CRED-03", "WebView cookie harvester synthesises an OAuth bearer token from <code>sessionid</code>", "Critical", "Credentials",
  "<code>oa.l1.onPageFinished()</code> reads <code>CookieManager.getCookie(\"https://www.instagram.com/\")</code>, extracts <code>sessionid</code>, <code>ds_user_id</code> and <code>mid</code>, then builds <code>\"Bearer IGT:2:\" + Base64({\"ds_user_id\":..,\"sessionid\":..})</code> and writes it to <code>instagram_accounts.u_a</code>. This is silent session-token theft performed on any page load, with no user gesture or confirmation.",
  "Account takeover without ever learning the password. The synthesised bearer is exactly what Instagram's own mobile clients use, so it is fully functional for follow / like / comment / DM automation.",
  "<code>oa.l1.java</code> &mdash; <code>y(cookie,\"sessionid\")</code>, <code>y(cookie,\"ds_user_id\")</code>, <code>\"Bearer IGT:2:\" + Base64.encodeToString(...)</code>, <code>v13_3.setU_a(com.bumptech.glide.d.q(v8_9))</code>",
  "04_credential_theft.js",
  "Do not harvest cookies from a WebView. Use official Instagram OAuth with PKCE and store only the returned, scoped, expiring access token.")

v("CRED-04", "Instagram session token sent to the vendor backend in a plaintext HTTP header", "Critical", "Credentials",
  "<code>com.bumptech.glide.d.t(InstagramAccount)</code> builds the header map attached to <em>every</em> backend call and puts the victim's Instagram session token straight into <code>Token: account.getToken()</code>, together with <code>Active-Id: account.getPk()</code> and <code>Top-Token: device.getToken()</code>.",
  "The operator of <code>top.nivafollower.app</code> receives live Instagram session credentials for every user on every request &mdash; a server-side mass account-takeover capability requiring no client compromise at all.",
  "<code>com.bumptech.glide.d.t()</code>: <code>v0_1.put(\"Token\", p4.getToken())</code>, <code>put(\"Active-Id\", p4.getPk())</code>, <code>put(\"Top-Token\", ...getDevice().getToken())</code>",
  "03_instagram_api_intercept.js, 08_backend_traffic_and_servercheck.js",
  "Session tokens must never leave the device. Perform Instagram actions locally and send the backend only opaque, non-replayable result attestations.")

v("CRED-05", "Instagram login credentials forwarded to <code>instagramLogin.php</code>", "Critical", "Credentials",
  "<code>ha.b.onReady()</code> case 0 calls native <code>helper.q.r(json, q8.t1.k(), DeviceId)</code> (<code>libtopfollow.so!x0015b1e9</code>) to build the body of a POST to the base64-obfuscated endpoint <code>aW5zdGFncmFtTG9naW4ucGhw</code> = <code>instagramLogin.php</code>. The username and password entered for Instagram are therefore also transmitted to the third-party TopFollow server.",
  "Vendor-side credential phishing by design. Combined with CRED-01 the operator holds both the live session and the long-term password for every user of the app.",
  "<code>ha.b.java:30</code> <code>a(com.bumptech.glide.d.o(\"aW5zdGFncmFtTG9naW4ucGhw\"), d.t(0), ...)</code>; endpoint decoded from the DEX literal",
  "08_backend_traffic_and_servercheck.js",
  "Remove the endpoint. Instagram authentication belongs between the user and Instagram only.")

v("CRED-06", "Hard-coded spoofed Instagram client identity", "High", "Instagram API",
  "The app impersonates one specific real device/app build: User-Agent <code>Instagram 369.0.0.46.101 Android (33/13;420dpi;1080x2269;samsung;SM-E625F;f62;exynos9825;en_US;785863906)</code>, <code>x-ig-app-id: 567067343352427</code>, <code>x-bloks-version-id: 083f38c334f42c5e3322bb77464c601e8882cd9ff2d30ac915ba7a497539d604</code>, <code>x-ig-capabilities: 3brTv10=</code>.",
  "Instagram can trivially fingerprint and mass-ban every TopFollow user, since all of them present the same device model, app version and bloks id. It is also a ToS violation that endangers the user's account.",
  "<code>ia.q.f(long)</code> header builder; UA literal in the DEX string table; <code>ia.v</code> uses the same bloks id in the login body",
  "03_instagram_api_intercept.js",
  "Do not impersonate the official client. Use the sanctioned Graph API with the user's own app credentials.")

v("CRED-07", "Per-request forged <code>x-ig-nav-chain</code> / <code>x-ig-salt-ids</code> / <code>x-fb-rmd</code>", "High", "Instagram API",
  "Every action request fabricates a navigation chain that makes an automated call look like organic UI navigation, e.g. <code>ShortUrlFeedFragment:feed_short_url:1:warm_start:{ts-5}.{ts+8}::</code>, <code>ContextualFeedFragment:feed_contextual:11:button:...</code>, <code>GVw:comments_v2_feed_timeline:5:button:</code>, plus four sets of salt ids such as <code>220145826</code> and <code>220140399,974460658</code>. Timestamps are derived from <code>System.currentTimeMillis()</code> and split at index 10.",
  "Deliberate anti-fraud evasion against Instagram's abuse detection. The automation is engineered to be indistinguishable from a human &mdash; exactly what platform-integrity systems exist to catch.",
  "<code>ja.e.b()</code> (nav_chain builders for follow/like/repost/comment); <code>ia.q.f()</code>; <code>a2.d.n(v0_14,\"x-ig-nav-chain\",v4_12,\"x-ig-salt-ids\",\"220145826\")</code>",
  "03_instagram_api_intercept.js",
  "Remove. There is no legitimate use for synthesising another product's telemetry.")

v("CRED-08", "Human-behaviour simulator with jittered timings and forced re-login", "High", "Instagram API",
  "<code>ia.x</code> performs a warm-up burst before every real action &mdash; typeahead lookup, profile view, media tab, inbox, quick-promotions &mdash; with timestamps offset &minus;2&nbsp;s to &minus;12&nbsp;s and 100&ndash;999&nbsp;ms random jitter. If <code>last_login</code> is older than 1800&nbsp;s it re-authenticates first, so the session pattern mimics a real user returning to the app.",
  "Purpose-built defeat of behavioural bot detection. Raises the blast radius for Instagram (fake engagement at scale) and for the user (account suspension).",
  "<code>ia.x</code>; <code>instagram_accounts.last_login</code> column; re-login threshold 1800&nbsp;s",
  "03_instagram_api_intercept.js",
  "Remove.")

v("CRED-09", "Android Keystore ECDSA key under a hard-coded alias", "Medium", "Cryptography",
  "An ECDSA P-256 key pair is generated in the Android Keystore under the fixed alias <code>top_key_4286</code>, and the app references Instagram's <code>attestation/create_android_keystore/</code> endpoint.",
  "A constant alias makes the key predictable and enumerable across installs; combined with the attestation endpoint it indicates an attempt to obtain Instagram device attestation that cannot actually be validated.",
  "Keystore alias literal <code>top_key_4286</code>; endpoint <code>attestation/create_android_keystore/</code> in the DEX string table",
  "07_native_jni_dumper.js",
  "Derive the alias per install from a server-issued nonce and enable <code>setAttestationChallenge</code> so the key is hardware-attested.")

v("CRED-10", "Firebase cloud project number and FCM token collected", "Low", "Data storage",
  "The Play Integrity nonce is composed as <code>RD + q.j() + \"877665803231\"</code>, where <code>877665803231</code> is the Google Cloud project number, and <code>device.fcm_token</code> is stored and uploaded.",
  "Leaks the vendor's GCP project (abusable for quota/abuse reports and for correlating installs) and gives the operator a push channel to every device.",
  "<code>d3.d.l()</code>: literal <code>877665803231</code>; Room DDL <code>device(... `fcm_token` TEXT)</code>",
  "08_backend_traffic_and_servercheck.js",
  "Do not embed the project number in a client-side nonce; use a server-issued random nonce per request.")

# ============================================================== CRYPTO ========
v("CRYP-01", "Keyless static cipher used for all &ldquo;encrypted&rdquo; local secrets", "Critical", "Cryptography",
  "<code>com.bumptech.glide.d.p()</code> / <code>.q()</code> apply a fixed four-stage transform with no key material whatsoever: XOR every byte with <code>0x6C</code>; rotate each byte left by 3; reverse the whole buffer; XOR byte <em>i</em> with <code>(i*37) ^ 0xA5</code>. It was re-implemented in Python and round-trips perfectly. This single routine protects the Instagram password, the bearer token, the 2FA seed and every sensitive SharedPreferences value.",
  "Obfuscation marketed as encryption. Anyone who pulls the APK &mdash; or merely a backup &mdash; decrypts every secret offline in microseconds, with no key-recovery step at all.",
  "<code>com.bumptech.glide.d.p()/q()</code>; verified by <code>report/cipher_poc.py</code> (round-trip OK for passwords, bearers, TOTP seeds and URLs)",
  "04_credential_theft.js",
  "Use <code>androidx.security.crypto.EncryptedSharedPreferences</code> / EncryptedFile with an AndroidKeyStore master key, or SQLCipher for Room.")

v("CRYP-02", "Hard-coded 64-hex integrity constant reconstructed from nested base64", "High", "Cryptography",
  "<code>helper/a0.x()</code> concatenates the literal <code>ZDgzZmI3Y2U3ZjlhNzM5MjJkMjI2MmNlM</code> with <code>d.o(\"MlEzWXpoak56aGxOR014TWpFeFpHRXhOMlkwTldJNU9UQmhNelE0WkRRd05XSTFPRFkzTnc9PQ==\")</code> and base64-decodes the result, yielding <code>d83fb7ce7f9a73922d2262ce3d7c8c78e4c1211da17f45b990a348d405b58677</code>. It matches none of SHA-256(APK), SHA-256(classes.dex), SHA-256(libtopfollow.so), SHA-256(package name) or SHA-256(backend URL) &mdash; it is a bare hard-coded comparison constant.",
  "A static embedded comparison value is a patch-one-byte bypass: replace the constant with the digest of your own modified build, or hook the comparator. Layering base64 over it adds no security, only friction for analysts.",
  "<code>com.nivaroid.topfollow.helper.a0.x()</code>; decoded chain reproduced in the analysis log",
  "01_anti_tamper_killer.js",
  "Use Play Integrity API verdicts evaluated server-side. Client-side digest comparison cannot be made tamper-proof.")

v("CRYP-03", "Static, fully replayable challenge blob <code>x4</code> in every coin claim", "High", "Business logic",
  "<code>helper/a0.x4()</code> builds <code>\"VkVacVRW\" + d.o(\"VW1GVmJYTXhZMnN4U1ZwRw==\") + \"UldVZz09\"</code> and double-base64-decodes it to the constant <code>TFjMTZRk5rMHdTVR</code>. No device id, timestamp, server nonce or counter enters the computation, so the value is identical on every install forever.",
  "Whatever anti-replay purpose <code>x4</code> was meant to serve is void: the same token can be replayed by any client indefinitely. Security theatre embedded directly in the money path.",
  "<code>com.nivaroid.topfollow.helper.a0.x4()</code> &rarr; <code>TFjMTZRk5rMHdTVR</code>; consumed by <code>ha.c.onReady()</code> as the <code>x4</code> field of <code>order/syncOrder.php</code>",
  "06_task_verification_bypass.js",
  "Issue a single-use server nonce per task, bind it to the order id and the device attestation, and expire it server-side.")

v("CRYP-04", "Certificate pin is the APK signing-certificate digest, and it is server-rotatable", "High", "Transport",
  "The pin literal recovered from <code>libtopfollow.so</code> .rodata is <code>sha256/d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e</code>. That is byte-for-byte the SHA-256 of the APK's own signing certificate (self-signed, <code>CN=Maryam Ahmadi, OU=Android Developer, O=NivaRoid, L=Shiraz, ST=Fars, C=IR</code>, serial 1, RSA-2048, valid 2023-12-15 &rarr; 2048-12-08). The same digest is also the tamper-check value, so one constant does two unrelated jobs. Worse, the <em>live</em> pin is whatever the server pushed into SharedPreferences <code>Pin</code> / <code>PinActive</code>.",
  "Pinning a signing certificate rather than a TLS leaf/intermediate SPKI is meaningless for transport security &mdash; it pins nothing about the server's key. And because the pin arrives from the network, a MITM or a compromised ServerCheck response can install an attacker pin and then intercept everything.",
  "<code>libtopfollow.so</code> .rodata (XOR 0x55) pin literal; APK Signature Scheme v2 block at file offset 0x9ce620 (cert DER 864 bytes); <code>ha.h</code> &rarr; <code>q.k(d.p(Pin), PinActive)</code>",
  "02_ssl_pinning_bypass.js, 08_backend_traffic_and_servercheck.js",
  "Pin the SPKI of the real TLS certificate plus a backup, ship the pins inside the binary, and never accept a pin from a network response.")

v("CRYP-05", "No TLS stack and no crypto <i>imports</i> in the native library &mdash; pinning is Java-side only", "High", "Native hardening",
  "<code>libtopfollow.so</code> imports no crypto and no TLS symbols (<code>DT_NEEDED</code> = libz/libandroid/liblog/libm/libdl/libc); checksec shows FULL RELRO + BIND_NOW, stack canary and FORTIFY, but the only exported symbol is <code>JNI_OnLoad</code>. All pinning, certificate handling and Retrofit construction happen through JNI calls back into Java (OkHttp <code>CertificatePinner</code>). The library does implement its own AES-256 internally (CRYP-09), but that is used inside the request pipeline and is not what protects the TLS channel.",
  "The entire &ldquo;native hardening&rdquo; story collapses at the Java boundary: hooking <code>okhttp3.CertificatePinner.check</code> in Frida defeats the pinning without touching a single instruction of the .so. The obfuscation buys time, not security.",
  "<code>out/13_so_checksec.json</code>; import table contains no <code>SSL_*</code>, no <code>EVP_*</code>, no <code>*crypt*</code>; sole export <code>JNI_OnLoad</code>",
  "02_ssl_pinning_bypass.js",
  "If pinning must resist instrumentation it needs a native TLS stack (e.g. statically linked BoringSSL) with verification performed entirely in native code.")

v("CRYP-06", "Base64-only obfuscation of endpoint paths and constants", "Medium", "Obfuscation",
  "Sensitive endpoint names are stored as single-layer base64 decoded by <code>d.o()</code>: <code>b3JkZXIvc3VibWl0T3JkZXIucGhw</code>=<code>order/submitOrder.php</code>, <code>aW5zdGFncmFtTG9naW4ucGhw</code>=<code>instagramLogin.php</code>, <code>Z2V0TWFpbkluZm8ucGhw</code>=<code>getMainInfo.php</code>, <code>YWNjb3VudC9jaGVja0NhcHRjaGEucGhw</code>=<code>account/checkCaptcha.php</code>, <code>cHJlLWxvZ2luL3NldFVwRGV2aWNlLnBocA==</code>=<code>pre-login/setUpDevice.php</code>, <code>cHJlLWxvZ2luL2FjdGl2ZURldmljZS5waHA=</code>=<code>pre-login/activeDevice.php</code>, <code>cHJlLWxvZ2luL3ByaXZhY3lQb2xpY3kucGhw</code>=<code>pre-login/privacyPolicy.php</code>. Some are nested two or three deep.",
  "Provides zero protection &mdash; the entire API surface was recovered with a shell one-liner &mdash; while actively hindering legitimate security review and audit of the app.",
  "<code>com.bumptech.glide.d.o(String)</code> call sites in <code>ha.a</code>, <code>ha.b</code>, <code>a7.a</code>, <code>androidx.fragment.app.e</code>",
  "08_backend_traffic_and_servercheck.js",
  "Obfuscating the API surface is not a control. Ship a documented, authenticated API instead.")

v("CRYP-07", "Native string tables obfuscated with two single-byte XOR keys", "Medium", "Native hardening",
  "An exhaustive sweep of every printable run in <code>libtopfollow.so</code> against all 127 single-byte XOR keys recovers the whole secret set with just two keys: <code>0x55</code> yields the backend URL <code>https://top.nivafollower.app/v840/</code>, the Instagram URLs, a UUID <code>3bbeeba8e-beaa-4458-ac60-6d9a61b2be9e</code> and the pin; <code>0x5A</code> yields the anti-Frida keyword list and every root-detection path.",
  "Single-byte XOR is defeated by a brute force that runs in well under a second, so all &ldquo;hidden&rdquo; native strings are effectively plaintext. The protection only stops the most casual <code>strings(1)</code> run.",
  "<code>out/19_xor_decoded.txt</code> (sweep of all ASCII runs, keys 1..127); per-function reference map <code>out/18_native_strings_by_fn.txt</code> (943 PIC thunks, 760 resolved .rodata references)",
  "07_native_jni_dumper.js",
  "If strings must be hidden, derive them at runtime from a keyed KDF with per-install entropy, or fetch them inside an attested server session.")

v("CRYP-08", "Instagram URLs hidden as triple-base64 in .rodata", "Low", "Native hardening",
  "<code>https://b.i.instagram.com/api/v1/</code>, <code>https://i.instagram.com/api/v2/</code>, <code>https://www.instagram.com/graphql/query</code>, <code>https://www.instagram.com/</code> and the endpoint fragments <code>create_note/v2/</code>, <code>seen/</code>, <code>/save/</code> are each base64-encoded three times before being embedded.",
  "Layered base64 is not encryption; it decoded deterministically. It documents the full private-API surface the app abuses.",
  "<code>libtopfollow.so</code> .rodata; decoded via <code>out/19_xor_decoded.txt</code> and the bootstrap function <code>x0018d3f7</code>",
  "07_native_jni_dumper.js",
  "See CRYP-07.")

# ============================================================ INTEGRITY ======
v("INTE-01", "APK signature self-check is hookable at the Java reflection layer", "High", "Integrity",
  "The bootstrap mega-function <code>x0018d3f7</code> (registered as <code>helper.q.l(int)</code>) calls <code>PackageManager.getPackageInfo(pkg, GET_SIGNATURES)</code>, then reflectively obtains <code>MessageDigest.getInstance(\"SHA-256\")</code> and compares the digest against the embedded constant. Because the whole check is expressed as ordinary JNI calls into <code>java.security.MessageDigest</code> and <code>android.content.pm.Signature</code>, hooking <code>digest()</code> or <code>Signature.toByteArray()</code> returns whatever value the check expects.",
  "The primary anti-repackaging control is defeated with roughly ten lines of Frida, allowing a modified, re-signed APK to run while believing itself genuine.",
  "<code>libtopfollow.so!x0018d3f7</code> references (per <code>out/18_native_strings_by_fn.txt</code>): <code>getPackageInfo</code>, <code>signatures</code>, <code>SHA-256</code>, <code>MessageDigest</code>, <code>certificatePinner</code>, <code>ANDROID_ID</code>, <code>DeviceModel</code>",
  "01_anti_tamper_killer.js",
  "Rely on the Play Integrity API verdict, verified server-side against Google's keys. Client self-inspection is always defeatable.")

v("INTE-02", "Google Play Store certificate gate <code>d8.f.a()</code> forced open", "High", "Integrity",
  "<code>d8.f.a(Signature[])</code> (&ldquo;PhoneskyVerificationUtils&rdquo;) SHA-256/base64url-compares the Play Store package's signatures against <code>8P1sW0EPJcslw7UzRsiXL64w-O50Ed-RBICtay1g24M</code>, or against <code>GXWy8XF3vIml3_MfnmSmyuKBpT3B0dWbHRR_4cgq-gA</code> when <code>Build.TAGS</code> contains dev-keys/test-keys. <code>d3.d.l()</code> calls it before requesting an integrity token. A one-line hook returns <code>true</code> unconditionally.",
  "Lets an attacker run the Play Integrity attestation path from a repackaged build, or on a device without a genuine Play Store, so the backend receives an apparently valid token.",
  "<code>d8/f.java</code>; consumed at <code>d3.d.java:527</code> <code>if ((v7_2.enabled) && (d8.f.a(v3_6.signatures)))</code>",
  "01_anti_tamper_killer.js",
  "Do not gate attestation on a client-side certificate comparison. Request the token and let the server validate it, including <code>appRecognitionVerdict</code>.")

v("INTE-03", "<code>/proc/self/maps</code> scan for Frida, Xposed, Riru, Zygisk and Substrate", "High", "Anti-analysis",
  "The native code scans <code>/proc/self/maps</code> for a keyword set that is itself XOR-0x5A obfuscated: <code>/proc/self/maps</code>, <code>xposed</code>, <code>lsposed</code>, <code>edxposed</code>, <code>riru</code>, <code>substrate</code>, <code>libcso_substrate</code>, <code>libbridge.so</code>, <code>zygisk</code>; plus base64-encoded <code>frida</code>, <code>gum-js-loop</code>, <code>libfrida-gadget</code>, <code>re.frida.server</code>. It also looks for <code>(deleted)</code> libart/libc mappings and <code>rwxp</code> regions.",
  "Detection, not prevention. Filtering <code>open()</code>/<code>read()</code>/<code>fgets()</code> and neutering <code>strstr()</code>/<code>strcmp()</code> makes every keyword invisible while the instrumented process runs normally.",
  "<code>out/19_xor_decoded.txt</code> (key 0x5A); referenced from <code>x0018d3f7</code>",
  "01_anti_tamper_killer.js",
  "Instrumentation detection is an arms race with a known outcome. Spend the effort on server-side verification instead.")

v("INTE-04", "Root detection is a static list of nine <code>su</code> paths", "Medium", "Anti-analysis",
  "The check tests for <code>Superuser.apk</code>, <code>/sbin/su</code>, <code>/system/bin/su</code>, <code>/system/xbin/su</code>, <code>/data/local/xbin/su</code>, <code>/data/local/bin/su</code>, <code>/system/sd/xbin/su</code>, <code>/system/bin/failsafe/su</code> and <code>/data/local/su</code>. The paths are XOR-0x5A encoded in .rodata and probed through <code>open</code>/<code>access</code>/<code>stat</code> and <code>java.io.File.exists()</code>.",
  "Magisk DenyList, a renamed <code>su</code>, or a KernelSU/APatch install is invisible to this list. Forcing the probes to fail with ENOENT defeats it completely.",
  "<code>out/19_xor_decoded.txt</code> (key 0x5A root-path block)",
  "01_anti_tamper_killer.js",
  "Use the Play Integrity <code>deviceRecognitionVerdict</code> fields evaluated server-side; a static path list is trivially evaded.")

v("INTE-05", "Emulator detection from spoofable <code>Build</code> properties", "Medium", "Anti-analysis",
  "The native bootstrap reads <code>Build.DEVICE</code> and <code>Build.HARDWARE</code> (referenced as <code>DEVICE</code>/<code>HARDWARE</code> in the function's string set) to reject emulators.",
  "<code>android.os.Build</code> fields are plain statics; overwriting them in Frida makes any emulator report itself as a Samsung SM-E625F on exynos9825 &mdash; which is exactly the identity the app already hard-codes for Instagram.",
  "<code>libtopfollow.so!x0018d3f7</code> string references <code>DEVICE</code>, <code>HARDWARE</code>; matching hard-coded UA in <code>ia.q</code>",
  "01_anti_tamper_killer.js",
  "Collect emulator signals server-side from attestation, not from client-readable system properties.")

v("INTE-06", "OLLVM control-flow flattening as the sole native protection", "Low", "Native hardening",
  "All 22 registered native functions use an OLLVM-style state-dispatcher (control-flow flattening), which makes static CFG recovery impractical in a disassembler. It does not protect data: resolving the 943 position-independent <code>call $+5; pop reg; add reg,K</code> thunks per function recovered 760 <code>.rodata</code> references and thus every secret string.",
  "Raises analysis cost but not the security floor. Once the data references were resolved, the flattened control flow was irrelevant to extracting keys, URLs, pins and detection keywords.",
  "<code>out/15_disasm_key.txt</code>; thunk resolution <code>work/fn_strings3.py</code> &rarr; <code>out/18_text_refs.json</code>, <code>out/18_native_strings_by_fn.txt</code>",
  "07_native_jni_dumper.js",
  "Treat obfuscation as delay, never as a control. Combine it with hardware-backed attestation and server-side enforcement.")

v("INTE-07", "Scrambled DEX <code>map_list</code> to break static analysis tooling", "Low", "Anti-analysis",
  "The single <code>classes.dex</code> has a deliberately scrambled <code>map_list</code>, which makes annotation and section parsing crash or return out-of-bounds offsets in standard tooling.",
  "An anti-RE measure with no security value: full pseudocode for all 4,146 classes was still recovered, and the scrambling merely removes the ability to read Retrofit annotations.",
  "Observed while parsing the DEX map list; annotation extraction goes out of bounds",
  "07_native_jni_dumper.js",
  "Do not rely on tooling breakage. It inconveniences defenders and auditors more than attackers.")

v("INTE-08", "Play Integrity gate keyed on client-writable SharedPreferences", "High", "Integrity",
  "<code>d3.d.l()</code> only performs attestation when <code>SP.getBoolean(\"SND\",false) == true</code> <em>and</em> <code>SP.getInt(\"RID\",0) == 3850153</code>. Both live in the <code>TOPFVC_Shared</code> preferences file and are trivially hooked or edited on a rooted device.",
  "The integrity requirement can be switched off entirely (skip attestation) or switched on with forged values, so the backend cannot distinguish a genuinely attested client from one that simply set two integers.",
  "<code>d3.d.java:494</code> <code>if ((!v4_3.a.getBoolean(\"SND\",0)) || (v4_3.a.getInt(\"RID\",0) != 3850153))</code>",
  "01_anti_tamper_killer.js, 08_backend_traffic_and_servercheck.js",
  "Require a fresh, valid integrity token server-side on sensitive endpoints and reject requests without one &mdash; never let the client decide whether to attest.")

v("INTE-09", "Integrity token cached for six hours and replayable", "Medium", "Integrity",
  "The attestation result is cached in SharedPreferences <code>RIT</code>/<code>AIT</code>/<code>RD</code> and reused while <code>now - RIT &lt; 6 h</code>. The cached token is then re-sent as body field <code>x2</code> = <code>d.q(d.p(SP\"RD\"))</code>.",
  "One valid token can be replayed for six hours across unlimited requests, so the attestation provides no per-request binding and no protection against a scripted client that captured a single genuine token.",
  "<code>d3.d.java:500-538</code>: <code>getLong(\"RIT\",0)</code> freshness test, <code>p21.addProperty(\"x2\", d.q(d.p(SP\"RD\")))</code>",
  "08_backend_traffic_and_servercheck.js",
  "Bind each token to a server-issued nonce and a request hash, use it once, and expire it in minutes.")

v("INTE-10", "Predictable Play Integrity nonce", "Medium", "Integrity",
  "The integrity nonce is <code>RD + helper.q.j() + \"877665803231\"</code>, where <code>q.j()</code> is a native timestamp and <code>877665803231</code> is a constant GCP project number. There is no server-supplied randomness.",
  "A predictable nonce lets an attacker pre-compute or reuse attestation requests and prevents the server from establishing freshness &mdash; which is the whole point of a nonce.",
  "<code>d3.d.l()</code> nonce composition; constant <code>877665803231</code>",
  "08_backend_traffic_and_servercheck.js",
  "Issue a cryptographically random per-request nonce from the server and embed it in the integrity request.")

v("INTE-11", "Native bootstrap collects ANDROID_ID and a full device profile", "Medium", "Privacy",
  "<code>x0018d3f7</code> resolves references to <code>ANDROID_ID</code>, <code>DeviceModel</code> and its setters <code>setHash_key</code>, <code>setNonce</code>, <code>setHash_type</code>, <code>addDevice</code>, populating the Room <code>device</code> table (<code>coin, gem, hash_type, hash_key, nonce, token, fcm_token</code>).",
  "A persistent cross-session device fingerprint is built and uploaded, enabling tracking of users across installs and correlation of their Instagram accounts.",
  "<code>out/18_native_strings_by_fn.txt</code> for <code>x0018d3f7</code>; Room DDL <code>device(...)</code>; <code>MyDatabase.addDevice()</code>",
  "04_credential_theft.js, 07_native_jni_dumper.js",
  "Collect only what is required, disclose it in the privacy policy, and do not exfiltrate ANDROID_ID.")

v("INTE-12", "Self-signed 25-year signing certificate, serial 1, v2-only signature", "Medium", "Integrity",
  "The APK is signed with a self-signed RSA-2048 certificate whose subject and issuer are both <code>CN=Maryam Ahmadi, OU=Android Developer, O=NivaRoid, L=Shiraz, ST=Fars, C=IR</code>, serial number 1, valid 2023-12-15 &rarr; 2048-12-08, SHA-256 <code>d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e</code>. There is no v1/JAR signature at all (no <code>META-INF/*.RSA|*.SF|*.MF</code>) &mdash; only an APK Signature Scheme v2 block plus a verity padding block.",
  "A 25-year self-signed key with serial 1 is generated once and never rotated; if it leaks, every past and future build can be forged and there is no revocation path. v2-only signing also means older tooling sees the APK as unsigned.",
  "APK Signing Block: magic at 0x9d1608, v2 pair at 0x9ce620, cert DER 864 bytes; parsed in <code>out/20_signing.txt</code>",
  "01_anti_tamper_killer.js",
  "Use Play App Signing so Google holds the app signing key, keep the upload key in an HSM, and rotate on a defined schedule.")

# ========================================================= BUSINESS LOGIC ====
v("BIZ-01", "Coin reward flag <code>get_coin</code> is asserted by the client", "Critical", "Business logic",
  "When a task finishes, <code>ha.c.onReady(JsonObject)</code> sets <code>get_coin</code> to <code>\"true\"</code> if and only if the in-memory Instagram response object reports <code>getStatus().equals(\"ok\")</code>, then POSTs the claim to <code>order/syncOrder.php</code>. The status is a client-side object; forcing it to <code>\"ok\"</code> makes the client claim payment for an action that never happened or that Instagram rejected.",
  "Unbounded coin generation. Coins are the currency spent on followers and likes, so this converts directly into free engagement for any account the attacker names &mdash; the core fraud of the entire service.",
  "<code>ha.c.java:78</code> <code>p9.addProperty(\"get_coin\", v1_16)</code> with <code>v1_16 = (resp.getStatus()==null || !resp.getStatus().equals(\"ok\")) ? \"false\" : \"true\"</code>",
  "06_task_verification_bypass.js",
  "Determine the reward exclusively server-side, from an independently fetched Instagram state plus a server-issued task nonce. Never accept a client-declared success flag.")

v("BIZ-02", "Reward amount <code>order_value</code> travels from the client", "Critical", "Business logic",
  "The same claim body carries <code>order_value = order.getOrder_value()</code>, taken from the local <code>Order</code> object, and <code>type = order.getOrder_type()</code>. The client therefore states how much the completed task is worth. A hook on <code>Order.getOrder_value()</code> rewrites the amount before the request is even built.",
  "Direct monetary inflation: the attacker chooses the payout. Even if the server re-derives the amount, the field's presence shows the client is trusted with pricing on the money path.",
  "<code>ha.c.java:69</code> <code>p9.addProperty(\"order_value\", v4_8)</code>, <code>:62</code> <code>addProperty(\"type\", v1_11.getOrder_type())</code>; <code>models.Order.getOrder_value()</code>",
  "06_task_verification_bypass.js",
  "Look up the reward from the server's own copy of the order keyed by <code>order_id</code>; ignore any client-supplied value.")

v("BIZ-03", "Client-side price computation for buying engagement", "High", "Business logic",
  "The purchase dialog computes <code>cost = MyDatabase.setup().n().getCoin_per_like() * selectedCount</code> (and the equivalent for follow/comment/repost/save/seen/threads) and compares it against <code>MyDatabase.setup().getDevice().getCoin()</code> &mdash; a row in the local Room <code>device</code> table. If the balance is insufficient the Buy button's click listener is simply set to <code>null</code>; otherwise <code>new oa.i0(activity, count, dialog, 0)</code> is attached.",
  "The affordability decision never reaches the server before the button becomes clickable. Inflating the local <code>device.coin</code> value, or hooking <code>DeviceModel.getCoin()</code>, enables every purchase path in the UI.",
  "<code>androidx.fragment.app.e</code> (default branch) and <code>ha.a.onReady()</code>: <code>int cost = n().getCoin_per_like() * count; if (getDevice().getCoin() < cost) ... setOnClickListener(0)</code>",
  "05_coin_economy_bypass.js",
  "Enforce price and balance server-side on <code>order/submitOrder.php</code>, and treat the client figure as display-only.")

v("BIZ-04", "<code>set_order_stamp</code> signature omits balance, currency and nonce", "High", "Business logic",
  "Before submitting an order the app calls native <code>helper.q.s(username, order_count, type)</code> (<code>libtopfollow.so!x0017b62c</code>) and attaches the result as <code>set_order_stamp</code>. The signed input is exactly three fields: target username, requested count and action type. The coin/gem balance, which currency is spent, any server nonce and the requesting account are all outside the signature.",
  "The stamp cannot prove the buyer could pay. A replayed or edited request that preserves those three fields carries a valid stamp while the payment context around it is entirely attacker-chosen.",
  "<code>ha.b.java:34</code> <code>p11.addProperty(\"set_order_stamp\", q.s(json.get(\"username\"), json.get(\"order_count\"), json.get(\"type\")))</code>",
  "05_coin_economy_bypass.js",
  "Sign the complete canonical request body including account id, server nonce, timestamp and price, and verify server-side.")

v("BIZ-05", "Local wallet in an unencrypted Room database is the balance of record for the UI", "High", "Data storage",
  "The Room database <code>t_f_d_b_f_v_c</code> is opened with a plain <code>SupportSQLiteOpenHelper</code> &mdash; there is no SQLCipher dependency and no <code>SupportFactory</code> passphrase anywhere in the DEX. Table <code>device</code> holds <code>coin</code> and <code>gem</code>; <code>instagram_accounts</code> holds 42 columns of credentials; <code>two_factors</code> holds passwords and TOTP seeds; <code>app_info</code> holds the server-pushed economy rates.",
  "On any rooted device, or from a cloud backup (STOR-02), the entire wallet and credential store is readable and writable with the <code>sqlite3</code> CLI. Balances can be edited at rest, not merely hooked at runtime.",
  "<code>com.nivaroid.topfollow.db.MyDatabase.setup()</code> (no passphrase / SupportFactory); Room DDL for <code>device</code>, <code>instagram_accounts</code>, <code>two_factors</code>, <code>app_info</code>",
  "04_credential_theft.js, 05_coin_economy_bypass.js",
  "Encrypt the database with SQLCipher under an AndroidKeyStore key, and keep the authoritative balance server-side so a local edit has no effect.")

v("BIZ-06", "Static challenge token <code>x4</code> accepted on the claim endpoint", "High", "Business logic",
  "<code>order/syncOrder.php</code> receives <code>x4</code> from <code>helper/a0.x4()</code>, which is the compile-time constant <code>TFjMTZRk5rMHdTVR</code> (see CRYP-03). It carries no device, session, order or time binding.",
  "The one field meant to make a claim non-replayable is identical for every user, every device, forever, so any captured claim can be replayed &mdash; or fabricated from scratch.",
  "<code>ha.c.java:39</code> <code>p9.addProperty(\"x4\", v3_2)</code> from <code>a0.x4()</code>",
  "06_task_verification_bypass.js",
  "Replace with a per-task server nonce bound to the order id and the device attestation.")

v("BIZ-07", "Claim body built entirely on-device by native code with no server challenge", "High", "Business logic",
  "<code>helper.q.t(JsonObject, InstagramAccount, Order)</code> (<code>x0015a3b7</code>) together with <code>q.i</code>/<code>q.u</code>/<code>q.v</code> assemble the whole <code>syncOrder.php</code> payload locally, including <code>x5 = q.a(gson.toJson(instagramResponse))</code>, <code>x6 = order_stamp</code>, <code>x7 = response.getMessage()</code>, <code>active_pk</code>, <code>get_new_order</code>, <code>new_order_type</code> and <code>is_single_tasking</code> (read from SharedPreferences). None of these values is issued or countersigned by the server for that specific attempt.",
  "A scripted client can construct a syntactically perfect, internally consistent claim without ever talking to Instagram, because every input to the payload is available locally or forgeable.",
  "<code>ha.c.java:24-99</code>; natives <code>x0015a3b7</code>, <code>x0014b4f3</code>, <code>x00120b1e</code>, <code>x00135e2a</code>, <code>x0012e5a1</code>",
  "06_task_verification_bypass.js, 07_native_jni_dumper.js",
  "Require a server-issued single-use task token, and verify the Instagram action independently (server-side fetch of the target's follower/like state) before crediting.")

v("BIZ-08", "Mass multi-account farming worker with a client-controlled concurrency flag", "High", "Instagram API",
  "<code>DoTasksService</code> enumerates every row of <code>instagram_accounts</code> where <code>isActive()</code> is true and spawns one <code>ja.e</code> worker per account. If SharedPreferences <code>SingleTasking</code> is false, all workers run in parallel rather than only the first.",
  "The app is architecturally an engagement-farming bot: one device drives N hijacked Instagram accounts simultaneously. Flipping a single boolean multiplies the abuse rate, and it is entirely under the user's control.",
  "<code>DoTasksService.onCreate()/a()</code>; <code>SP.getBoolean(\"SingleTasking\", true)</code>; <code>ja.e(InstagramAccount, Context, d3.d)</code> per active account",
  "05_coin_economy_bypass.js, 06_task_verification_bypass.js",
  "This is the product's core abuse; there is no fix short of not automating other people's accounts.")

v("BIZ-09", "VIP upgrade gated only on locally available fields", "Medium", "Business logic",
  "<code>account/upgradeAccountToVip.php</code> is called only if <code>currentInstagram().getMedia_count()</code> and <code>getUsername()</code> are non-empty, and the body carries <code>vip_stamp = helper.q.m()</code> (<code>x0011f42b</code>) &mdash; a native value with no visible per-account or per-payment binding. The local <code>instagram_accounts.is_vip</code> column mirrors the status.",
  "The precondition is data the client already holds, and the stamp is opaque but constant per build; combined with a local <code>is_vip</code> flag the VIP tier is weakly protected at best.",
  "<code>androidx.fragment.app.e.java:381</code> <code>p8.addProperty(\"vip_stamp\", q.m())</code> after a <code>media_count</code>/<code>username</code> emptiness test; <code>instagram_accounts.is_vip</code>",
  "05_coin_economy_bypass.js",
  "Bind VIP status to a server-side payment record and re-validate it on every privileged call.")

v("BIZ-10", "Coupon, gift-code and daily-reward redemption driven by the client", "Medium", "Business logic",
  "<code>account/addCoupon.php</code>, <code>getCoupons.php</code>, <code>getGiftCodeReward.php</code>, <code>checkDailyGift.php</code> and <code>getDailyItems.php</code> are all invoked with client-built bodies; the coupon code arrives as a plain <code>coupon</code>/<code>coupon_type</code> property and the models <code>Coupon</code>, <code>CouponList</code>, <code>CouponType</code> are parsed client-side.",
  "Codes can be enumerated and replayed, and daily-gift timing checks run against the device clock, which the user controls.",
  "<code>androidx.fragment.app.e</code> cases 3, 7, 9, 13, 15; <code>addProperty(\"coupon_type\", ...)</code>",
  "05_coin_economy_bypass.js",
  "Rate-limit and single-use every code server-side; take the daily-reset time from the server, not the device clock.")

v("BIZ-11", "Invite, leaderboard and miner-request flows are client-editable", "Medium", "Business logic",
  "<code>account/getInviteData.php</code>, <code>setInviteCode.php</code>, <code>getLeaderBoard.php</code>, <code>getMinerRequests.php</code> and <code>changeMinerRequest.php</code> all take a client-built JSON body with a locally generated <code>request_id</code> UUID (<code>UUID.randomUUID()</code>) and a <code>by</code>/<code>user_pk</code> identity field.",
  "Referral rewards and rankings can be inflated by spoofing <code>user_pk</code>/<code>by</code>; a locally generated <code>request_id</code> provides no deduplication guarantee unless the server enforces it.",
  "<code>ha.h.java:51,60,69,78</code> <code>addProperty(\"request_id\", UUID.randomUUID().toString())</code>; <code>ha.i.java:44</code> <code>addProperty(\"user_pk\", ...)</code>; six <code>addProperty(\"by\", ...)</code> sites",
  "05_coin_economy_bypass.js, 08_backend_traffic_and_servercheck.js",
  "Derive identity from the authenticated session server-side; issue request ids from the server and enforce idempotency.")

v("BIZ-12", "Server-pushed update and download links are opened without verification", "High", "Integrity",
  "<code>ServerCheckModel</code> carries <code>update_available</code>, <code>update_url</code> and <code>repair_mode</code>, and <code>app_info</code> carries <code>download_link</code>, <code>shop_link</code>, <code>support_link</code> and <code>channel_link</code>. The base URL and pin come from the same channel. There is no signature or digest check over the update payload.",
  "Whoever can MITM or compromise the ServerCheck response can point every install at an arbitrary APK or web page. Because the pin also arrives on that channel (CRYP-04), the MITM can pin itself first and then serve the update.",
  "<code>models.ServerCheckModel{url,pin,pin_active,repair_mode,update_available,update_url}</code>; <code>app_info(download_link, shop_link, support_link, channel_link)</code>; bootstrap in <code>com.bumptech.glide.manager.r</code>",
  "02_ssl_pinning_bypass.js, 08_backend_traffic_and_servercheck.js",
  "Distribute updates only through Play's in-app update API, and sign any out-of-band payload with a key embedded at build time.")

# ============================================================ TRANSPORT ======
v("TRAN-01", "Certificate pinning defeated at the Java layer", "High", "Transport",
  "Pinning is implemented as <code>okhttp3.CertificatePinner</code> instances constructed from native code via JNI. <code>CertificatePinner.check()</code> is an ordinary Java method, so replacing its implementation with a no-op accepts any certificate, and hooking <code>CertificatePinner$Builder.add()</code> reveals every pin as it is installed.",
  "Full MITM of both the Instagram private API and the TopFollow backend, exposing every credential, token and coin claim in cleartext to an attacker on the same network.",
  "<code>libtopfollow.so</code> references <code>certificatePinner</code> / <code>CertificatePinner$Builder.add</code>; pin literal <code>sha256/d845591e...</code>; no TLS imports in the .so (CRYP-05)",
  "02_ssl_pinning_bypass.js",
  "Perform verification in native code against a pinned SPKI set, and validate the pin list itself with a build-time signature.")

v("TRAN-02", "Backend base URL and pin are downloaded at runtime", "Critical", "Transport",
  "<code>ha.h</code> constructs its Retrofit with <code>helper.q.k(com.bumptech.glide.d.p(SP.getString(\"Pin\",\"\")), SP.getBoolean(\"PinActive\",false))</code>. The stored <code>Pin</code> blob and <code>PinActive</code> flag are written by the ServerCheck bootstrap from the network response. The current decoded value is <code>https://top.nivafollower.app/v840/</code>.",
  "A single compromised or intercepted ServerCheck response redirects the whole application &mdash; including <code>instagramLogin.php</code>, which carries the user's Instagram password &mdash; to an attacker-controlled host, with the attacker's certificate pinned as trusted.",
  "<code>ha.h.java</code> <code>q.k(d.p(Pin), PinActive)</code>; <code>com.bumptech.glide.manager.r</code> stores <code>Pin</code>/<code>PinActive</code>; decoded URL from <code>libtopfollow.so</code> XOR 0x55",
  "08_backend_traffic_and_servercheck.js, 02_ssl_pinning_bypass.js",
  "Hard-code the production base URL and pin in the binary. If rotation is required, sign the ServerCheck payload with a build-time embedded public key and verify it natively.")

v("TRAN-03", "No <code>networkSecurityConfig</code> declared", "Medium", "Transport",
  "The manifest sets <code>android:usesCleartextTraffic=\"false\"</code> but declares no <code>android:networkSecurityConfig</code>. There is therefore no certificate-transparency requirement, no explicit trust-anchor restriction and no per-domain policy; on API 24+ user-installed CAs are excluded by default, but the app's own WebView and any debug-build behaviour is unconstrained.",
  "The only transport control is the runtime-installed OkHttp pinner, which is itself hookable (TRAN-01) and remotely replaceable (TRAN-02). A declarative policy would at least survive Java-layer hooking.",
  "<code>out/07_AndroidManifest.xml</code>: <code>usesCleartextTraffic=\"false\"</code>, <code>networkSecurityConfig</code> absent",
  "02_ssl_pinning_bypass.js",
  "Add a <code>network_security_config.xml</code> pinning the backend and Instagram domains, with <code>&lt;pin-set&gt;</code> entries, a backup pin and an expiration date.")

v("TRAN-04", "Response host/path verification is a native function over a client-held object", "Medium", "Transport",
  "<code>helper.q.e()</code> (<code>x0014e2e9</code>) is referenced alongside <code>getHost</code>, <code>getPath</code> and <code>web</code>, indicating a post-response check that the reply came from the expected host and path. It runs on the client, over a response object the client already holds.",
  "A client-side check of a value the client controls is not a control: with Frida attached it returns whatever the caller wants, so it provides no assurance that traffic was not redirected.",
  "<code>libtopfollow.so!x0014e2e9</code> string references <code>getHost</code>, <code>getPath</code>, <code>web</code>; Java wrapper <code>helper.q.e()</code>",
  "07_native_jni_dumper.js",
  "Verify origin server-side, or rely on a declarative network security config plus native TLS verification.")

v("TRAN-05", "Instagram private-API traffic multiplexed with backend traffic in one process", "Medium", "Transport",
  "Three Retrofit instances for Instagram (<code>b.i.instagram.com/api/v1/</code>, <code>i.instagram.com/api/v2/</code>, <code>www.instagram.com/graphql/query</code>) and one for the vendor backend share a single OkHttp stack built by the same native bootstrap; <code>d.t()</code> headers go to the backend while <code>ia.q.f()</code> headers go to Instagram.",
  "One successful MITM or one hooked interceptor yields both the Instagram session material and the TopFollow account material simultaneously; there is no isolation between the two trust domains.",
  "<code>helper.q.l(0|1|2)</code> &rarr; <code>x0018d3f7</code>; <code>helper.q.k()</code> &rarr; <code>x00126f7c</code>; <code>ia.q.f()</code> vs <code>d.t()</code>",
  "03_instagram_api_intercept.js, 08_backend_traffic_and_servercheck.js",
  "Separate the trust domains: never let the vendor backend see Instagram session material (CRED-04), and use distinct OkHttp clients with distinct pin sets.")

# ============================================================ STORAGE =======
v("STOR-01", "Room database is unencrypted", "Critical", "Data storage",
  "<code>MyDatabase.setup()</code> builds the database named <code>t_f_d_b_f_v_c</code> through a plain Room builder (<code>c2.u(context)</code>). There is no SQLCipher, no <code>SupportFactory</code> passphrase and no Jetpack Security usage anywhere in the DEX. The file contains Instagram passwords (<code>u_w</code>), bearer tokens (<code>u_a</code>), TOTP seeds (<code>s_k</code>), session tokens, the coin/gem wallet and the FCM token.",
  "Any local attacker &mdash; rooted device, malicious app with backup access, forensic tool or stolen phone &mdash; reads the full credential and wallet store with <code>sqlite3</code>. The only protection over the values is the keyless cipher of CRYP-01.",
  "<code>com.nivaroid.topfollow.db.MyDatabase.setup()</code>; Room DDL strings for <code>device</code>, <code>instagram_accounts</code>, <code>two_factors</code>, <code>app_info</code>",
  "04_credential_theft.js",
  "Encrypt with SQLCipher under an AndroidKeyStore-resident key, and stop storing passwords and TOTP seeds at all (CRED-01, CRED-02).")

v("STOR-02", "<code>allowBackup=true</code> with completely empty backup-exclusion rules", "Critical", "Data storage",
  "The manifest declares <code>android:allowBackup=\"true\"</code> with <code>android:fullBackupContent=\"@7F160000\"</code> and <code>android:dataExtractionRules=\"@7F160001\"</code>. Both resources were decoded from the ARSC and are empty shells: <code>&lt;full-backup-content/&gt;</code> (132 bytes) and <code>&lt;data-extraction-rules&gt;&lt;cloud-backup/&gt;&lt;/data-extraction-rules&gt;</code> (212 bytes). Neither contains a single <code>&lt;exclude&gt;</code> element, so the default include-everything behaviour applies to the database and shared_prefs directories.",
  "The unencrypted Room database &mdash; Instagram passwords, TOTP seeds, session tokens &mdash; plus all of <code>TOPFVC_Shared</code>, is copied into the user's Google cloud backup and into any device-to-device transfer. An attacker who compromises the Google account, or who borrows the phone during a migration, obtains every credential without ever touching the device.",
  "<code>res/Qq.xml</code> = <code>&lt;full-backup-content/&gt;</code>; <code>res/4j.xml</code> = <code>&lt;data-extraction-rules&gt;&lt;cloud-backup/&gt;&lt;/data-extraction-rules&gt;</code>; <code>out/21_backup_rules.txt</code>",
  "04_credential_theft.js",
  "Set <code>allowBackup=\"false\"</code>, or add explicit <code>&lt;exclude domain=\"database\" path=\"t_f_d_b_f_v_c\"/&gt;</code> and <code>&lt;exclude domain=\"sharedpref\" path=\"TOPFVC_Shared.xml\"/&gt;</code> to both rule files.")

v("STOR-03", "Sensitive values in SharedPreferences with reversible obfuscation", "High", "Data storage",
  "<code>TOPFVC_Shared</code> (MODE_PRIVATE) holds <code>ActiveID</code>, <code>ATFLogged</code>, <code>SingleTasking</code>, <code>Sign</code>, <code>RID</code>, <code>RD</code>, <code>SND</code>, <code>Aid</code>, <code>DeviceId</code>, <code>Pin</code>, <code>PinActive</code>, <code>Language</code>, <code>NewTaskType</code>, <code>ShowShop</code>, <code>AIT</code> and <code>RIT</code>. <code>Sign</code>, <code>Aid</code>, <code>DeviceId</code>, <code>RD</code> and <code>Pin</code> are wrapped in <code>d.q()</code> &mdash; the keyless cipher of CRYP-01 &mdash; and unwrapped with <code>d.p()</code>.",
  "The backend base URL and pin, the integrity gate values (<code>SND</code>/<code>RID</code>), the cached attestation token (<code>RD</code>/<code>RIT</code>/<code>AIT</code>) and the device identity are all readable and writable by the app itself, and all included in backups.",
  "<code>helper/a0.x0()..x4()</code>, <code>ha.h</code>, <code>d3.d.l()</code>, <code>com.bumptech.glide.manager.r</code>",
  "04_credential_theft.js, 08_backend_traffic_and_servercheck.js",
  "Use EncryptedSharedPreferences with an AndroidKeyStore master key, and exclude the file from backup.")

v("STOR-04", "<code>extractNativeLibs=false</code> leaves the packed .so directly accessible", "Low", "Data storage",
  "The manifest sets <code>android:extractNativeLibs=\"false\"</code>, so <code>libtopfollow.so</code> (arm64-v8a, x86_64, x86) is loaded straight out of the APK zip and is never unpacked into a protected directory.",
  "The protection surface &mdash; all obfuscated strings, the pin, the detection keywords and the 22 JNI functions &mdash; can be lifted from the APK with <code>unzip</code> and analysed offline, which is exactly how this report was produced.",
  "<code>out/07_AndroidManifest.xml</code>; <code>lib/{arm64-v8a,x86_64,x86}/libtopfollow.so</code> and <code>libdatastore_shared_counter.so</code>",
  "07_native_jni_dumper.js",
  "This flag is a performance choice, not a security one. Do not treat native code presence as protection (see INTE-06).")

v("STOR-05", "<code>get_image.php</code> accepts a client-supplied <code>image_url</code>", "Medium", "Server-side",
  "<code>ha.i</code> POSTs to <code>get_image.php</code> with a body containing <code>image_url</code> (six <code>addProperty(\"image_url\", ...)</code> sites), <code>request_id</code>, <code>user_pk</code> and <code>by</code>. The server is expected to fetch that URL and return an image.",
  "A server-side request forgery primitive: an attacker can point <code>image_url</code> at internal addresses, cloud metadata endpoints (169.254.169.254) or arbitrary third parties, using the vendor's server as a proxy.",
  "<code>ha.i.java:44-45</code>; <code>addProperty(\"image_url\", ...)</code> call sites",
  "08_backend_traffic_and_servercheck.js",
  "Validate and allow-list the URL server-side, resolve and block private/link-local ranges, disable redirects, and cap response size and content type.")

v("STOR-06", "Crash reporting and analytics collect device and session data pre-consent", "Low", "Privacy",
  "Firebase Crashlytics, Firebase Messaging, Firebase Sessions and <code>androidx.datatransport</code> (CCT backend) are all registered via <code>androidx.startup</code> initialisation providers and run before any user-consent gate.",
  "Device identifiers, session data and crash traces &mdash; potentially including fragments of harvested credentials inside exception messages &mdash; leave the device automatically.",
  "Manifest <code>meta-data</code> <code>com.google.firebase.components:*Registrar</code> entries; authorities <code>com.nivaroid.topfollow.firebaseinitprovider</code>, <code>com.nivaroid.topfollow.androidx-startup</code>; <code>backend:...CctBackendFactory = cct</code>",
  "08_backend_traffic_and_servercheck.js",
  "Gate Crashlytics collection behind an explicit consent flag and scrub credential material from logs and exception messages.")

v("STOR-07", "WebView used for Instagram login and hCaptcha with a JS bridge", "High", "Credentials",
  "<code>WebViewActivity</code> loads <code>https://www.instagram.com/</code> for the cookie-harvest login path (CRED-03) and also renders hCaptcha from an embedded HTML template using <code>jsSrc https://js.hcaptcha.com/1/api.js</code>, exposing a <code>JSInterface</code> bridge object with <code>getConfig()</code>, <code>onPass(token)</code>, <code>onError()</code>, <code>onLoaded()</code> and <code>onOpen()</code>. The template mocks the bridge when it is absent and reads <code>window.JSDI.getDebugInfo()</code>.",
  "A JavaScript bridge in a WebView that displays a live Instagram session is a credential-exposure channel: any injected or compromised script in that context can read cookies and call back into the app. The hCaptcha bridge hands the token straight to native code, so a token can be injected without solving a challenge.",
  "<code>oa.l1</code> / <code>com.nivaroid.topfollow.ui.WebViewActivity</code>; embedded hCaptcha HTML template in the DEX string table containing <code>BridgeObject = window.JSInterface</code>",
  "04_credential_theft.js, 02_ssl_pinning_bypass.js",
  "Do not run third-party login flows in an in-app WebView. Use Custom Tabs so the browser owns the session, restrict <code>addJavascriptInterface</code> to bound methods, and verify captcha tokens server-side only.")

v("STOR-08", "CAPTCHA site keys come from native code and the token is signed client-side", "Medium", "Business logic",
  "<code>CaptchaRequest</code> chooses between reCAPTCHA (<code>captcha_type == 0</code>) and hCaptcha, obtaining the site key from native <code>helper.q.f()</code> (<code>x0010e27f</code>) and <code>helper.q.g()</code> (<code>x00113f7a</code>). On success the token goes to <code>verifyCaptcha()</code>, which signs it with native <code>helper.q.c(token)</code> (<code>x00105e9b</code>) and sends <code>captcha_stamp</code> to <code>account/checkCaptcha.php</code>. The SDK fallback site key <code>10000000-ffff-ffff-ffff-000000000001</code> is present in the embedded template.",
  "The token can be supplied directly to <code>verifyCaptcha()</code> by a hook, bypassing the challenge UI entirely. Whether that succeeds depends solely on <code>checkCaptcha.php</code> validating the token with the provider &mdash; unverifiable from the client &mdash; and the native signing step adds no provider binding.",
  "<code>com.nivaroid.topfollow.views.CaptchaRequest</code> (<code>showReCaptcha</code>, <code>showHCaptcha</code>, <code>verifyCaptcha</code>); <code>ha.a.java:484</code> <code>addProperty(\"captcha_stamp\", q.c(token))</code>",
  "05_coin_economy_bypass.js",
  "Validate the captcha token server-side against the provider's siteverify API with the secret key, bound to the session and to the action being performed.")

v("STOR-09", "Task-control service accepts an arbitrary account id with no authorisation check", "Medium", "Integrity",
  "<code>DoTasksService.onStartCommand()</code> reads <code>action</code> (<code>stop</code>/<code>enable</code>/<code>disable</code>) and, for enable/disable, an integer extra <code>id</code> that it passes to <code>MyDatabase.setup().p(id)</code> to fetch an <code>InstagramAccount</code> and start automation for it. The service also broadcasts <code>\"task.service.receiver\"</code> with <code>type=start|stop</code> and <code>setPackage(\"com.nivaroid.topfollow\")</code>. Neither the service nor <code>TaskActionReceiver</code> is exported, so this is an internal surface &mdash; but the design accepts an arbitrary account id with no authorisation binding.",
  "Any component inside the app &mdash; including one reached through a WebView bridge or a hijacked intent relay &mdash; can start or stop credential-driven automation for any stored account by index.",
  "<code>DoTasksService.onStartCommand()</code>: <code>getExtras().getString(\"action\")</code>, <code>getExtras().getInt(\"id\")</code> &rarr; <code>new ja.e(MyDatabase.setup().p(id), ...)</code>; broadcast <code>\"task.service.receiver\"</code>",
  "05_coin_economy_bypass.js",
  "Validate that the caller is authorised for the requested account, keep the receiver unexported, and use in-process messaging instead of a broadcast.")

v("STOR-10", "No client-side throttling on the money endpoints", "Medium", "Business logic",
  "Claims (<code>order/syncOrder.php</code>), orders (<code>order/submitOrder.php</code>), coupons and daily gifts are issued back-to-back from worker threads and UI handlers with no client-side throttle beyond <code>app_info.action_delay</code> &mdash; a server-supplied integer used only to pace Instagram actions. <code>request_id</code> is a locally generated UUID.",
  "A scripted client can submit claims at arbitrary rate. Exploitability depends entirely on server-side controls of which the client shows no evidence, and the locally generated <code>request_id</code> offers no deduplication unless enforced.",
  "<code>ha.c</code>, <code>ha.b</code>, <code>ha.h</code>; <code>app_info.action_delay</code> column; <code>UUID.randomUUID()</code> request ids",
  "05_coin_economy_bypass.js, 06_task_verification_bypass.js",
  "Enforce per-account and per-device rate limits, server-issued idempotency keys, and anomaly detection on claim velocity.")

v("STOR-11", "Balances and activity exposed through notification text and reflected errors", "Low", "Data storage",
  "<code>DoTasksService.b()</code> renders a foreground notification containing live counters &mdash; <code>&quot;💰 Coins: &quot; + DoTasksService.s + &quot;\\n✅ Tasks done: &quot; + DoTasksService.t</code> &mdash; from static mutable fields, and the app surfaces raw server error strings (<code>&quot;Sorry, there was a problem with your request.&quot;</code>, <code>&quot;The password you entered is incorrect&quot;</code>, <code>&quot;We can't find an account with&quot;</code>) directly in the UI.",
  "Account activity and balances are visible on the lock screen, and reflected server error text can leak account existence and state to anyone holding the device.",
  "<code>DoTasksService.b()</code>; static fields <code>DoTasksService.s</code>/<code>.t</code>; <code>ia.s.success()</code> error-string branches",
  "06_task_verification_bypass.js",
  "Mark the notification sensitive (<code>visibility = VISIBILITY_PRIVATE</code>) and map server errors to generic client-side messages.")

v("STOR-12", "Login response parsed by substring matching on the raw JSON text", "Medium", "Instagram API",
  "<code>ia.s.success()</code> decides the login outcome by string-searching the raw response body for <code>\"Bearer\"</code>, <code>\"two_step_verification\"</code>, <code>\"challenge_required\"</code>, <code>\"The password you entered is incorrect\"</code>, <code>\"We can't find an account with\"</code> and <code>\"there was a problem with your request\"</code>, and extracts the 2FA context with <code>indexOf(\"(dkc\")</code> plus the regex <code>(\\d+)\\s+\"com\\.bloks\\.</code>. <code>ia.v.a()</code> likewise splits on <code>\"logged_in_user\"</code>, <code>\"headers\"</code>, <code>\"Bearer\"</code> and <code>\"hmac\"</code>.",
  "Fragile parsing of attacker-influenceable text. Any MITM (TRAN-01) or crafted Instagram response can steer the client into the two-step-verification branch, inject a chosen <code>challenge_context</code>, <code>instance_id</code> or <code>marker_id</code>, or cause a bearer token to be extracted from an arbitrary position in the body.",
  "<code>ia.s.success(InstagramBody)</code>; <code>ia.v.a(ia.v,String)</code>; constants <code>instance_id 4806706160933748992</code>, <code>marker_id 36707139</code>",
  "03_instagram_api_intercept.js, 06_task_verification_bypass.js",
  "Parse responses with a real JSON parser, validate against a schema, and reject unexpected shapes instead of substring-matching.")

v("STOR-13", "Bloks/CAA login flow with hard-coded instance and marker ids", "Low", "Instagram API",
  "The login POST targets <code>com.bloks.www.caa.login.login_homepage</code> with <code>bloks_version 083f38c334f42c5e3322bb77464c601e8882cd9ff2d30ac915ba7a497539d604</code>, <code>styles_id instagram</code> and a <code>server_params</code> block containing <code>INTERNAL__latency_qpl_instance_id 19558568600088</code>, <code>INTERNAL__latency_qpl_marker_id 36707139</code>, <code>offline_experiment_group caa_iteration_v3_perf_ig_4</code>, <code>access_flow_version pre_mt_behavior</code>, <code>login_surface login_home</code>, <code>login_entry_point logged_out</code>, plus an <code>aac</code> sub-object (<code>aac_init_timestamp</code>, <code>aacjid</code>, <code>aaccs</code>).",
  "Confirms the app is a full reimplementation of Instagram's confidential Android login flow rather than an OAuth client. Every constant is a fingerprint Instagram can use to detect and ban these sessions, and the hard-coded experiment ids will silently break as Instagram iterates.",
  "<code>ia.v</code> constructor and <code>ia.s.success()</code>; header <code>x-ig-client-endpoint: com.bloks.www.caa.login.login_homepage</code>",
  "03_instagram_api_intercept.js",
  "Use Instagram's official OAuth. Reimplementing the private login flow violates platform terms and puts the user's account at risk.")

v("STOR-14", "Direct-message, Threads and interop endpoints automated", "Medium", "Instagram API",
  "Beyond follow/like/comment/save/seen/repost the app references <code>direct_v2/has_interop_upgraded/</code>, <code>create_note/v2/</code> (Threads notes), <code>seen/</code>, <code>/save/</code>, three Facebook <code>doc_id</code> GraphQL documents and the token prefix <code>3,IGbdd5f76a8fb9c4f86adf36a09f2750dc,{pk}</code>, and stores <code>interop_messaging_user_fbid</code> and <code>fbid_v2</code> per account.",
  "The automation reaches into Instagram DM interop and Threads, widening the abuse surface well beyond follower exchange and exposing Facebook-side identifiers that link the Instagram and Facebook accounts.",
  "DEX string table: <code>direct_v2/has_interop_upgraded/</code>, <code>create_note/v2/</code>, <code>seen/</code>, <code>/save/</code>, <code>3,IGbdd5f76a8fb9c4f86adf36a09f2750dc,{pk}</code>; <code>instagram_accounts.interop_messaging_user_fbid</code>, <code>fbid_v2</code>",
  "03_instagram_api_intercept.js",
  "Do not automate private messaging or cross-product endpoints. Restrict to the sanctioned public API.")

v("STOR-15", "No user confirmation before credential-driven automation begins", "High", "Privacy",
  "Once an account row exists with <code>active=1</code>, <code>DoTasksService.onCreate()</code> collects it and <code>a()</code> starts a <code>ja.e</code> worker immediately; the only gate is the <code>SingleTasking</code> preference deciding whether one or all workers start. There is no per-action, per-session or per-account re-consent before the app begins following, liking, commenting and viewing stories as that user.",
  "Users hand over a password or session and the app then acts autonomously and continuously on their behalf with no meaningful ongoing consent &mdash; a serious informed-consent and ToS exposure for the user.",
  "<code>DoTasksService.onCreate()/a()</code>; <code>instagram_accounts.active</code>; <code>SharedPreferences \"SingleTasking\"</code>",
  "06_task_verification_bypass.js",
  "Require explicit, per-session, revocable consent for each automated action category, and show the user a running audit log.")

v("STOR-16", "Small exported surface, but the launcher activity is world-reachable", "Low", "Attack surface",
  "The manifest exports exactly three components: <code>com.nivaroid.topfollow.ui.TopActivity</code> (MAIN/LAUNCHER, no permission), <code>com.google.firebase.iid.FirebaseInstanceIdReceiver</code> (protected by <code>com.google.android.c2dm.permission.SEND</code>) and <code>androidx.profileinstaller.ProfileInstallReceiver</code> (protected by <code>android.permission.DUMP</code>). There are no deep links, no content providers beyond the Firebase/androidx-startup initialisers, and no exported services; <code>TaskActionReceiver</code> and <code>DoTasksService</code> are not exported.",
  "The direct IPC attack surface is small &mdash; a genuinely positive finding &mdash; but the two Firebase/androidx receivers are framework components whose protections are only as good as the platform's, and the launcher activity is the world-reachable entry point to the whole credential flow.",
  "<code>out/07_AndroidManifest.xml</code>; <code>uses-permission</code> set is INTERNET, FOREGROUND_SERVICE(_SPECIAL_USE), POST_NOTIFICATIONS, ACCESS_NETWORK_STATE, WAKE_LOCK, c2dm.RECEIVE plus a self-declared signature-level <code>DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION</code>",
  "01_anti_tamper_killer.js",
  "Keep the receiver and service unexported, and validate every intent extra on the launcher path since it is world-reachable.")


# ===========================================================================
# PASS 2 -- native binary deep dive (AES discovery + Unicorn execution proof)
#
# The first pass over libtopfollow.so reported "no crypto in the native
# library". That conclusion was WRONG, and the cause is worth recording: the
# reference resolver (work/fn_strings3.py) discarded any .rodata target that
# was not >=92% printable, so the AES S-box, inverse S-box and rcon -- which
# are high-entropy binary tables -- were silently filtered out of every
# listing. work/aes_forensics.py and work/aes_xref.py keep binary references,
# and work/unicorn_aes.py then EXECUTES the code to confirm what it is.
# ===========================================================================

v("CRYP-09", "Native AES-table cipher with an AES-256-shaped key expansion; block ciphers not validated under emulation, and unreachable from Java", "High", "Cryptography",
  "<code>libtopfollow.so</code> contains a compact, table-based cipher built on the real AES tables in all three ABIs. The canonical FIPS-197 forward S-box, inverse S-box and rcon were located by byte-pattern search &mdash; arm64-v8a <code>0x128b0</code>/<code>0x139b0</code>/<code>0x13b10</code>, x86_64 <code>0x0db80</code>/<code>0x0ec80</code>/<code>0x0ede0</code>, x86 <code>0x07070</code>/<code>0x08170</code>/<code>0x082d0</code> &mdash; and each was verified to be the true AES table by independent derivation in GF(2<sup>8</sup>) and by confirming that the inverse table is the exact permutation inverse of the forward table. Five functions reference them: <code>0x2dc00</code>, <code>0x2fdcc</code> (S-box, encrypt), <code>0x2eb94</code>, <code>0x30f18</code> (inverse S-box, decrypt) and <code>0x32158</code> (S-box <i>and</i> rcon, key expansion), behind wrappers <code>0x34424</code>, <code>0x35518</code>, <code>0x38fa4</code>, <code>0x3a838</code>. Running <code>0x32158</code> under Unicorn AArch64 with libc trampolines executed 89,148 instructions, returned normally, read <b>rcon exactly 14 times</b> (the AES-256 count), validated <code>w3</code>/<code>w4</code> against <code>#0x20</code>=32, and wrote a 240-byte (15&times;16) output. An instruction-level histogram (<code>work/unicorn_round_structure.py</code>, <code>out/42</code>) shows its 112 S-box reads come from exactly 8 distinct instructions each hit 14 times &mdash; the period-14 <code>SubWord</code> structure of AES-256 key expansion. <b>The key expansion is therefore structurally AES-256.</b> The <b>block ciphers, however, could not be validated under emulation</b>: on a zeroed schedule the encrypt block <code>0x2fdcc</code> returns early after 23,186 instructions with only 32 S-box reads (4 instructions &times; 8, a truncated path, not a 14-round ~160-read SubBytes), and with populated schedule buffers it does not terminate (3,000,000-instruction cap, 0 S-box reads) because the OLLVM control-flow-flattened dispatcher never reaches an exit state without the exact C++ <code>ctx</code> object layout (key string, IV, mode, GCM/CTR counter). The apparent <code>decrypt(encrypt(pt))&ne;pt</code> is a consequence of both calls taking truncated paths, not proof of a non-AES cipher. So the correct claim is &ldquo;an AES-table cipher with an AES-256-shaped key expansion&rdquo;, not &ldquo;proven standard AES-256&rdquo; and not &ldquo;proven not-AES&rdquo;. Separately, <b>none of the 22 <code>RegisterNatives</code> methods has a <code>([B)[B</code> signature</b>, and no <code>com.nivaroid.topfollow</code> method anywhere in the DEX has that descriptor, so whatever this cipher is, it is not directly callable from Java as a byte-array primitive.",
  "A table-based block cipher built on the real AES S-box is compiled into the shipping binary and used internally by the native request/signature pipeline, but it is invisible to any Java-level audit, to the app's own developers reviewing the Java layer, and to any tester who only instruments Java. Crypto that cannot be reached by the documented interface cannot be reviewed, rotated, disabled or tested &mdash; it is an unauditable primitive sitting in the trust path of every signed request. That even its exact algorithm resists validation without the live object layout makes it <i>less</i> reviewable still: an analyst cannot safely assume textbook AES semantics. It also means an analyst who only examines the DEX will conclude, wrongly, that the app performs no native encryption at all.",
  "S-box/inverse/rcon located and verified in all three ABIs (<code>work/out/30_aes_forensics_arm64.txt</code>); five referencing functions and the 22-ancestor call graph (<code>work/out/32_aes_xref_arm64-v8a.json</code>); Unicorn key-expansion log, 112 S-box + 14 rcon reads (<code>work/out/33_unicorn_aes_arm64.txt</code>); period-14 S-box-read IP histogram for keyexp and the 4&times;8 encrypt pattern (<code>work/out/42_round_structure.txt</code>); block-cipher runs that early-exit / spin, showing they are unvalidated (<code>work/out/40_verify_cipher.txt</code>, <code>work/out/41_roundtrip.txt</code>); 22 JNI signatures from the DEX, none <code>([B)[B</code> (<code>work/out/39_jni_full_map.json</code>)",
  "09_native_aes_dump.js",
  "Do not ship cryptographic primitives that no documented interface reaches, and do not ship a cipher whose exact algorithm cannot be validated without the live object layout. Either expose it through an auditable, standards-conformant API with a rotatable key, or remove it. Publish the key-management story for whatever remains.")

v("CRYP-10", "Native AES key is runtime-derived: it is not the caller's key and not a byte window of the file", "High", "Cryptography",
  "The Unicorn run of the key-expansion routine <code>0x32158</code> was given a FIPS-197 AES-256 test key in a caller buffer laid out three different ways (libc++ short-string, libc++ long-string, and a plain {ptr,len,cap} triple). All three runs were byte-identical: 89,148 instructions, 112 S-box reads, 14 rcon reads, and the same resulting schedule. The expanded schedule therefore does <b>not</b> depend on the key supplied by the caller. A full per-instruction read trace (<code>work/unicorn_key_trace.py</code>, 9,173 reads) shows the caller key buffer is <b>never read at all</b>; instead the routine reads the <code>ctx</code> struct byte-by-byte and pulls <b>52 scattered single bytes from a 549-byte high-entropy table at <code>.rodata 0x13b30</code></b> (entropy 7.8099, immediately after rcon, preceded by a 16-byte constant <code>9a2f5ebc&hellip;c591</code> at <code>0x13b1e</code>). That table is not the S-box, not the inverse, not a permutation and not a GF(2<sup>8</sup>) log table &mdash; it is a key-derivation / whitening table that the first content-scan missed because it only looked for the five canonical AES patterns. Brute-force over every 16-, 24- and 32-byte window of the 1,805,400-byte file (5.4 million candidates) found no window that expands to the observed RK0 <code>1742e227063cdfce2c2b4cbd71f1297a</code>, and RK0 appears in no file-backed region the routine reads. The key is computed inside the OLLVM-flattened prologue at runtime by folding the <code>0x13b30</code> table, the <code>0x13b1e</code> constant and the <code>ctx</code> state together.",
  "The cipher's key cannot be extracted by reading the binary, and cannot be influenced by the caller &mdash; so whatever this AES protects is keyed by a value that exists only during execution. That makes the protection opaque even to the vendor's own Java-side code review, and it means the key is either a hardcoded derivation (recoverable by one dynamic trace, and then identical on every install forever) or depends on device state (in which case it is not portable and silently breaks recovery and migration). Neither is a sound key-management design.",
  "<code>work/out/34_aes_key_recovery.txt</code>: observed RK0..RK14; 5,416,128 file windows scanned, no match; three caller-buffer layouts producing identical schedules. <code>work/out/37_key_source_trace.txt</code> + <code>38_key_source_summary.txt</code>: the 9,173-read trace, reads-by-region, and the <code>0x13b30</code> whitening-table hexdump. <code>work/unicorn_key_trace.py</code> reproduces it.",
  "09_native_aes_dump.js",
  "Derive keys with a documented KDF from a server-issued secret and a device-bound AndroidKeyStore key. Never key a production cipher from an opaque in-binary computation.")

v("CRYP-11", "Instagram password sealed with RSA PKCS#1 v1.5 rather than OAEP", "Medium", "Cryptography",
  "<code>q8.t1.f(String plaintext, String pubKeyB64, String keyId)</code> is the app's Instagram password encryptor and produces the <code>#PWD_INSTAGRAM:4:&lt;ts&gt;:&lt;base64&gt;</code> envelope. It generates a 32-byte AES key and a 12-byte IV from <code>SecureRandom</code>, wraps the AES key with <code>Cipher.getInstance(\"RSA/ECB/PKCS1PADDING\")</code>, then encrypts the password with <code>Cipher.getInstance(\"AES/GCM/NoPadding\")</code> using <code>GCMParameterSpec(128, iv)</code> and <code>updateAAD(ts.getBytes())</code>. The blob is <code>0x01 || keyId || iv[12] || u16le(encKeyLen) || encKey || tag[16] || ciphertext</code>. The construction is sound &mdash; authenticated encryption with the timestamp bound as additional authenticated data &mdash; but the key-wrapping layer uses PKCS#1 v1.5 padding instead of RSA-OAEP.",
  "PKCS#1 v1.5 key transport is the padding variant with a long history of padding-oracle and Bleichenbacher-style attacks; OAEP is the recommended replacement. In this specific deployment the practical exposure is limited because the ciphertext is consumed only by Instagram's own servers and the app never exposes a decryption oracle, but it means the strongest layer of the password's protection rests on a deprecated padding scheme. This is inherited from Instagram's protocol rather than chosen by the vendor, which is itself the point: the vendor has reimplemented a confidential protocol and inherits its weaknesses without owning them.",
  "<code>q8.t1.java:56</code> <code>Cipher.getInstance(\"RSA/ECB/PKCS1PADDING\")</code>; <code>q8.t1.java:59-61</code> AES/GCM/NoPadding + <code>GCMParameterSpec(128, iv)</code> + <code>updateAAD</code>; called from <code>ia.v.java:259</code> <code>params.put(\"password\", q8.t1.f(...))</code>",
  "10_java_crypto_layer.js",
  "Use Instagram's official OAuth instead of reimplementing its private password-sealing protocol. If the protocol must be implemented, prefer OAEP where the server allows it and pin the expected key length.")

v("CRYP-12", "The RSA public key that seals the password is supplied by the network at runtime and never validated", "High", "Cryptography",
  "<code>ia.m.java:215-218</code> reads two Instagram response headers &mdash; <code>Ig-Set-Password-Encryption-Key-Id</code> and <code>Ig-Set-Password-Encryption-Pub-Key</code> &mdash; into <code>InstagramReqInfo.key_id</code> and <code>.pub_key</code>. <code>ia.v.java:259</code> then passes them straight into <code>q8.t1.f()</code>, which base64-decodes the key, strips <code>-(.*)-|\\n</code>, wraps it in an <code>X509EncodedKeySpec</code> and uses it to seal the user's Instagram password. There is no allow-list of expected keys, no key-length or algorithm check, no certificate validation and no comparison against any previously seen key. Scanning all three ABIs for RSA SubjectPublicKeyInfo DER prefixes (<code>30820122300d06092a864886f70d010101</code>), modulus prefixes and PEM headers confirms <b>no RSA public key is embedded in the binary</b> &mdash; the trust anchor for the password is entirely network-supplied.",
  "Anyone who can present a response to the app &mdash; a MITM who has defeated the Java-side pinning, a hostile network, or an attacker who has hijacked the runtime-supplied ServerCheck pin (see TRAN-02 and CRYP-04) &mdash; can install their own RSA public key. The app will then seal the victim's real Instagram password to the attacker's key, hand over the complete <code>#PWD_INSTAGRAM:4:</code> blob, and the attacker decrypts it offline. The password is captured in plaintext without ever breaking the encryption. This composes directly with the ServerCheck pin-injection flaw: one hijacked bootstrap response yields the entire user base's Instagram passwords.",
  "<code>ia.m.java:215-218</code> header capture; <code>com.nivaroid.topfollow.models.InstagramReqInfo</code> fields <code>key_id</code>, <code>pub_key</code>; <code>q8.t1.java:52-58</code> decode + <code>X509EncodedKeySpec</code> with no validation; absence of any RSA DER/PEM in all three ABIs",
  "10_java_crypto_layer.js, 02_ssl_pinning_bypass.js, 08_backend_traffic_and_servercheck.js",
  "Validate the supplied public key: enforce a minimum modulus size, require RSA, and compare its fingerprint against a pinned allow-list or a signed key-distribution channel. Reject the login rather than sealing to an unexpected key.")

v("CRYP-13", "Native AES is table-based with no ARMv8 Crypto Extension, so it is cache-timing exposed", "Low", "Cryptography",
  "A full instruction sweep of arm64 <code>.text</code> (397,892 instructions) found <b>zero</b> occurrences of <code>aese</code>, <code>aesd</code>, <code>aesmc</code>, <code>aesimc</code>, <code>sha1*</code> or <code>sha256*</code>. Combined with the absence of 32-bit T-tables (<code>Te0[0]=0xc66363a5</code>, <code>Td0[0]=0x51f4a750</code> and their byte-swapped forms are all not present) this identifies the implementation as the compact 256-byte-S-box variant rather than a bitsliced or hardware-accelerated one. The <code>DT_NEEDED</code> list is <code>libz, libandroid, liblog, libm, libdl, libc</code> &mdash; no crypto library &mdash; and the 90 imported symbols contain no cryptographic function.",
  "S-box lookups indexed by secret-dependent bytes are the classic AES cache-timing side channel. On a shared device another process in the same cache domain can recover the key from lookup timing. The practical severity is low because the cipher is internal to the native pipeline rather than protecting long-lived secrets at rest, and exploiting it needs a co-resident attacker &mdash; but it also means the app forgoes the ARMv8 AES instructions that every supported device (minSdk 24) provides, so it is slower and weaker than the platform default for no benefit.",
  "Capstone sweep of arm64 <code>.text</code>: no <code>aese/aesd/aesmc/aesimc/sha*</code> (<code>work/out/30_aes_forensics_arm64.txt</code> section 5); T-table constants absent (section 2); <code>DT_NEEDED</code> and 90-symbol import list contain no crypto (section 8)",
  "09_native_aes_dump.js",
  "Use the ARMv8 Crypto Extension (constant-time by construction) or BoringSSL via the platform. If a software table implementation must stay, use a bitsliced variant and mask the lookups.")

v("CRYP-14", "Opaque 5-byte literal 'F3AES' embedded in the JNI metadata cluster of all three ABIs and referenced by nothing", "Low", "Cryptography",
  "A 5-byte NUL-terminated string <code>F3AES</code> sits at arm64 <code>.rodata+0x14b2f</code>, x86_64 <code>+0x0fdff</code> and x86 <code>+0x092ef</code>. Its immediate neighbours are unmistakably JNI registration metadata: <code>(Lretrofit2/Response;)Ljava/lang/String;</code>, <code>(ZLjava/lang/String;)Lretrofit2/Retrofit;</code>, <code>digest</code>, <code>com/nivaroid/topfollow/helper/T</code>, <code>setup</code>, <code>()Lcom/nivaroid/topfollow/models/InstagramAccount;</code>. An exhaustive ADRP+ADD/ADR/LDR resolution sweep of the entire arm64 <code>.text</code> found <b>no instruction that computes the address of <code>F3AES</code></b>, and the string does not appear anywhere in the DEX. It also does not decode as base64 under any alignment or prefix.",
  "The name reads as a cipher-suite or algorithm identifier, and it is placed among live JNI metadata, yet nothing in the binary or the DEX consumes it. That is either a dead remnant of a removed or disabled cryptographic feature &mdash; in which case the shipping binary carries unreferenced crypto naming that will mislead any audit, including this one, and may indicate code paths still reachable by a future or server-flagged build &mdash; or it is consumed through a computed offset the static sweep cannot model, in which case an analyst cannot rule out an undisclosed algorithm selector. Both readings mean the binary contains crypto-related metadata whose liveness cannot be established statically.",
  "<code>F3AES</code> present in all three ABIs at the offsets above; zero resolving instructions across 397,892 arm64 <code>.text</code> instructions; absent from the DEX and from <code>work/out/03_all_strings.txt</code>; adjacent JNI metadata strings listed",
  "09_native_aes_dump.js, 07_native_jni_dumper.js",
  "Strip unreferenced literals at link time (<code>-ffunction-sections</code> + <code>--gc-sections</code>). Do not leave dead crypto identifiers in a shipped binary; they cannot be distinguished from live ones by an auditor.")

v("CRED-11", "Dead JNI bridge: native code looks up helper.T.digest([B)[B which does not exist in the DEX", "Medium", "Credentials",
  "At arm64 VAs <code>0x106660</code> and <code>0x162c4c</code> (and the equivalents at <code>0x106714</code> and <code>0x162ce0</code>) <code>libtopfollow.so</code> executes <code>ldr x8,[x8,#0x108]</code> &mdash; JNIEnv function-table slot 33, <code>GetStaticMethodID</code> &mdash; with <code>x1</code> = the class ref for <code>com/nivaroid/topfollow/helper/T</code>, <code>x2</code> = <code>\"digest\"</code> (<code>.rodata+0x14b88</code>) and <code>x3</code> = <code>\"([B)[B\"</code> (<code>.rodata+0x14cc4</code>). Enumerating the DEX directly shows <code>helper.T</code> declares exactly two methods, <code>o(Ljava/lang/String;)Ljava/lang/String;</code> and <code>sd(Ljava/lang/String;)Ljava/lang/String;</code>. There is no <code>digest</code> method, and no method with descriptor <code>([B)[B</code> exists in any <code>com.nivaroid.topfollow</code> class. The lookup therefore returns NULL and raises <code>NoSuchMethodError</code>.",
  "The native layer expects a Java <code>static byte[] digest(byte[])</code> that the shipped DEX does not provide. That is a build-integrity defect: native and Java halves of the app are out of step, so either a code path silently fails at runtime (and whatever protection or transform it was meant to perform does not happen), or the Java class was stripped by an obfuscator that renamed or removed a method the native side still references by string. Either way it demonstrates that the native/Java contract is not verified at build time, and it is exactly the kind of mismatch an attacker can exploit by supplying their own <code>digest</code> implementation in a repackaged build to control what the native code believes it hashed.",
  "Disassembly at <code>0x106644-0x106664</code> and <code>0x162c30-0x162c50</code>: <code>ldr x8,[x8,#0x108]</code> then <code>add x2,x2,#0xb88</code> (<code>digest</code>), <code>add x3,x3,#0xcc4</code> (<code>([B)[B</code>), <code>blr x8</code>; DEX enumeration of <code>Lcom/nivaroid/topfollow/helper/T;</code> returning only <code>o</code> and <code>sd</code>; zero <code>([B)[B</code> methods in the app's packages",
  "10_java_crypto_layer.js, 07_native_jni_dumper.js",
  "Add a build-time check that every <code>FindClass</code>/<code>Get*MethodID</code> target in the native code exists in the compiled DEX, and fail the build otherwise. Exclude natively-referenced classes from obfuscator renaming.")

v("INTE-13", "ECDSA device-attestation key uses a fixed alias and a 25-year self-signed certificate", "Medium", "Integrity",
  "<code>com.nivaroid.topfollow.helper.T</code> performs the app's device attestation against the AndroidKeyStore under the hardcoded alias <code>top_key_4286</code>. <code>T.o(String)</code> loads the keystore, fetches <code>getCertificate(\"top_key_4286\")</code> and <code>getCertificateChain(\"top_key_4286\")</code>, signs the input with <code>SHA256withECDSA</code> using <code>getKey(\"top_key_4286\", null)</code>, and returns <code>Base64( signature + \"#\" + Base64(pubkey.getEncoded()) + \"#\" + JSONArray(Base64(cert[i].getEncoded())) )</code>. <code>T.sd(String)</code> returns just the signature. The native layer drives this through <code>q.i(JsonObject,String)</code> / <code>x00120b1e</code>, and <code>d3.d.java:738-740</code> generates the EC key pair and reads <code>ECPublicKey.getW()</code>. The alias is a compile-time constant identical on every installation.",
  "A fixed, guessable keystore alias means the attestation key is addressable by any code in the process, and the attestation is self-asserted: the app sends its own public key and its own certificate chain alongside the signature, so the server learns the key from the same untrusted channel it uses to verify it. Because the certificate chain is generated on-device rather than issued by a hardware attestation root, nothing binds the key to genuine StrongBox or TEE-backed storage &mdash; a repackaged build, an emulator or a rooted device can mint an identical-looking chain. The 25-year validity of the signing certificate elsewhere in this app (<code>2023-12-15</code> to <code>2048-12-08</code>) shows the project's posture toward key lifetimes.",
  "<code>com.nivaroid.topfollow.helper.T.o()/sd()</code>; alias literal <code>top_key_4286</code>; <code>d3.d.java:738-740</code> <code>KeyPairGenerator.getInstance(\"EC\")</code> + <code>ECPublicKey.getW()</code>; native driver <code>q.i</code> = <code>x00120b1e</code>",
  "10_java_crypto_layer.js, 08_backend_traffic_and_servercheck.js",
  "Use hardware-backed key attestation: generate the key with <code>setIsStrongBoxBacked(true)</code> and an attestation challenge issued by the server, then verify the certificate chain on the server up to the Google hardware attestation root and check <code>attestationSecurityLevel</code>. Derive the alias per-installation.")

v("INTE-14", "Native anti-analysis relies on file reads and string matching; no ptrace, TracerPid, property_get, dlopen or timing checks exist", "Medium", "Integrity",
  "The claimed detection set does not match the binary. Across all three ABIs the string tables contain <b>no</b> <code>ptrace</code>, <b>no</b> <code>TracerPid</code>, <b>no</b> <code>/proc/self/status</code>, <b>no</b> <code>property_get</code> or <code>__system_property_get</code>, <b>no</b> <code>dlopen</code>/<code>dlsym</code>, <b>no</b> <code>prctl</code>, <b>no</b> <code>clock_gettime</code> or <code>gettimeofday</code>. The 90-symbol import list confirms it: the only timing-adjacent import is <code>clock</code>, and the only syscall-adjacent ones are <code>syscall</code>, <code>__open_2</code>, <code>read</code>, <code>__read_chk</code>, <code>close</code> and <code>access</code>. What the library actually does is read <code>/proc/self/maps</code> and match keywords that are stored XOR-obfuscated with key <code>0x5A</code> (recovered in <code>work/out/19_xor_decoded.txt</code>), match base64-encoded Frida markers &mdash; decoding the <code>.rodata</code> base64 blobs yields <code>libfrida-gadget</code>, <code>re.frida.server</code>, <code>gum-js-loop</code>, <code>substrate</code>, <code>libcso_substrate</code>, <code>libbridge.so</code>, <code>libc.so (deleted)</code> and <code>libart.so (deleted)</code> &mdash; and <code>access()</code> nine hardcoded <code>su</code> paths. There is no inline-hook detection, no SVC-based syscall path, no debugger-attached check and no execution-timing check.",
  "Every detection in the native layer is a filesystem read followed by a substring match, which is the weakest possible construction: it is defeated by sanitising the buffer returned from <code>read()</code>, by hooking <code>strstr</code>/<code>strcmp</code>, or by simply not having the target strings present. Because there is no <code>ptrace</code> self-attach, no <code>TracerPid</code> parse and no timing check, a tracer can attach and single-step without ever tripping a detection. The obfuscation budget went entirely into control-flow flattening of code that performs trivially bypassable checks, so the anti-analysis story is far weaker than the binary's apparent sophistication suggests.",
  "String and import sweeps over all three ABIs; <code>DT_NEEDED</code> = libz, libandroid, liblog, libm, libdl, libc; 90 imported symbols enumerated in <code>work/out/30_aes_forensics_arm64.txt</code> section 8; base64-decoded anti-analysis markers; XOR key <code>0x5A</code> keyword table in <code>work/out/19_xor_decoded.txt</code>",
  "01_anti_tamper_killer.js, 07_native_jni_dumper.js",
  "Treat detection as telemetry for server-side risk scoring rather than as a gate. If native detection is retained, add checks that cannot be satisfied by sanitising a file read &mdash; hardware attestation verified server-side is the only construction that holds.")

v("OBFU-02", "OLLVM control-flow flattening only: .text entropy is 6.86, so the library is not packed", "Low", "Obfuscation",
  "Per-section entropy across arm64 <code>libtopfollow.so</code> shows <code>.text</code> = <b>6.8621</b> over 1,591,568 bytes and whole-file entropy = 6.7518. A packed or compressed <code>.text</code> scores above 7.8; 6.86 is the normal range for AArch64 code. The obfuscation is therefore purely control-flow: the AES wrapper at <code>0x34424</code> contains 1,085 instructions with a histogram of <code>mov</code>&nbsp;191, <code>movk</code>&nbsp;142, <code>cmp</code>&nbsp;119, <code>cset</code>&nbsp;46, <code>b.eq</code>&nbsp;28, <code>b.ne</code>&nbsp;23 and a single dispatch loop &mdash; the signature of OLLVM bogus-control-flow plus flattening. <code>.rodata</code> is only 37,547 bytes, so the claimed multi-megabyte white-box table cannot exist at any offset in a 1,805,400-byte file. The highest-entropy 4 KiB windows in the whole binary are <code>0x12000-0x13000</code> at 7.9954 and <code>0x13000-0x14000</code> at 7.9613 &mdash; and those two windows are precisely the AES S-box and inverse S-box, not a white-box table. <code>.eh_frame</code> yields 1,090 well-formed FDEs, which a packer would destroy.",
  "The binary looks formidable &mdash; 1.8 MB, a single exported symbol, 22 runtime-registered natives, flattened control flow &mdash; but none of that is packing, and the absence of packing is what made the whole analysis possible statically. Every secret was recoverable without executing the app: 943 position-independent thunks resolved to 760 <code>.rodata</code> references, and a single-byte XOR sweep over keys 1-127 recovered the backend URL, the Instagram endpoints, the certificate pin and the anti-analysis keyword tables. Assessing this app's real strength requires separating obfuscation from protection: the former is heavy, the latter is thin.",
  "<code>work/out/30_aes_forensics_arm64.txt</code> sections 6-7 (per-section entropy, top entropy windows); instruction histogram of <code>0x34424</code>; <code>.rodata</code> = 37,547 B; 1,090 <code>.eh_frame</code> FDEs from <code>work/native_deep.py</code>; no white-box table at the claimed offsets",
  "07_native_jni_dumper.js, 09_native_aes_dump.js",
  "Obfuscation is not a control. Spend the budget on server-side verification and hardware-backed attestation; client-side flattening only raises analysis cost, it does not change what an attacker who finishes the analysis can do.")
