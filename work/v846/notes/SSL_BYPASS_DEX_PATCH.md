# TOTAL SSL/CAPTURE BYPASS — TopFollow v846 (non-rooted, HTTPCanary)
### Self-contained spec: what to patch WHERE, with exact code. Companion to `PATCH_SPEC_v846.md`.

## 0. What "total SSL bypass" means for THIS app (evidence-based)

Layer-by-layer audit (all re-verified with a corrected dex scanner — an earlier androguard
call silently no-op'd, so every conclusion below is from the fixed scan):

| Layer | Finding | Bypass needed? |
|---|---|---|
| **Native .so — TLS** | ZERO TLS/network imports (no SSL_*/socket/connect/send/recv/getifaddrs), zero static TLS strings, zero TLS code. **Syscall-level scan also done**: only `svc` count in `.text` = 0; `syscall()` PLT (0x106370) has exactly **2 call sites** (0xeafe4, 0xeb03c), both with number **0xb2 = `delete_module`** — an environment-fingerprint canary (return value compared/stored), NOT networking. | **Nothing to bypass.** The .so cannot open connections; all HTTP is Java. |
| **Native .so — OkHttp JNI strings** | Present in rodata but **zero code references** (dead build residue) | Nothing. |
| **Java/dex — pinning** | Exactly 5 `new OkHttpClient$Builder` sites (`Ly9/i;.<init>` = C2 client, `Lz9/q;.q/.t`, `Lz9/v;.run`, `Lz9/x;.success` = 4 IG clients). **None** calls `certificatePinner(...)`, `sslSocketFactory(...)`, `hostnameVerifier(...)`, `proxy(...)`, or `proxySelector(...)`. All `CertificatePinner`/`TrustManager` usage in the dex is stock OkHttp-internal (`Lcc/*`, `Lyb/*`, `Ldc/*` = minified okhttp internals). | No pinning exists. |
| **Java/dex — proxy** | No `setProxy`, no custom `ProxySelector` on any client → all 5 clients use the **system proxy** (HTTPCanary's). `Lic/a;.select` (NO_PROXY) is OkHttp's *own* internal RouteSelector fallback, not app code. | No proxy-bypass to remove — good, traffic DOES flow through HTTPCanary. |
| **Java/dex — VPN/proxy detection** | `TYPE_VPN: 0`, `NET_CAPABILITY: 0`, `getLinkProperties: 0`, `VpnService: 0`, `isProxyEnabled: 0`, `getProxyName/Port: 0`. The 9 `ConnectivityManager`/`getActiveNetworkInfo` sites are plain "is internet on" UX checks. | **No VPN detection exists.** (ApkPatcher's "VPN bypass" had nothing to do here.) |
| **APK — network security config** | None in manifest, no `res/xml/network_security_config*`, no `usesCleartextTraffic`. targetSdk 35 → **default policy: only system CAs trusted, user CAs (HTTPCanary's) NOT trusted.** | **THIS is the only real TLS blocker.** Fix = make the app trust user CAs (Option A) or trust-all in code (Option B). |
| **Native .so — kill checks** | 12 detection/verify sites (frida scans, frida_tokens, hooktokens, delmaps, APK-SHA ×3) — all code-disabled by `patch_topfollow.py` (12-patch set, see PATCH_SPEC_v846.md). | Patched. **Critical for C2** (below). |

### Why you saw "IG captured, C2 not" with ApkPatcher
1. C2's Retrofit base URL is **native-provided**: `Ly9/i;.<init>` calls `Lcom/nivaroid/topfollow/helper/q;->e()` — the *only* native call in the whole dex that feeds a network base URL. If the native layer is in a kill-flag state, the C2 path dies while IG (hardcoded `https://i.instagram.com/`, pure Java path) survives.
2. ApkPatcher modifies the APK bytes → **APK-SHA re-verify (our R2/L3 checks) fails** → kill flag set natively → C2 path suppressed. IG path doesn't consult that flag the same way → visible.
3. ⇒ **Our 12-patch .so is the missing piece for C2**: with APK-SHA + all kill checks dead natively, the modified APK no longer poisons the native layer, `q.e()` keeps returning the real C2 URL, and C2 requests flow (through the system proxy, since no client overrides proxy).

## 1. The SSL bypass itself — Option B (recommended): trust-all at `OkHttpClient$Builder.build()`

One code patch makes **every** OkHttp client in the app (all 5) accept any certificate —
the complete, deterministic "SSL bypass" for the Java/dex layer. Apply via apktool
(`apktool d` → edit smali → `apktool b` → sign) or via ApkPatcher's smali-hook facility.

### 1a. New class — `smali/com/nivaroid/topfollow/helper/SSLBypass.smali`
```smali
.class public Lcom/nivaroid/topfollow/helper/SSLBypass;
.super Ljava/lang/Object;

.method public static apply(builder Lokhttp3/OkHttpClient$Builder;)Lokhttp3/OkHttpClient$Builder;
    .locals 5

    # --- trust-all X509TrustManager (inline impl below) ---
    new-instance v0, Lcom/nivaroid/topfollow/helper/SSLBypass$TM;
    invoke-direct {v0}, Lcom/nivaroid/topfollow/helper/SSLBypass$TM;-><init>()V

    # SSLSocketFactory from a TLS context seeded with the trust-all TM
    const-string v1, "TLS"
    invoke-static {v1}, Ljavax/net/ssl/SSLContext;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;
    move-result-object v1

    const/4 v2, 0x1
    new-array v2, v2, [Ljavax/net/ssl/TrustManager;
    const/4 v3, 0x0
    aput-object v0, v2, v3

    const/4 v4, 0x0
    invoke-virtual {v1, v4, v2, v4}, Ljavax/net/ssl/SSLContext;->init(Ljava/security/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V

    invoke-virtual {v1}, Ljavax/net/ssl/SSLContext;->getSocketFactory()Ljavax/net/ssl/SSLSocketFactory;
    move-result-object v1

    # install trust-all socket factory + trust manager on the builder
    invoke-virtual {builder, v1, v0}, Lokhttp3/OkHttpClient$Builder;->sslSocketFactory(Ljavax/net/ssl/SSLSocketFactory;Ljavax/net/ssl/X509TrustManager;)Lokhttp3/OkHttpClient$Builder;
    move-result-object builder

    # permissive hostname verifier (accepts any hostname)
    new-instance v0, Lcom/nivaroid/topfollow/helper/SSLBypass$HV;
    invoke-direct {v0}, Lcom/nivaroid/topfollow/helper/SSLBypass$HV;-><init>()V
    invoke-virtual {builder, v0}, Lokhttp3/OkHttpClient$Builder;->hostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)Lokhttp3/OkHttpClient$Builder;
    move-result-object builder

    return-object builder
.end method
```
### 1b. New class — `smali/com/nivaroid/topfollow/helper/SSLBypass$TM.smali`
```smali
.class public Lcom/nivaroid/topfollow/helper/SSLBypass$TM;
.super Ljavax/net/ssl/X509TrustManager;

.method public constructor <init>()V
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public checkClientTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V
    return-void
.end method

.method public checkServerTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V
    return-void
.end method

.method public getAcceptedIssuers()[Ljava/security/cert/X509Certificate;
    const/4 v0, 0x0
    new-array v0, v0, [Ljava/security/cert/X509Certificate;
    return-object v0
.end method
```
### 1c. New class — `smali/com/nivaroid/topfollow/helper/SSLBypass$HV.smali`
```smali
.class public Lcom/nivaroid/topfollow/helper/SSLBypass$HV;
.super Ljava/lang/Object;
.implements Ljavax/net/ssl/HostnameVerifier;

.method public constructor <init>()V
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public verify(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z
    const/4 v0, 0x1
    return v0
.end method
```
### 1d. Injection — `smali/okhttp3/OkHttpClient$Builder.smali`, method `build()`
Insert **immediately after** the `.method public build()Lokhttp3/OkHttpClient;` line
(before the first original instruction of the body):
```smali
    invoke-static {p0}, Lcom/nivaroid/topfollow/helper/SSLBypass;->apply(Lokhttp3/OkHttpClient$Builder;)Lokhttp3/OkHttpClient$Builder;
    move-result-object p0
```
That's the entire dex-side patch: 3 new smali files + 2 injected lines.
Why it's complete: all 5 client constructions go through `build()` (proven by census),
so IG×4 and C2 all get the trust-all factory. No pinning/verifier/proxy code exists
anywhere else to bypass (tables in §0).

### Option A (alternative, no dex rebuild): network-security-config resource patch
Add `res/xml/network_security_config.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```
and add `android:networkSecurityConfig="@xml/network_security_config"` to `<application>` in
AndroidManifest.xml. This requires binary AXML/resource surgery (string pool + new entry)
— more fiddly than Option B; keep as fallback. Option B is code-only and covers all clients.

## 2. Full build recipe (non-rooted HTTPCanary capture, everything visible)

1. Take `v846_new.apk`.
2. Replace `lib/arm64-v8a/libtopfollow.so` with **`libtopfollow_patched.so`** (12-patch set, `work/v846/apkx/lib/arm64-v8a/libtopfollow_patched.so`, sha256 `5d98fc76…`).
3. Apply the **SSLBypass smali patch** (§1) via apktool (or ApkPatcher smali hook): decompile → add 3 files + 2 lines → rebuild.
4. Resign (apksigner). Pin-blob rewrite step stays in the pipeline (defense-in-depth; the pin verdict channel is already code-dead via patch #9).
5. Install. **Clear app data first** (forces a fresh C2 `topfollow_check` + license flow — otherwise cached state may skip the C2 round during your capture session).
6. Start HTTPCanary (system proxy) → open app → C2 (`nivafollower-app.com/api-v3/*`) **and** IG (`i.instagram.com`, `b.i.instagram.com`) should both appear, decrypted.
7. C2 also fires per-ViewModel (`Ly9/d;`, `Lca/e;` `onReady`) — opening the main screens triggers it; IG fires per action (like/comment/media).

## 3. Explicit non-goals (do NOT waste time on these)
- "Native SSL bypass": does not exist (no TLS in native). The 12 .so patches kill the *detection* blockers (incl. APK-SHA), which is what was silently killing the C2 path.
- "VPN detection bypass": no such check exists in native or Java (verified twice, corrected scanner).
- "CertificatePinner removal": no pinner is configured anywhere.
