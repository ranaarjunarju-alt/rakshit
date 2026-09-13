/* ============================================================================
 * 02 - SSL / CERTIFICATE PINNING BYYPASS  (+ MITM traffic unlock)
 * ----------------------------------------------------------------------------
 * How TopFollow pins (all recovered statically):
 *   * libtopfollow.so imports NO crypto/TLS symbols at all -> the pinner is
 *     built in NATIVE code but via JNI against Java OkHttp. That means the pin
 *     lives in java-land and is trivially hookable.
 *   * Backend Retrofit is built by native helper.q.k(String pin, boolean pinActive)
 *     (== libtopfollow.so!x00126f7c).  The pin string comes from
 *     SharedPreferences "Pin"/"PinActive" and is SERVER-ROTATABLE via
 *     ServerCheckModel { pin, pin_active, repair_mode, update_available,
 *     update_url, url } fetched at bootstrap by com.bumptech.glide.manager.r.
 *   * IG Retrofits (3 of them: private / graphql / web) are built by native
 *     helper.q.l(int) (== libtopfollow.so!x0018d3f7) which also calls
 *     CertificatePinner$Builder.add(...).
 *   * Hardcoded pin literals observed in .rodata (XOR 0x55 / triple-base64):
 *        sha256/d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e
 *        sha256/3bbeeba8e-beaa-4458-ac60-6d9a61b2be9e (UUID-form literal)
 *     NOTE d845591e... == SHA-256 of the APK *signing* certificate, i.e. the same
 *     constant doubles as the tamper check value and as a pinned "identity".
 *   * ha.h / glide.d.t() also performs post-hoc verification of the response
 *     (helper.q.e checks getHost()/getPath()), and the manifest declares NO
 *     networkSecurityConfig, so Java hooks are the only barrier.
 *
 * Usage: frida -U -f com.nivaroid.topfollow -l 00_common.js -l 02_ssl_pinning_bypass.js
 *        then point the device at Burp/mitmproxy with a user-installed CA.
 * ==========================================================================*/
'use strict';
const H = (typeof module !== 'undefined' && module.exports) ? module.exports : H;

function hex(bytes) { let s = ''; for (let i = 0; i < bytes.length; i++) s += ('0' + (bytes[i] & 0xff).toString(16)).slice(-2); return s; }

Java.perform(function () {

  /* ---- 1. OkHttp3 CertificatePinner: neutralise check() and log pins ---- */
  const CP = 'okhttp3.CertificatePinner';
  H.cls(CP, function (Pinner) {
    Pinner.check.overloads.forEach(function (ov) {
      ov.implementation = function () {
        const host = arguments[0];
        H.log('pin', 'CertificatePinner.check("' + host + '") -> BYPASSED');
        return;                       // throw nothing == pin accepted
      };
    });
    if (Pinner.check$okhttp) {
      Pinner.check$okhttp.overloads.forEach(function (ov) {
        ov.implementation = function () { H.log('pin', 'check$okhttp -> BYPASSED'); return; };
      });
    }
  });
  H.cls('okhttp3.CertificatePinner$Builder', function (B) {
    B.add.implementation = function (pattern, pins) {
      H.log('pin', 'CertificatePinner.Builder.add("' + pattern + '", ' + pins + ')  <-- captured pin');
      return this.add(pattern, pins); // keep behaviour, we already killed check()
    };
  });

  /* ---- 2. TrustManager: install an accept-all X509TrustManager ---- */
  const X509 = Java.use('javax.net.ssl.X509TrustManager');
  const SSLCTX = Java.use('javax.net.ssl.SSLContext');
  const TrustAll = Java.registerClass({
    name: 'dev.topfollow.trustall',
    implements: [X509],
    methods: {
      checkClientTrusted: function (chain, authType) { H.log('tls', 'checkClientTrusted(' + (chain ? chain.length : 0) + ') accepted'); },
      checkServerTrusted: function (chain, authType) {
        if (chain && chain.length) {
          try {
            const md = Java.use('java.security.MessageDigest').getInstance('SHA-256');
            H.log('tls', 'server cert[0] SHA-256 = ' + hex(md.digest(chain[0].getEncoded())) +
                        '  subject=' + chain[0].getSubjectX500Principal().getName() +
                        '  issuer=' + chain[0].getIssuerX500Principal().getName());
          } catch (e) {}
        }
        H.log('tls', 'checkServerTrusted -> ACCEPTED (MITM CA trusted)');
      },
      getAcceptedIssuers: function () { return []; }
    }
  });
  const trustAll = TrustAll.$new();
  const ctx = SSLCTX.getInstance('TLS');
  ctx.init(null, [trustAll], null);
  const defSSLSocketFactory = ctx.getSocketFactory();

  const SSLSocketFactory = Java.use('javax.net.ssl.HttpsURLConnection');
  try { SSLSocketFactory.setDefaultSSLSocketFactory.call(SSLSocketFactory, defSSLSocketFactory); } catch (e) {}

  // Force OkHttp clients built at runtime to use our factory + trust-all
  ['okhttp3.OkHttpClient', 'okhttp3.OkHttpClient$Builder'].forEach(function (c) {
    H.cls(c, function (K) {
      if (K.sslSocketFactory) {
        K.sslSocketFactory.overloads.forEach(function (ov) {
          ov.implementation = function () {
            H.log('tls', c + '.sslSocketFactory(...) -> replaced with trust-all');
            if (ov.argumentTypes.length === 2) return ov.call(this, defSSLSocketFactory, trustAll);
            return ov.call(this, defSSLSocketFactory);
          };
        });
      }
      if (K.certificatePinner) {
        K.certificatePitter = null;
        K.certificatePinner.overloads.forEach(function (ov) {
          ov.implementation = function (p) { H.log('pin', c + '.certificatePinner(...) -> NULL pinner installed'); return ov.call(this, p); };
        });
      }
      if (K.hostnameVerifier) {
        K.hostnameVerifier.overloads.forEach(function (ov) {
          ov.implementation = function () { H.log('tls', 'hostnameVerifier -> accept-all');
            return ov.call(this, Java.registerClass({ name: 'dev.topfollow.hv', implements: [Java.use('javax.net.ssl.HostnameVerifier')],
              methods: { verify: function (h, s) { H.log('tls', 'HostnameVerifier.verify("' + h + '") -> true'); return true; } } }).$new()); };
        });
      }
    });
  });

  /* ---- 3. javax.net.ssl.HttpsURLConnection default hostname verifier ---- */
  const HV = Java.use('javax.net.ssl.HttpsURLConnection');
  HV.setDefaultHostnameVerifier(Java.registerClass({
    name: 'dev.topfollow.hv2', implements: [Java.use('javax.net.ssl.HostnameVerifier')],
    methods: { verify: function (h, s) { return true; } }
  }).$new());

  /* ---- 4. Android WebView: allow the MITM cert + log mixed content ---- */
  const WVC = Java.use('android.webkit.WebViewClient');
  WVC.onReceivedSslError.implementation = function (view, handler, error) {
    H.log('webview', 'onReceivedSslError -> handler.proceed() (' + error + ')');
    handler.proceed();
  };

  /* ---- 5. Conscrypt / platform TLS (native) - hook SSL_verify_cert_chain ---- */
  ['SSL_verify_cert_chain', 'SSL_CTX_set_custom_verify', 'SSL_set_custom_verify'].forEach(function (sym) {
    const p = Module.findExportByName(null, sym);
    if (p) Interceptor.replace(p, new NativeCallback(function () { return 1; }, 'int',
      sym === 'SSL_verify_cert_chain' ? ['pointer', 'pointer', 'int'] : ['pointer', 'int', 'pointer']));
    if (p) H.log('tls', sym + ' -> forced OK');
  });

  /* ---- 6. Reveal the pin at rest: decode SharedPreferences "Pin"/"PinActive" ---- */
  try {
    const ActivityThread = Java.use('android.app.ActivityThread');
    const ctxApp = ActivityThread.currentApplication().getApplicationContext();
    const sp = ctxApp.getSharedPreferences('TOPFVC_Shared', 0);
    const rawPin = sp.getString('Pin', '');
    const active = sp.getBoolean('PinActive', false);
    H.log('pin@rest', 'SharedPreferences "Pin" (stored, ciphered) = ' + rawPin);
    H.log('pin@rest', 'SharedPreferences "PinActive" = ' + active);
    if (rawPin) {
      H.cls('com.bumptech.glide.d', function (D) {
        try { H.log('pin@rest', 'd.p(Pin) -> ' + D.p(rawPin)); }
        catch (e) { H.log('pin@rest', 'd.p(Pin) failed (native q.n not ready yet): ' + e); }
      });
    }
  } catch (e) { H.log('pin@rest', 'context not ready: ' + e); }

  /* ---- 7. ServerCheck bootstrap: log/replace the server-rotated URL + pin ---- */
  H.cls('models.ServerCheckModel', function (M) {
    ['getUrl', 'getPin', 'getPin_active', 'getRepair_mode', 'getUpdate_available', 'getUpdate_url'].forEach(function (g) {
      if (M[g]) M[g].implementation = function () { const v = this[g](); H.log('servercheck', g + '() = ' + v); return v; };
    });
  });
  H.cls('com.bumptech.glide.manager.r', function (R) {
    H.log('servercheck', 'com.bumptech.glide.manager.r (ServerCheck bootstrap) loaded - watch for pin rotation');
  });
});

H.hr('SSL pinning bypass ARMED');
