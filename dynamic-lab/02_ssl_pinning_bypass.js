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

/* ===========================================================================
 * SELF-ARMING DETECTION BYPASS (mandatory baseline - built into every script)
 * ---------------------------------------------------------------------------
 * TopFollow detects hooks at startup unless the anti-tamper killer is active:
 *   - maps scanner reads /proc/self/maps via __open_2 + read()/__read_chk and
 *     string-matches XOR-0x5A/base64 tokens (frida/xposed/riru/zygisk/substrate)
 *   - 9 su-path probes via access()/open (func#169 @0x13ba30)
 *   - OkHttp CertificatePinner (pin d845591e...6bec5e == signing-cert digest)
 * If 01_anti_tamper_killer.js / 02_ssl_pinning_bypass.js were loaded first they
 * set globalThis.__TF_BYPASS_ARMED and this block is a no-op; otherwise it
 * installs the minimal bypass set so THIS script alone still works on device.
 * =========================================================================*/
(function selfArmBypass() {
  if (globalThis.__TF_BYPASS_ARMED || globalThis.__TF_SELF_ARMED) return;
  globalThis.__TF_SELF_ARMED = true;
  var DENY = ['frida','gum-js','gadget','re.frida','xposed','lsposed','edxposed',
              'riru','zygisk','substrate','libbridge','(deleted)','rwxp','magisk'];
  var ROOT = ['/sbin/su','/system/bin/su','/system/xbin/su','/data/local/xbin/su',
              '/data/local/bin/su','/system/sd/xbin/su','/system/bin/failsafe/su',
              '/data/local/su','superuser.apk'];
  function sus(p) {
    if (!p) return false;
    var l = p.toLowerCase();
    if (l.indexOf('/proc/self/maps') !== -1) return 'maps';
    for (var i = 0; i < ROOT.length; i++) if (l.indexOf(ROOT[i]) !== -1) return 'root';
    return false;
  }
  ['open','open64','fopen','__open_2','openat','access','stat','lstat'].forEach(function (fn) {
    var p = Module.findExportByName(null, fn);
    if (!p) return;
    try {
      Interceptor.attach(p, {
        onEnter: function (a) { try { this.p = a[0].readCString(); } catch (e) { this.p = null; } this.d = sus(this.p); },
        onLeave: function (r) { if (this.d === 'root') r.replace(ptr(-1)); }
      });
    } catch (e) {}
  });
  function scrub(buf, n) {
    if (n <= 0) return n;
    var s; try { s = buf.readUtf8String(n); } catch (e) { return n; }
    if (!s) return n;
    var hit = false, low = s.toLowerCase();
    for (var i = 0; i < DENY.length; i++) if (low.indexOf(DENY[i]) !== -1) { hit = true; break; }
    if (!hit) return n;
    var clean = s.split('\n').filter(function (l) {
      var ll = l.toLowerCase();
      for (var j = 0; j < DENY.length; j++) if (ll.indexOf(DENY[j]) !== -1) return false;
      return true;
    }).join('\n');
    var cb = Memory.allocUtf8String(clean);
    Memory.copy(buf, cb, Math.min(n, clean.length + 1));
    return clean.length;
  }
  var rp = Module.findExportByName('libc.so', 'read');
  if (rp) Interceptor.attach(rp, {
    onEnter: function (a) { this.b = a[1]; },
    onLeave: function (r) { var n = r.toInt32(); if (n > 0) { var m = scrub(this.b, n); if (m !== n) r.replace(m); } }
  });
  var rc = Module.findExportByName('libc.so', '__read_chk');
  if (rc) Interceptor.attach(rc, {
    onEnter: function (a) { this.b = a[1]; },
    onLeave: function (r) { var n = r.toInt32(); if (n > 0) { var m = scrub(this.b, n); if (m !== n) r.replace(m); } }
  });
  ['strstr','strcmp','strncmp'].forEach(function (fn) {
    var p = Module.findExportByName('libc.so', fn);
    if (!p) return;
    try {
      Interceptor.attach(p, {
        onEnter: function (a) {
          this.hit = false;
          try {
            var s1 = a[0].readCString() || '', s2 = a[1].readCString() || '';
            var l = (s1 + '|' + s2).toLowerCase();
            for (var i = 0; i < DENY.length; i++) if (l.indexOf(DENY[i]) !== -1) { this.hit = true; break; }
          } catch (e) {}
        },
        onLeave: function (r) { if (this.hit) r.replace(ptr(0)); }
      });
    } catch (e) {}
  });
  Java.perform(function () {
    try {
      var CP = Java.use('okhttp3.CertificatePinner');
      CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {};
      try { CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function () {}; } catch (e) {}
    } catch (e) {}
    try {
      var SSLContext = Java.use('javax.net.ssl.SSLContext');
      var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
      var EmptyTM = Java.registerClass({
        name: 'com.tf.lab.EmptyTrustManager' + Date.now(),
        implements: [TrustManager],
        methods: {
          checkClientTrusted: function () {},
          checkServerTrusted: function () {},
          getAcceptedIssuers: function () { return []; }
        }
      }).$new();
      var ctx = SSLContext.getInstance('TLS');
      ctx.init(null, [EmptyTM], null);
    } catch (e) {}
  });
  console.log('[bypass] self-arming minimal anti-tamper/SSL bypass installed (load 01+02 for the full set)');
})();

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

globalThis.__TF_BYPASS_ARMED = true;  // full baseline loaded: downstream scripts skip self-arm
