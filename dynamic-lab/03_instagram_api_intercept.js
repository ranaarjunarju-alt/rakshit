/* ============================================================================
 * 03 - INSTAGRAM PRIVATE-API / GRAPHQL / WEB TRAFFIC INTERCEPTOR
 * ----------------------------------------------------------------------------
 * TopFollow drives Instagram with THREE native-built Retrofit instances
 * (helper.q.l(int) == libtopfollow.so!x0018d3f7):
 *     l(0) -> https://b.i.instagram.com/api/v1/     (private mobile API)
 *     l(1) -> https://i.instagram.com/api/v2/        (private API v2)
 *     l(2) -> https://www.instagram.com/graphql/query (+ https://www.instagram.com/)
 * Service interfaces: ia.g (private), ia.q builds the header map.
 *
 * Header set produced by ia.q.f(long) - all spoofed to look like a real
 * Samsung SM-E625F running Instagram 369.0.0.46.101:
 *     x-bloks-version-id : 083f38c334f42c5e3322bb77464c601e8882cd9ff2d30ac915ba7a497539d604
 *     x-ig-app-id        : 567067343352427
 *     x-ig-capabilities  : 3brTv10=
 *     x-ig-android-id    : android-{Aid}          (Aid from SharedPreferences)
 *     x-pigeon-session-id: UFS-{uuid}-0
 *     authorization      : com.bumptech.glide.d.p(u_a)  <-- DECODED IG BEARER TOKEN
 *     cookie             : mid / ig-u-rur / ig-u-ds-user-id / sessionid
 *     user-agent         : helper.q.b() (native)
 * per-request forged:  x-ig-nav-chain, x-ig-salt-ids (4 sets), x-fb-rmd
 *
 * This script logs EVERY IG request: method, URL, all headers (with the decoded
 * Authorization bearer), and the full request/response bodies.  It also dumps
 * the account credentials pulled from the Room DB for that request.
 *
 * Usage: frida -U -f com.nivaroid.topfollow -l 00_common.js -l 01_anti_tamper_killer.js \
 *                                        -l 02_ssl_pinning_bypass.js -l 03_instagram_api_intercept.js
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

function s(j) { try { return j === null || j === undefined ? String(j) : j.toString(); } catch (e) { return '<' + e + '>'; } }

Java.perform(function () {

  /* ---------- 1. THE universal hook: OkHttp RealCall / Interceptor chain ---- */
  function hookOkHttp() {
    // OkHttp3 Response.body().string() - capture decoded response text
    H.cls('okhttp3.Response', function (Resp) {
      // Response is immutable; hook the Builder instead to see url/code
      H.log('okhttp', 'okhttp3.Response loaded');
    });
    H.cls('okhttp3.Request', function (Req) {
      Req.url.implementation = function () { const u = this.url(); return u; };
    });
    // The reliable place: okhttp3.internal.http.RealInterceptorChain.proceed
    ['okhttp3.internal.http.RealInterceptorChain', 'okhttp3.RealCall', 'okhttp3.internal.connection.RealCall']
      .forEach(function (cn) {
        H.cls(cn, function (C) {
          if (C.proceed) C.proceed.overloads.forEach(function (ov) {
            ov.implementation = function () {
              const req = arguments[0];
              let url = '', method = '', hdrs = {};
              try {
                url = s(req.url()); method = s(req.method());
                const hs = req.headers();
                for (let i = 0; i < hs.size(); i++) hdrs[hs.name(i)] = hs.value(i);
              } catch (e) {}
              if (/instagram\.com|fbcdn|graph\.facebook|nivafollower/.test(url)) {
                H.hr('IG REQUEST ' + method + ' ' + url);
                Object.keys(hdrs).forEach(function (k) {
                  let v = hdrs[k];
                  if (v.length > 240) v = v.slice(0, 240) + '…(' + v.length + ')';
                  console.log('   ' + k + ': ' + v);
                });
                try {
                  const body = req.body();
                  if (body) {
                    const Buf = Java.use('okio.Buffer').$new();
                    body.writeTo(Buf);
                    const txt = Buf.readUtf8();
                    console.log('   --- BODY (' + txt.length + ' bytes) ---');
                    console.log('   ' + txt.replace(/\r?\n/g, '\n   ').slice(0, 4000));
                  }
                } catch (e) { console.log('   <body unreadable: ' + e + '>'); }
              }
              const resp = ov.apply(this, arguments);
              if (/instagram\.com|fbcdn|graph\.facebook|nivafollower/.test(url)) {
                try {
                  console.log('   <<< HTTP ' + resp.code() + ' ' + resp.message());
                  const pk = resp.peekBody(Java.use('java.lang.Long').parseLong('262144'));
                  const t = pk.string();
                  console.log('   --- RESPONSE (' + t.length + ' bytes) ---');
                  console.log('   ' + t.replace(/\r?\n/g, '\n   ').slice(0, 4000));
                } catch (e) { console.log('   <response peek failed: ' + e + '>'); }
              }
              return resp;
            };
          });
        });
      });
  }
  hookOkHttp();

  /* ---------- 2. The header factory: ia.q.f(long) ---------- */
  H.cls('ia.q', function (Q) {
    if (Q.f) Q.f.overloads.forEach(function (ov) {
      ov.implementation = function () {
        const map = ov.apply(this, arguments);
        H.hr('ia.q.f() -> IG HEADER MAP (' + map.size() + ' entries)');
        const it = map.entrySet().iterator();
        while (it.hasNext()) { const e = it.next(); console.log('   ' + e.getKey() + ': ' + e.getValue()); }
        return map;
      };
    });
    if (Q.e) H.log('ia', 'ia.q.e = the IG Retrofit service interface field');
  });

  /* ---------- 3. Authorization header decode: com.bumptech.glide.d.p() ---------- */
  H.cls('com.bumptech.glide.d', function (D) {
    D.p.overloads.forEach(function (ov) {
      ov.implementation = function (ciphered) {
        const plain = ov.apply(this, arguments);
        H.log('crypto', 'd.p( <' + s(ciphered).slice(0, 60) + '...> ) -> "' + s(plain) + '"');
        return plain;
      };
    });
    D.q.overloads.forEach(function (ov) {
      ov.implementation = function (plain) {
        const ciphered = ov.apply(this, arguments);
        H.log('crypto', 'd.q( "' + s(plain).slice(0, 80) + '" ) -> <' + s(ciphered).slice(0, 60) + '...>');
        return ciphered;
      };
    });
    D.t.overloads.forEach(function (ov) {
      ov.implementation = function (acct) {
        const hdrs = ov.apply(this, arguments);
        H.hr('d.t(InstagramAccount) -> TOPFOLLOW BACKEND HEADERS');
        try {
          const it = hdrs.entrySet().iterator();
          while (it.hasNext()) { const e = it.next(); console.log('   ' + e.getKey() + ': ' + e.getValue()); }
        } catch (e) {}
        try {
          if (acct) {
            H.log('cred', '  account.pk        = ' + acct.getPk());
            H.log('cred', '  account.username  = ' + acct.getUsername());
            H.log('cred', '  account.token     = ' + acct.getToken() + '   <-- IG session token leaked to backend');
            H.log('cred', '  account.u_a (ciphered IG bearer) = ' + s(acct.getU_a()).slice(0, 60));
          }
        } catch (e) {}
        return hdrs;
      };
    });
  });

  /* ---------- 4. signed_body + per-order native signature ---------- */
  H.cls('com.nivaroid.topfollow.helper.q', function (Q) {
    const sig = { h: 'q.h(Order) -> IG signed_body', s: 'q.s(u,c,t) -> set_order_stamp',
                  p: 'q.p(Response,Order,Account) -> x5 claim body', q: 'q.q(Response) -> x7',
                  n: 'q.n(String) cipher', o: 'q.o(String) cipher', a: 'q.a(String) response parse',
                  b: 'q.b() -> backend User-Agent', m: 'q.m() -> vip_stamp', j: 'q.j() -> timestamp',
                  c: 'q.c(token) -> captcha_stamp', d: 'q.d() -> servercheck path',
                  f: 'q.f() -> reCAPTCHA sitekey', g: 'q.g() -> hCaptcha sitekey', e: 'q.e()' };
    Object.keys(sig).forEach(function (m) {
      if (!Q[m]) return;
      Q[m].overloads.forEach(function (ov, i) {
        ov.implementation = function () {
          const args = Array.prototype.slice.call(arguments).map(s);
          const r = ov.apply(this, arguments);
          H.log('native', sig[m] + '#' + i + '(' + args.map(function (a) { return a.length > 120 ? a.slice(0, 120) + '…' : a; }).join(', ') + ')\n           => ' + s(r).slice(0, 300));
          return r;
        };
      });
    });
  });

  /* ---------- 5. The follow / like / comment / save / seen action bodies ---------- */
  ['ia.g', 'ia.q', 'ja.e'].forEach(function (c) {
    H.cls(c, function (K) {
      K.class.getDeclaredMethods().forEach(function (m) {
        const n = m.getName();
        if (/^(follow|unfollow|like|unlike|comment|save|unsave|seen|createNote|k0|l0|m0)/i.test(n)) {
          try {
            K[n].overloads.forEach(function (ov) {
              ov.implementation = function () {
                const args = Array.prototype.slice.call(arguments).map(function (a) { const t = s(a); return t.length > 400 ? t.slice(0, 400) + '…' : t; });
                H.hr('IG ACTION  ' + c + '.' + n + '(' + args.length + ' args)');
                args.forEach(function (a, i) { console.log('   arg' + i + ' = ' + a); });
                return ov.apply(this, arguments);
              };
            });
          } catch (e) {}
        }
      });
    });
  });

  /* ---------- 6. Human-behaviour simulator (ia.x) ---------- */
  H.cls('ia.x', function (X) {
    H.log('sim', 'ia.x = pre-action human-simulation burst (typeahead -> profile -> media tab -> inbox -> quick promos, ts -2..-12s, 100-999ms jitter, re-login if last_login>1800s)');
  });
});

H.hr('Instagram API interceptor ARMED');
