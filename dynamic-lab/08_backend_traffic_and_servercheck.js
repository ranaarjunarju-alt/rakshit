/* ============================================================================
 * 08 - TOPFOLLOW BACKEND TRAFFIC + ServerCheck / PIN-ROTATION HIJACK
 * ----------------------------------------------------------------------------
 * BASE URL : https://top.nivafollower.app/v840/
 *            Recovered from libtopfollow.so .rodata as a XOR-0x55 obfuscated
 *            literal.  It is NOT static though: ha.h builds it at runtime via
 *              helper.q.k( com.bumptech.glide.d.p(SP"Pin"), SP"PinActive" )
 *              == libtopfollow.so!x00126f7c  -> OkHttp+CertificatePinner Retrofit
 *            so the vendor can rotate host AND pin remotely.
 *
 * BOOTSTRAP: com.bumptech.glide.manager.r fetches a ServerCheckModel
 *              { url, pin, pin_active, repair_mode, update_available, update_url }
 *            and writes url->SharedPreferences "Pin", pin_active->"PinActive".
 *            => whoever controls that one response controls where the app sends
 *               Instagram passwords, session tokens and coin claims.
 *
 * ALL 26 ENDPOINTS (base64-obfuscated ones marked *):
 *   order/submitOrder.php *          <- place a follower/like/comment order (spend coins)
 *   order/syncOrder.php              <- claim coins for a completed task (get_coin!)
 *   order/getSelfOrders.php          <- my open orders
 *   order/getDefaultComment.php      <- server-supplied comment text
 *   instagramLogin.php *             <- POSTs the IG login body built by native q.r()
 *   getMainInfo.php *                <- app_info: coin_per_* rates, min_*_order, links
 *   account/checkCaptcha.php *       <- captcha_stamp = native q.c(hCaptcha token)
 *   account/getQuestions.php         <- 2FA challenge questions
 *   account/getSecretKey.php         <- TOTP / secret key material
 *   account/requestDigitCode.php     <- digit-code 2FA step
 *   account/upgradeAccountToVip.php  <- vip_stamp = native q.m()
 *   account/getUpgradeStatus.php     account/addCoupon.php   account/getCoupons.php
 *   account/getGiftCodeReward.php    account/checkDailyGift.php
 *   account/getDailyItems.php        account/getInviteData.php
 *   account/setInviteCode.php        account/getLeaderBoard.php
 *   account/getMinerRequests.php     account/changeMinerRequest.php
 *   get_image.php                    pre-login/setUpDevice.php *
 *   pre-login/activeDevice.php *     pre-login/privacyPolicy.php *
 *   (ServerCheck path itself comes from native q.d() == x0016d3b9)
 *
 * HEADERS on every authenticated call (com.bumptech.glide.d.t):
 *   Content-Type: application/json          Version-Name: 8.4.5-Beta
 *   Device-Language: <base64 locale>        Version-Code: 845
 *   Top-Language: <SP Language>             Android-Name: <Build.VERSION.RELEASE>
 *   User-Agent: <native q.b()>              Top-Token: <device.token>
 *   Active-Id:  <InstagramAccount.pk>       Token: <InstagramAccount.token>  <-- IG SESSION
 *
 * Play Integrity (d3.d.l): gated on SP SND==true && RID==3850153; token cached
 *   6h in SP RIT/AIT/RD; nonce = RD + q.j() + "877665803231" (cloud project id);
 *   token is sent as body field `x2` = d.q(d.p(SP"RD")).
 *
 * Usage: frida -U -f com.nivaroid.topfollow -l 00_common.js -l 01_anti_tamper_killer.js \
 *                                        -l 02_ssl_pinning_bypass.js -l 08_backend_traffic_and_servercheck.js
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

/* Set this to redirect the whole app to your own MITM/backend */
const OVERRIDE_BASE_URL = null;   // e.g. 'http://192.168.1.20:8080/v840/'
const OVERRIDE_PIN      = null;   // e.g. 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='

function s(x) { try { return x === null || x === undefined ? String(x) : x.toString(); } catch (e) { return '<?>'; } }

Java.perform(function () {

  /* ---- 1. The native Retrofit builders ---- */
  H.cls('com.nivaroid.topfollow.helper.q', function (Q) {
    if (Q.k) Q.k.overloads.forEach(function (ov) {
      ov.implementation = function (pin, pinActive) {
        H.hr('helper.q.k(pin, pinActive) -> BACKEND Retrofit   [libtopfollow.so!x00126f7c]');
        console.log('   pin (decrypted by caller via d.p(SP"Pin")) = ' + s(pin));
        console.log('   pinActive                                  = ' + s(pinActive));
        if (OVERRIDE_PIN) { H.log('pin', 'overriding pin -> ' + OVERRIDE_PIN); pin = Java.use('java.lang.String').$new(OVERRIDE_PIN); }
        return ov.call(this, pin, pinActive);
      };
    });
    if (Q.l) Q.l.overloads.forEach(function (ov) {
      ov.implementation = function (which) {
        const NAMES = { 0: 'IG PRIVATE  https://b.i.instagram.com/api/v1/',
                        1: 'IG PRIVATE2 https://i.instagram.com/api/v2/',
                        2: 'IG GRAPHQL  https://www.instagram.com/graphql/query' };
        H.hr('helper.q.l(' + which + ') -> ' + (NAMES[which] || '?') + '   [libtopfollow.so!x0018d3f7 BOOTSTRAP]');
        return ov.call(this, which);
      };
    });
    if (Q.d) Q.d.overloads.forEach(function (ov) {
      ov.implementation = function () { const r = ov.apply(this, arguments); H.log('native', 'q.d() -> ServerCheck path = ' + s(r)); return r; };
    });
    if (Q.b) Q.b.overloads.forEach(function (ov) {
      ov.implementation = function () { const r = ov.apply(this, arguments); H.log('native', 'q.b() -> backend User-Agent = ' + s(r)); return r; };
    });
    if (Q.e) Q.e.overloads.forEach(function (ov) {
      ov.implementation = function () { const r = ov.apply(this, arguments); H.log('native', 'q.e() response host/path verifier -> ' + s(r)); return r; };
    });
    ['i', 'u', 'v'].forEach(function (m) {
      if (!Q[m]) return;
      Q[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          const r = ov.apply(this, arguments);
          try { H.log('native', 'q.' + m + '() injected -> ' + s(arguments[0]).slice(0, 900)); } catch (e) {}
          return r;
        };
      });
    });
    if (Q.r) Q.r.overloads.forEach(function (ov) {
      ov.implementation = function (json, ua, deviceId) {
        const r = ov.apply(this, arguments);
        H.hr('helper.q.r(json, userAgent, deviceId) -> instagramLogin.php BODY  [x0015b1e9]');
        console.log('   User-Agent = ' + s(ua));
        console.log('   DeviceId   = ' + s(deviceId));
        try { console.log('   BODY       = ' + s(json)); } catch (e) {}
        return r;
      };
    });
  });

  /* ---- 2. The ServerCheck bootstrap: log + optionally hijack ---- */
  H.cls('models.ServerCheckModel', function (M) {
    ['getUrl', 'getPin', 'getPin_active', 'getRepair_mode', 'getUpdate_available', 'getUpdate_url'].forEach(function (g) {
      if (!M[g]) return;
      M[g].implementation = function () {
        let v = this[g]();
        H.log('servercheck', g + '() = ' + s(v));
        if (OVERRIDE_BASE_URL && g === 'getUrl') { H.log('servercheck', '   -> HIJACKED to ' + OVERRIDE_BASE_URL); return Java.use('java.lang.String').$new(OVERRIDE_BASE_URL); }
        if (OVERRIDE_PIN && g === 'getPin') { H.log('servercheck', '   -> HIJACKED pin'); return Java.use('java.lang.String').$new(OVERRIDE_PIN); }
        return v;
      };
    });
  });
  ['com.bumptech.glide.manager.r', 'ha.h'].forEach(function (c) {
    H.cls(c, function (K) { H.log('backend', c + ' loaded'); });
  });
  /* ha.h builds the base URL from SP "Pin" - log every Retrofit it hands out */
  H.cls('ha.h', function (HH) {
    HH.class.getDeclaredFields().forEach(function (f) {
      if (String(f.getName()) === 'a') H.log('backend', 'ha.h.a = the static backend Retrofit instance');
    });
  });

  /* ---- 3. SharedPreferences writes: catch the pin/url rotation live ---- */
  const SPE = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
  SPE.putString.implementation = function (k, v) {
    if (['Pin', 'PinActive', 'Sign', 'Aid', 'DeviceId', 'RD', 'RID', 'SND', 'AIT', 'RIT'].indexOf(k) !== -1) {
      H.log('prefs', 'putString("' + k + '", "' + s(v).slice(0, 160) + '")');
      if (k === 'Pin') {
        H.cls('com.bumptech.glide.d', function (D) {
          try { H.log('prefs', '   d.p(Pin) -> ' + D.p(v) + '   <== LIVE BACKEND BASE URL'); } catch (e) {}
        });
      }
    }
    return this.putString(k, v);
  };
  SPE.putBoolean.implementation = function (k, v) { if (k === 'PinActive' || k === 'SND') H.log('prefs', 'putBoolean("' + k + '", ' + v + ')'); return this.putBoolean(k, v); };
  SPE.putInt.implementation    = function (k, v) { if (k === 'RID' || k === 'ActiveID') H.log('prefs', 'putInt("' + k + '", ' + v + ')'); return this.putInt(k, v); };

  /* ---- 4. Play Integrity / attestation ---- */
  H.cls('d3.d', function (DD) {
    DD.l.overloads.forEach(function (ov) {
      ov.implementation = function () {
        H.hr('d3.d.l() -> Play Integrity injection for a backend request');
        return ov.apply(this, arguments);
      };
    });
  });
  ['com.google.android.play.core.integrity.IntegrityManager',
   'com.google.android.play.core.integrity.IntegrityManagerFactory'].forEach(function (c) {
    H.cls(c, function (K) { H.log('integrity', c + ' present'); });
  });
  H.cls('java.util.concurrent.atomic.AtomicReference', function () {});

  /* ---- 5. Every backend POST with headers + body ---- */
  H.cls('ha.k', function (K) {
    K.a.overloads.forEach(function (ov) {
      ov.implementation = function (path, headers, body) {
        H.hr('TOPFOLLOW BACKEND  POST ' + s(path));
        try {
          const it = headers.entrySet().iterator();
          while (it.hasNext()) { const e = it.next(); console.log('   H  ' + e.getKey() + ': ' + s(e.getValue()).slice(0, 200)); }
        } catch (e) {}
        try {
          const Buf = Java.use('okio.Buffer').$new();
          body.writeTo(Buf);
          console.log('   BODY ' + Buf.readUtf8().slice(0, 4000));
        } catch (e) {}
        return ov.call(this, path, headers, body);
      };
    });
  });

  /* ---- 6. Responses from the backend (ka.o / ha.f / p9.c handlers) ---- */
  ['ka.o', 'ha.f', 'p9.c', 'ka.i', 'ka.k'].forEach(function (c) {
    H.cls(c, function (K) {
      if (!K.onResponse) return;
      K.onResponse.overloads.forEach(function (ov) {
        ov.implementation = function (call, resp) {
          try {
            H.hr('BACKEND RESPONSE ' + s(call.request().url()) + '  HTTP ' + resp.code());
            const pk = resp.peekBody(Java.use('java.lang.Long').parseLong('262144'));
            console.log('   ' + pk.string().slice(0, 4000));
          } catch (e) {}
          return ov.call(this, call, resp);
        };
      });
    });
  });

  /* ---- 7. FCM push (task push / remote config) ---- */
  H.cls('com.google.firebase.messaging.FirebaseMessagingService', function (F) {
    H.log('fcm', 'FirebaseMessagingService present - push can drive tasks; watch onMessageReceived');
  });
});

rpc.exports = {
  redirect: function (url, pin) { return 'edit OVERRIDE_BASE_URL/OVERRIDE_PIN at the top of this script'; },
  prefs: function () { Java.perform(function () { console.log(JSON.stringify(H.dumpPrefs(H.appContext()), null, 2)); }); }
};
H.hr('backend traffic + ServerCheck hijack ARMED');
