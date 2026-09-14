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
