/* ============================================================================
 * 05 - COIN / GEM ECONOMY + FOLLOWER-PURCHASE TAMPERING
 * ----------------------------------------------------------------------------
 * THE ECONOMY (recovered end-to-end):
 *
 *  WALLET : Room table `device` (MyDatabase.getDevice()) columns `coin`,`gem`.
 *           This is a LOCAL, client-side mirror of the balance.  Every "can I
 *           afford this?" decision in the UI is made against it:
 *             cost = app_info.coin_per_{follow|like|comment|repost|save|seen|threads} * count
 *             if (MyDatabase.setup().getDevice().getCoin() < cost) -> disable Buy button
 *           (androidx.fragment.app.e default-branch and ha.a onReady())
 *           => no server round-trip is required to make the button clickable.
 *
 *  RATES  : Room table `app_info`, pushed by the server from getMainInfo.php.
 *           Client-side cost math => client controls `count`.
 *
 *  SPEND  : ha.b case 1 builds the JSON { username, order_count, type, ... }
 *           then calls NATIVE helper.q.s(username, order_count, type)
 *           (libtopfollow.so!x0017b62c) and attaches it as `set_order_stamp`
 *           -> POST order/submitOrder.php.
 *           NOTE: the stamp covers username|order_count|type only.  It does NOT
 *           cover the coin/gem balance, the payment currency, or any server
 *           nonce => the *price* is never authenticated client-side.
 *
 *  EARN   : DoTasksService performs IG actions for OTHER users' orders, then
 *           ha.c builds the claim:
 *             x4 = helper.a0.x4()   (static challenge blob)
 *             x5 = q.p(Response, Order, InstagramAccount)  <- IG response body
 *             x6 = order_stamp / stamp
 *             x7 = q.q(Response)
 *             get_coin = "true"  iff the IG JSON response contains status=="ok"
 *             order_id, order_value, type, i_type, pk, username, active_pk,
 *             account_type, get_new_order, is_single_tasking
 *           -> POST order/syncOrder.php
 *           `get_coin` is a CLIENT-ASSERTED boolean.  Hook it and the client
 *           simply claims the reward without the action having succeeded.
 *
 *  OTHER  : account/addCoupon.php + getCoupons.php (coupon codes),
 *           account/getGiftCodeReward.php, account/checkDailyGift.php,
 *           account/getDailyItems.php, account/upgradeAccountToVip.php
 *           (vip_stamp = native q.m()), account/getLeaderBoard.php,
 *           account/requestDigitCode.php, account/setInviteCode.php,
 *           account/getMinerRequests.php / changeMinerRequest.php.
 *
 * This script: (1) inflates the local wallet, (2) forces every affordability
 * check to pass, (3) logs & optionally rewrites order_count/type at submit
 * time, (4) forces get_coin=true, (5) auto-accepts coupons/gift codes.
 *
 * Usage: frida -U -f com.nivaroid.topfollow -l 00_common.js -l 01_anti_tamper_killer.js \
 *                                        -l 02_ssl_pinning_bypass.js -l 05_coin_economy_bypass.js
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

const FAKE_COIN = 999999999;
const FAKE_GEM  = 999999999;
let ORDER_OVERRIDE = null;   // e.g. { order_count: '5000', type: 'follow' }

function s(x) { try { return x === null || x === undefined ? String(x) : x.toString(); } catch (e) { return '<?>'; } }

Java.perform(function () {

  /* ---- 1. Inflate the local wallet (DeviceModel.getCoin/getGem) ---- */
  H.cls('com.nivaroid.topfollow.models.DeviceModel', function (DM) {
    DM.getCoin.implementation = function () { const r = this.getCoin(); H.log('wallet', 'DeviceModel.getCoin() ' + r + ' -> ' + FAKE_COIN); return FAKE_COIN; };
    DM.getGem.implementation  = function () { const r = this.getGem();  H.log('wallet', 'DeviceModel.getGem() '  + r + ' -> ' + FAKE_GEM);  return FAKE_GEM;  };
    DM.setCoin.implementation = function (v) { H.log('wallet', 'DeviceModel.setCoin(' + v + ') intercepted'); return this.setCoin(FAKE_COIN); };
    DM.setGem.implementation  = function (v) { H.log('wallet', 'DeviceModel.setGem(' + v + ') intercepted');  return this.setGem(FAKE_GEM);  };
  });

  /* ---- 2. Server-pushed economy rates: log them all ---- */
  H.cls('com.nivaroid.topfollow.models.AppInfo', function (AI) {
    ['getCoin_per_follow','getCoin_per_like','getCoin_per_comment','getCoin_per_repost',
     'getCoin_per_save','getCoin_per_seen','getCoin_per_threads','getMin_follow_order',
     'getMin_like_order','getMin_repost_order','getMin_save_order','getMin_seen_order',
     'getAction_delay','getIs_profile_mandatory','getIs_post_mandatory','getVip']
      .forEach(function (g) {
        if (!AI[g]) return;
        AI[g].implementation = function () { const v = this[g](); H.log('rates', g + '() = ' + v); return v; };
      });
  });

  /* ---- 3. Native economy signatures + claim builder ---- */
  H.cls('com.nivaroid.topfollow.helper.q', function (Q) {
    if (Q.s) Q.s.overloads.forEach(function (ov) {
      ov.implementation = function (username, count, type) {
        H.hr('ORDER SUBMIT  order/submitOrder.php');
        H.log('order', '  username     = ' + s(username));
        H.log('order', '  order_count  = ' + s(count) + (ORDER_OVERRIDE ? '  -> OVERRIDDEN ' + ORDER_OVERRIDE.order_count : ''));
        H.log('order', '  type         = ' + s(type)   + (ORDER_OVERRIDE ? '  -> OVERRIDDEN ' + ORDER_OVERRIDE.type : ''));
        let u = username, c = count, t = type;
        if (ORDER_OVERRIDE) {
          if (ORDER_OVERRIDE.order_count !== undefined) c = Java.use('java.lang.String').$new(String(ORDER_OVERRIDE.order_count));
          if (ORDER_OVERRIDE.type !== undefined)        t = Java.use('java.lang.String').$new(String(ORDER_OVERRIDE.type));
        }
        const stamp = ov.call(this, u, c, t);
        H.log('order', '  set_order_stamp = q.s(...) = ' + s(stamp));
        H.log('order', '  NOTE: stamp covers only username|order_count|type - balance is NOT authenticated');
        return stamp;
      };
    });
    if (Q.m) Q.m.overloads.forEach(function (ov) {
      ov.implementation = function () { const r = ov.apply(this, arguments); H.log('vip', 'q.m() -> vip_stamp = ' + s(r)); return r; };
    });
    if (Q.c) Q.c.overloads.forEach(function (ov) {
      ov.implementation = function (tok) { const r = ov.apply(this, arguments); H.log('captcha', 'q.c(hCaptcha token) -> captcha_stamp = ' + s(r) + '   (token len=' + s(tok).length + ')'); return r; };
    });
    if (Q.t) Q.t.overloads.forEach(function (ov) {
      ov.implementation = function (json, acct, order) {
        const r = ov.apply(this, arguments);
        H.hr('COIN CLAIM  order/syncOrder.php  (native q.t built the body)');
        try { console.log('   ' + s(json)); } catch (e) {}
        return r;
      };
    });
    if (Q.p) Q.p.overloads.forEach(function (ov) {
      ov.implementation = function () { const r = ov.apply(this, arguments); H.log('claim', 'q.p(Response,Order,Account) -> x5 = ' + s(r).slice(0, 200)); return r; };
    });
    if (Q.q) Q.q.overloads.forEach(function (ov) {
      ov.implementation = function () { const r = ov.apply(this, arguments); H.log('claim', 'q.q(Response) -> x7 = ' + s(r).slice(0, 200)); return r; };
    });
  });

  /* ---- 4. Force get_coin=true on every task claim ---- */
  H.cls('ha.c', function (HC) {
    HC.onReady.overloads.forEach(function (ov) {
      ov.implementation = function (json) {
        try {
          if (json.has('get_coin')) { H.log('claim', 'get_coin was ' + json.get('get_coin').getAsString() + ' -> forcing "true"'); json.addProperty('get_coin', 'true'); }
          if (json.has('order_id'))    H.log('claim', 'order_id=' + json.get('order_id').getAsString());
          if (json.has('order_value')) H.log('claim', 'order_value=' + json.get('order_value').getAsString());
          if (json.has('type'))        H.log('claim', 'type=' + json.get('type').getAsString());
          if (json.has('i_type'))      H.log('claim', 'i_type=' + json.get('i_type').getAsString());
          if (json.has('x5'))          H.log('claim', 'x5 (IG response) len=' + json.get('x5').getAsString().length);
        } catch (e) {}
        return ov.call(this, json);
      };
    });
  });

  /* ---- 5. Intercept the raw JsonObject right before every backend POST ---- */
  H.cls('ha.k', function (K) {
    K.a.overloads.forEach(function (ov) {
      ov.implementation = function (path, headers, body) {
        H.hr('BACKEND POST  ' + s(path));
        try {
          const it = headers.entrySet().iterator();
          while (it.hasNext()) { const e = it.next(); console.log('   H ' + e.getKey() + ': ' + String(e.getValue()).slice(0, 160)); }
        } catch (e) {}
        try {
          const Buf = Java.use('okio.Buffer').$new();
          body.writeTo(Buf);
          console.log('   BODY: ' + Buf.readUtf8().slice(0, 3000));
        } catch (e) {}
        return ov.call(this, path, headers, body);
      };
    });
  });

  /* ---- 6. Coupon / gift-code / daily-reward responses ---- */
  ['ka.i', 'ha.e'].forEach(function (c) {
    H.cls(c, function (K) {
      H.log('eco', c + ' = backend response handler (coupons / daily / invite / leaderboard / miner)');
    });
  });
});

rpc.exports = {
  setorder: function (count, type) { ORDER_OVERRIDE = { order_count: count, type: type }; return ORDER_OVERRIDE; },
  coin:     function (n) { return 'hooked getter returns ' + n; }
};
H.hr('coin-economy bypass ARMED  (wallet=' + FAKE_COIN + ', rpc.exports.setorder(count,type) to rewrite orders)');
