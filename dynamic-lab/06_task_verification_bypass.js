/* ============================================================================
 * 06 - FOLLOW-TASK VERIFICATION BYPASS  (fake task completion -> free coins)
 * ----------------------------------------------------------------------------
 * TASK PIPELINE (ja.e = per-account worker, spawned by DoTasksService):
 *
 *  1. ja.e ctor reads the action list:  MyDatabase.setup().n().getActionList()
 *     and SharedPreferences "NewTaskType" (default "all").
 *  2. ja.e.b() dispatches on Order.getType():
 *       0 = FOLLOW    -> ia.g.i(signed_body=q.h(order), url, form{
 *                          include_follow_friction_check=1, user_id=<target pk>,
 *                          radio_type=wifi-none, _uid, device_id=android-<aid>,
 *                          _uuid, nav_chain, container_module=profile })
 *       1 = LIKE      -> ia.g.i(..., form{ delivery_class=organic, tap_source=button,
 *                          media_id, radio_type, _uid, _uuid, nav_chain,
 *                          is_carousel_bumped_post=false, container_module=feed_short_url,
 *                          feed_position=0 } + "&d=0")
 *       3 = REPOST / Threads note -> form{ media_client_position, media_id,
 *                          note_style=13, text=, _uuid, nav_chain, audience=7,
 *                          event_source=ufi, container_module=feed_contextual_profile }
 *       4 = SEEN (story views) -> JSON{ ..., force_seen_story_ids: [] }
 *       5 = COMMENT   -> ia.g.d0(headers + x-ig-nav-chain=...,GVw:comments_v2_feed_timeline:5:button:,
 *                          x-ig-salt-ids=220140399,974460658,
 *                          form{ media_id, comment_session_id=<random UUID>, comment_text })
 *       6 = SAVE      -> /save/ endpoint
 *     EVERY one of these passes q.h(Order) as Instagram's `signed_body`.
 *  3. The IG response comes back; ha.c.onReady(JsonObject) builds the CLAIM:
 *         x4            = order.getOrder_stamp2()
 *         x5            = helper.q.a( gson.toJson(instagramResponse) )   <- native x0014b4f3
 *         x6            = order.getOrder_stamp()
 *         x7            = instagramResponse.getMessage()
 *         type          = order.getOrder_type()
 *         i_type        = order.getType()
 *         order_id      = order.getOrder_id()
 *         order_value   = order.getOrder_value()          <-- CLIENT-SUPPLIED REWARD AMOUNT
 *         pk, username  = target
 *         get_coin      = (instagramResponse.getStatus().equals("ok")) ? "true" : "false"
 *         account_type  = (acct.getAccount_type()=="web") ? "1" : "0"
 *         active_pk, get_new_order, new_order_type, is_single_tasking
 *       -> POST order/syncOrder.php
 *
 *  THE BUG: `get_coin` and `order_value` are CLIENT-ASSERTED.  Nothing binds
 *  them to a server-side re-verification of the Instagram action; the only
 *  "proof" is x5/x7, which are also produced client-side (x5 via a keyless
 *  native transform).  Forcing InstagramResponse.getStatus()=="ok" makes the
 *  worker claim payment for actions that never happened.
 *
 * Usage: frida -U -f com.nivaroid.topfollow -l 00_common.js -l 01_anti_tamper_killer.js \
 *                                        -l 02_ssl_pinning_bypass.js -l 06_task_verification_bypass.js
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

const FAKE_OK       = true;    // force every IG task response to look successful
const INFLATE_VALUE = null;    // e.g. '1000' to rewrite order_value in the claim
function s(x) { try { return x === null || x === undefined ? String(x) : x.toString(); } catch (e) { return '<?>'; } }

Java.perform(function () {

  /* ---- 1. Forge the Instagram action result ---- */
  H.cls('com.nivaroid.topfollow.models.InstagramResponse', function (IR) {
    IR.getStatus.implementation = function () {
      const real = this.getStatus();
      if (FAKE_OK && real !== 'ok') { H.log('VERIFY', 'InstagramResponse.getStatus() "' + real + '" -> "ok"'); return 'ok'; }
      return real;
    };
    IR.setMessage && (IR.setMessage.overloads.forEach(function (ov) {
      ov.implementation = function (m) { H.log('VERIFY', 'InstagramResponse.setMessage(' + s(m).slice(0, 120) + ')'); return ov.call(this, m); };
    }));
    IR.getMessage && (IR.getMessage.implementation = function () { const m = this.getMessage(); H.log('VERIFY', 'InstagramResponse.getMessage() = ' + s(m).slice(0, 160)); return m; });
  });

  /* ---- 2. Log & rewrite the Order that the worker is about to claim ---- */
  H.cls('com.nivaroid.topfollow.models.Order', function (O) {
    ['getOrder_id','getSign','getOrder_stamp','getOrder_stamp2','getOrder_stamp3','getOrder_type',
     'getType','getOrder_value','getMedia_id','getMedia_position','getComment_text','getPk',
     'getUsername','getDelay','getRemains','getFbid_v2'].forEach(function (g) {
      if (!O[g]) return;
      O[g].implementation = function () {
        const v = this[g]();
        H.log('order', g + '() = ' + s(v).slice(0, 140));
        if (INFLATE_VALUE && g === 'getOrder_value') { H.log('order', '  -> REWRITTEN to ' + INFLATE_VALUE); return Java.use('java.lang.String').$new(INFLATE_VALUE); }
        return v;
      };
    });
  });

  /* ---- 3. The claim builder: ha.c.onReady(JsonObject) -> order/syncOrder.php ---- */
  H.cls('ha.c', function (HC) {
    HC.onReady.overloads.forEach(function (ov) {
      ov.implementation = function (json) {
        try {
          if (FAKE_OK && json.has('get_coin')) {
            const was = json.get('get_coin').getAsString();
            json.addProperty('get_coin', 'true');
            H.hr('CLAIM order/syncOrder.php  get_coin ' + was + ' -> true');
          }
          ['x4','x5','x6','x7','type','i_type','order_id','order_value','pk','username',
           'account_type','active_pk','new_order_type','get_new_order','is_single_tasking']
            .forEach(function (k) {
              if (!json.has(k)) return;
              let v = s(json.get(k));
              console.log('   ' + k + ' = ' + (v.length > 200 ? v.slice(0, 200) + '…(' + v.length + ')' : v));
            });
          if (INFLATE_VALUE && json.has('order_value')) { json.addProperty('order_value', INFLATE_VALUE); H.log('CLAIM', 'order_value rewritten -> ' + INFLATE_VALUE); }
        } catch (e) { H.log('claim', e); }
        return ov.call(this, json);
      };
    });
  });

  /* ---- 4. The native per-order Instagram `signed_body` ---- */
  H.cls('com.nivaroid.topfollow.helper.q', function (Q) {
    if (Q.h) Q.h.overloads.forEach(function (ov) {
      ov.implementation = function (order) {
        const sig = ov.call(this, order);
        H.hr('IG signed_body = native q.h(Order)  [libtopfollow.so!x0011f1a2]');
        try {
          console.log('   order_id     = ' + order.getOrder_id());
          console.log('   type         = ' + order.getType() + ' (' + ['follow','like','?','repost/note','seen','comment','save'][order.getType()] + ')');
          console.log('   target       = ' + order.getUsername() + ' (pk=' + order.getPk() + ')');
          console.log('   order_stamp  = ' + s(order.getOrder_stamp()));
          console.log('   order_stamp2 = ' + s(order.getOrder_stamp2()));
          console.log('   sign         = ' + s(order.getSign()));
        } catch (e) {}
        console.log('   => signed_body = ' + s(sig));
        return sig;
      };
    });
    if (Q.a) Q.a.overloads.forEach(function (ov) {
      ov.implementation = function (txt) {
        const r = ov.call(this, txt);
        H.log('native', 'q.a(IG-response-json) [x0014b4f3]  in.len=' + s(txt).length + ' -> x5 len=' + s(r).length);
        H.log('native', '   x5 = ' + s(r).slice(0, 240));
        return r;
      };
    });
  });

  /* ---- 5. The worker dispatch itself ---- */
  H.cls('ja.e', function (W) {
    if (W.b) W.b.overloads.forEach(function (ov) {
      ov.implementation = function () {
        try {
          const o = this.j.value;
          H.hr('TASK DISPATCH ja.e.b()  type=' + (o ? o.getType() : 'null') + '  account=' + (this.i.value ? this.i.value.getUsername() : '?'));
        } catch (e) {}
        return ov.apply(this, arguments);
      };
    });
  });

  /* ---- 6. FriendshipStatus: make the app believe it is already following ---- */
  H.cls('com.nivaroid.topfollow.models.FriendshipStatus', function (FS) {
    ['getFollowing','getFollowed_by','getOutgoing_request','getBlocking','getIs_private','getFollow_key']
      .forEach(function (g) {
        if (!FS[g]) return;
        FS[g].implementation = function () { const v = this[g](); H.log('friendship', g + '() = ' + s(v)); return v; };
      });
  });

  /* ---- 7. DoTasksService counters (Coins / Tasks done notification) ---- */
  H.cls('com.nivaroid.topfollow.application.DoTasksService', function (S) {
    H.log('service', 'DoTasksService.s (coins shown) / .t (tasks done) are static counters');
  });
});

rpc.exports = {
  inflate: function (v) { return 'set INFLATE_VALUE in-script; rpc value=' + v; },
  status:  function () { return { FAKE_OK: FAKE_OK, INFLATE_VALUE: INFLATE_VALUE }; }
};
H.hr('task-verification bypass ARMED (get_coin forced "true")');
