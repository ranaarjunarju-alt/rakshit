/* ============================================================================
 * 07 - libtopfollow.so NATIVE / JNI INSTRUMENTATION & DUMPER
 * ----------------------------------------------------------------------------
 * libtopfollow.so (arm64-v8a / x86_64 / x86) exports exactly ONE symbol:
 *     JNI_OnLoad
 * Everything else is reached through RegisterNatives, so nothing is visible in
 * .dynsym.  22 methods of com.nivaroid.topfollow.helper.q are registered:
 *
 *   q.a(String)                    -> x0014b4f3   IG-response transform  (x5)
 *   q.b()                          -> x0012f5b7   backend User-Agent
 *   q.c(String)                    -> x00105e9b   captcha_stamp (hCaptcha token signer)
 *   q.d()                          -> x0016d3b9   ServerCheck endpoint path
 *   q.e()                          -> x0014e2e9   response host/path verifier
 *   q.f()                          -> x0010e27f   reCAPTCHA site-key
 *   q.g()                          -> x00113f7a   hCaptcha site-key
 *   q.h(Order)                     -> x0011f1a2   Instagram `signed_body`
 *   q.i(JsonObject,String)         -> x00120b1e   integrity/device-info injector
 *   q.j()                          -> x0011a4c2   timestamp (long)
 *   q.k(String,boolean)            -> x00126f7c   BACKEND Retrofit builder (pins!)
 *   q.l(int)                       -> x0018d3f7   BOOTSTRAP MEGA-FUNCTION:
 *                                      * 3x IG Retrofit builder
 *                                      * APK signature SHA-256 self-check
 *                                      * /proc/self/maps anti-Frida/Xposed/Riru/Zygisk scan
 *                                      * root-binary existence checks
 *                                      * DeviceModel{coin,gem,hash_type,hash_key,nonce,
 *                                                  token,fcm_token} population
 *                                      * CertificatePinner$Builder.add(...)
 *   q.m()                          -> x0011f42b   vip_stamp
 *   q.n(String)                    -> x0011e28b   cipher stage-1 (used by glide.d.p)
 *   q.o(String)                    -> x0012d3e0   cipher stage-1 (used by glide.d.q)
 *   q.p(Response,Order,Account)    -> x0015e49c   claim body part
 *   q.q(Response)                  -> x0014c1f9   claim body x7
 *   q.r(JsonObject,String,String)  -> x0015b1e9   instagramLogin.php body builder
 *   q.s(String,String,String)      -> x0017b62c   set_order_stamp (submitOrder.php)
 *   q.t(JsonObject,Account,Order)  -> x0015a3b7   syncOrder.php body builder
 *   q.u(JsonObject,Account,String) -> x00135e2a   account/DeviceId injector
 *   q.v(JsonObject)                -> x0012e5a1   device-info injector
 *
 * All 22 functions are OLLVM control-flow-flattened (state dispatcher), so
 * static CFG recovery is impractical; this script instruments them dynamically
 * and additionally resolves the XOR-obfuscated string tables:
 *   XOR key 0x55 -> backend URL / IG URLs / UUID / misc
 *   XOR key 0x5A -> anti-Frida keywords, root paths, /proc/self/maps
 *   triple-base64 -> https://b.i.instagram.com/api/v1/ , https://i.instagram.com/api/v2/ ,
 *                    create_note/v2/ , seen/ , /save/ , sha256/<pin>
 *
 * Usage: frida -U -f com.nivaroid.topfollow -l 00_common.js -l 07_native_jni_dumper.js
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
const SONAME = 'libtopfollow.so';

/* ---------- A. Capture the RegisterNatives table (live addresses) ---------- */
H.captureRegisterNatives(function (tbl) {
  H.hr('libtopfollow.so RegisterNatives table (' + Object.keys(tbl).length + ' entries)');
  const mod = Process.findModuleByName(SONAME);
  if (mod) H.log('so', SONAME + ' base=' + mod.base + ' size=' + mod.size + ' path=' + mod.path);
  Object.keys(tbl).forEach(function (k) {
    const e = tbl[k];
    console.log('  ' + k.padEnd(56) + e.sig.padEnd(46) + e.module + '!0x' + e.offset.toString(16));
  });
  instrument(tbl);
});

function instrument(tbl) {
  Object.keys(tbl).forEach(function (k) {
    const e = tbl[k];
    if (e.module !== SONAME) return;
    try {
      Interceptor.attach(e.fn, {
        onEnter: function (a) {
          this.t = Date.now();
          const env = Java.vm.getEnv();
          const parts = [];
          // a[0]=JNIEnv*, a[1]=jclass/jobject, a[2..]=real args
          for (let i = 2; i < 6; i++) {
            try {
              if (a[i].isNull()) { parts.push('arg' + (i - 2) + '=NULL'); continue; }
              let v = null;
              try { if (env.isInstanceOf(a[i], Java.use('java.lang.String').class)) v = env.stringFromJni(a[i]); } catch (_) {}
              parts.push('arg' + (i - 2) + '=' + (v !== null ? '"' + String(v).slice(0, 200) + '"' : a[i]));
            } catch (_) { break; }
          }
          H.log('native', '>> ' + k + '(' + parts.join(', ') + ')');
        },
        onLeave: function (r) {
          let v = r;
          try {
            const env = Java.vm.getEnv();
            if (!r.isNull()) {
              try { v = '"' + env.stringFromJni(r) + '"'; } catch (_) { v = r; }
            }
          } catch (_) {}
          H.log('native', '<< ' + k + ' = ' + String(v).slice(0, 400) + '   (' + (Date.now() - this.t) + ' ms)');
        }
      });
      H.log('hook', 'instrumented ' + k + ' @ ' + e.module + '!0x' + e.offset.toString(16));
    } catch (err) { H.log('!', 'cannot instrument ' + k + ': ' + err); }
  });
}

/* ---------- B. Decode the obfuscated .rodata string tables in memory ---------- */
function xorDecode(buf, len, key) {
  const out = [];
  for (let i = 0; i < len; i++) { const c = buf.add(i).readU8() ^ key; if (c === 0) break; out.push(c); }
  return String.fromCharCode.apply(null, out);
}
function dumpRodata() {
  const mod = Process.findModuleByName(SONAME);
  if (!mod) { H.log('!', SONAME + ' not loaded'); return; }
  const ranges = mod.enumerateRanges('r--').concat(mod.enumerateRanges('r-x'));
  H.hr(SONAME + ' XOR-obfuscated string recovery (keys 0x55 / 0x5A) + triple-base64');
  const seen = {};
  ranges.forEach(function (rg) {
    Memory.scanSync(rg.base, rg.size, '00').forEach(function () {});
    // walk printable runs, try both keys
    const size = rg.size;
    for (let off = 0; off + 4 < size; off++) {
      const p = rg.base.add(off);
      let b; try { b = p.readU8(); } catch (_) { break; }
      if (b < 0x20 || b > 0x7e) continue;
      [0x55, 0x5A, 0x6C].forEach(function (key) {
        const dec = xorDecode(p, 160, key);
        if (dec.length < 6) return;
        if (!/^[ -~]+$/.test(dec)) return;
        if (!/(http|\.php|instagram|frida|su$|xposed|zygisk|riru|substrate|maps|sha256|\/api\/|note|seen|save|Superuser|gum-js|gadget)/i.test(dec)) return;
        const k = key + '|' + dec;
        if (seen[k]) return; seen[k] = 1;
        console.log('  [xor 0x' + key.toString(16) + '] +0x' + off.toString(16) + '  ' + dec.slice(0, 120));
      });
    }
  });
  H.log('rodata', 'decoded ' + Object.keys(seen).length + ' unique obfuscated strings');
}

/* ---------- C. Triple-base64 literals (IG endpoints) ---------- */
function b64d(s) { try { return Java.use('android.util.Base64').decode(s, 2); } catch (e) { return null; } }
function dumpTripleB64() {
  Java.perform(function () {
    const mod = Process.findModuleByName(SONAME);
    if (!mod) return;
    const B64 = Java.use('android.util.Base64');
    const re = /^[A-Za-z0-9+/=]{12,}$/;
    H.hr('triple-base64 literals found in ' + SONAME + ' .rodata');
    const found = {};
    mod.enumerateRanges('r--').forEach(function (rg) {
      let cur = '';
      for (let off = 0; off < rg.size; off++) {
        let c; try { c = rg.base.add(off).readU8(); } catch (_) { break; }
        const ch = (c >= 0x20 && c <= 0x7e) ? String.fromCharCode(c) : '\n';
        if (/[A-Za-z0-9+/=]/.test(ch)) { cur += ch; continue; }
        if (cur.length >= 16 && re.test(cur)) {
          try {
            let s = cur;
            for (let k = 0; k < 3; k++) {
              const d = B64.decode(s, 2);
              const t = Java.use('java.lang.String').$new(d, Java.use('java.nio.charset.StandardCharsets').UTF_8).toString();
              if (!t || t === s) break;
              s = t;
              if (/^https?:\/\/|^[a-z_]+\/v[0-9]|^\/?[a-z_]+\/$/i.test(s)) {
                if (!found[s]) { found[s] = 1; console.log('  b64x' + (k + 1) + '  ' + cur.slice(0, 46) + '...  ->  ' + s); }
              }
            }
          } catch (e) {}
        }
        cur = '';
      }
    });
  });
}

/* ---------- D. Watch the anti-tamper primitives from inside the .so ---------- */
['fopen', 'open', '__system_property_get', 'popen', 'system', 'dlopen', 'dlsym'].forEach(function (fn) {
  const p = Module.findExportByName(null, fn);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (a) {
      this.fn = fn;
      try { this.a0 = a[0].isNull() ? null : a[0].readCString(); } catch (_) { this.a0 = null; }
    },
    onLeave: function (r) {
      const caller = this.returnAddress;
      const m = Process.findModuleByAddress(caller);
      if (m && m.name === SONAME) {
        H.log('so-call', SONAME + '!0x' + caller.sub(m.base).toString(16) + ' -> ' + this.fn + '("' + this.a0 + '") = ' + r);
      }
    }
  });
});

/* ---------- E. JNI reflection calls made from native (signature self-check) ---------- */
Java.perform(function () {
  const env = Java.vm.getEnv();
  ['java.security.MessageDigest', 'android.content.pm.PackageManager', 'android.os.Build',
   'android.provider.Settings$Secure', 'java.io.File'].forEach(function (cn) {
    H.cls(cn, function (K) {
      K.class.getDeclaredMethods().forEach(function (m) {
        const n = m.getName();
        if (!/getInstance|digest|getPackageInfo|getPackageName|getString|exists|getSystemService|getInstalledPackages/i.test(n)) return;
        try {
          K[n].overloads.forEach(function (ov) {
            ov.implementation = function () {
              const callerIsNative = (function () {
                const t = Java.use('java.lang.Thread').currentThread().getStackTrace();
                for (let i = 0; i < t.length; i++) if (String(t[i].getClassName()).indexOf('helper.q') !== -1) return true;
                return false;
              })();
              if (callerIsNative) {
                const args = Array.prototype.slice.call(arguments).map(function (a) { try { return String(a).slice(0, 60); } catch (e) { return '?'; } });
                const r = ov.apply(this, arguments);
                let rs = ''; try { rs = (n === 'digest') ? Array.prototype.map.call(r, function (b) { return ('0' + (b & 0xff).toString(16)).slice(-2); }).join('') : String(r).slice(0, 120); } catch (e) {}
                H.log('jni', cn + '.' + n + '(' + args.join(', ') + ') called from NATIVE -> ' + rs);
                return r;
              }
              return ov.apply(this, arguments);
            };
          });
        } catch (e) {}
      });
    });
  });
  setTimeout(function () { dumpRodata(); dumpTripleB64(); }, 4000);
});

rpc.exports = { dump: function () { dumpRodata(); dumpTripleB64(); }, natives: function () { return H.natives; } };
H.hr('native/JNI dumper ARMED');
