/* ============================================================================
 * 01 - ANTI-TAMPER / ANTI-FRIDA / ANTI-ROOT / SIGNATURE-CHECK KILLER
 * ----------------------------------------------------------------------------
 * Defeats every protection recovered from libtopfollow.so + DEX:
 *
 *  NATIVE (bootstrap mega-fn x0018d3f7 == helper.q.l(int), and friends):
 *    A. /proc/self/maps scan for XOR-0x5A encoded keywords:
 *         /proc/self/maps | xposed | lsposed | edxposed | riru | substrate |
 *         libcso_substrate | libbridge.so | zygisk
 *    B. base64-encoded Frida markers: frida | gum-js-loop | libfrida-gadget |
 *         re.frida.server        (+ TCP 27042/27043 default-port probes)
 *    C. root binary existence checks (XOR-0x5A):
 *         Superuser.apk /sbin/su /system/bin/su /system/xbin/su
 *         /data/local/xbin/su /data/local/bin/su /system/sd/xbin/su
 *         /system/bin/failsafe/su /data/local/su
 *    D. "(deleted)" libart/libc mappings + "rwxp" region checks (injected-code tell)
 *    E. APK signature verification:
 *         PackageManager.getPackageInfo(pkg, GET_SIGNATURES) ->
 *         MessageDigest("SHA-256").digest(sig.toByteArray()) compared against
 *         d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e
 *         (= SHA-256 of the real signing cert: CN=Maryam Ahmadi, O=NivaRoid, IR)
 *    F. emulator / device-prop checks: Build.DEVICE, Build.HARDWARE
 *
 *  JAVA:
 *    G. d8.f.a(Signature[])  - Google "PhoneskyVerificationUtils" gate that must
 *         pass BEFORE Play Integrity is requested (hardcoded Play cert pins).
 *    H. d3.d.l(..) integrity gate: SharedPreferences SND==true && RID==3850153
 *
 * Usage:  frida -U -f com.nivaroid.topfollow -l 00_common.js -l 01_anti_tamper_killer.js
 *         (spawn mode is REQUIRED: the checks run inside JNI_OnLoad/bootstrap)
 * ==========================================================================*/
'use strict';

const H = (typeof module !== 'undefined' && module.exports) ? module.exports : H;
const EXPECTED_CERT_SHA256 =
  'd845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e';

/* ---------- A/B/C/D : filesystem + maps + string-compare neutering -------- */
const MAPS_DENY = ['frida', 'gum-js', 'gadget', 'linjector', 're.frida',
                   'xposed', 'lsposed', 'edxposed', 'riru', 'zygisk',
                   'substrate', 'libbridge', '(deleted)', 'rwxp', 'magisk',
                   'libhook', 'substrate'];
const ROOT_PATHS = ['superuser.apk', '/sbin/su', '/system/bin/su', '/system/xbin/su',
                    '/data/local/xbin/su', '/data/local/bin/su', '/system/sd/xbin/su',
                    '/system/bin/failsafe/su', '/data/local/su', 'supolicy', 'daemonsu',
                    '/system/app/superuser.apk', 'com.noshufou.android.su',
                    'com.thirdparty.superuser', 'eu.chainfire.supersu', 'com.koushikdutta.superuser'];

let blockedOpens = {};
function suspicious(path) {
  if (!path) return false;
  const p = path.toLowerCase();
  if (p.indexOf('/proc/self/maps') !== -1 || p.indexOf('/proc/self/task') !== -1 ||
      p.indexOf('/proc/self/status') !== -1 || p.indexOf('/proc/net/tcp') !== -1) return true;
  for (const r of ROOT_PATHS) if (p.indexOf(r) !== -1) return true;
  return false;
}

['open', 'open64', 'fopen', 'fopen64', '__open_2', 'access', 'stat', 'lstat', 'stat64'].forEach(function (fn) {
  const p = Module.findExportByName(null, fn);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (a) {
      let path = null;
      try { path = a[0].isNull() ? null : a[0].readCString(); } catch (_) {}
      this.path = path; this.deny = suspicious(path);
      if (this.deny) blockedOpens[path] = (blockedOpens[path] || 0) + 1;
    },
    onLeave: function (r) {
      if (!this.deny) return;
      if (this.path && this.path.toLowerCase().indexOf('/proc/self/maps') !== -1) {
        // let it succeed: we sanitise the *contents* on read() instead (see below)
        return;
      }
      // make root-binary / su probes fail with ENOENT
      r.replace(ptr(-1));
      try { Memory.writeS32(Module.findExportByName('libc.so', '__errno') ?
            Module.findExportByName('libc.so', '__errno')().readPointer() : ptr(0), 2); } catch (_) {}
    }
  });
});
H.log('anti-root', 'open/fopen/access/stat hooked (' + Object.keys(blockedOpens).length + ' denials so far)');

/* Sanitise /proc/self/maps + /proc/net/tcp contents byte-stream on read() */
const mapsReads = {};
const readPtr = Module.findExportByName('libc.so', 'read');
const fgetsPtr = Module.findExportByName('libc.so', 'fgets');
function scrub(buf, n) {
  if (n <= 0) return n;
  let s;
  try { s = buf.readUtf8String(n); } catch (_) { try { s = buf.readCString(); } catch (__) { return n; } }
  if (!s) return n;
  const low = s.toLowerCase();
  let hit = false;
  for (const d of MAPS_DENY) if (low.indexOf(d) !== -1) { hit = true; break; }
  if (!hit) return n;
  const clean = s.split('\n').filter(function (line) {
    const l = line.toLowerCase();
    for (const d of MAPS_DENY) if (l.indexOf(d) !== -1) return false;
    return true;
  }).join('\n');
  const cb = Memory.allocUtf8String(clean);
  Memory.copy(buf, cb, Math.min(n, clean.length + 1));
  return clean.length;
}
Interceptor.attach(readPtr, {
  onEnter: function (a) { this.fd = a[0].toInt32(); this.buf = a[1]; },
  onLeave: function (r) { const n = r.toInt32(); if (n > 0) { const m = scrub(this.buf, n); if (m !== n) r.replace(m); } }
});
if (fgetsPtr) Interceptor.attach(fgetsPtr, {
  onEnter: function (a) { this.buf = a[0]; this.n = a[1].toInt32(); },
  onLeave: function (r) { if (!r.isNull()) { const m = scrub(this.buf, this.n); } }
});
H.log('maps', '/proc/self/maps + /proc/net/tcp line-scrubbing installed');

/* strstr/strcmp/strncmp/memmem must never match a detection keyword */
['strstr', 'strcmp', 'strncmp', 'strcasecmp', 'memmem'].forEach(function (fn) {
  const p = Module.findExportByName('libc.so', fn);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (a) {
      this.deny = false;
      try {
        const hay = a[0].isNull() ? '' : a[0].readCString().toLowerCase();
        const nee = a[1].isNull() ? '' : a[1].readCString().toLowerCase();
        for (const d of MAPS_DENY.concat(ROOT_PATHS)) {
          if ((nee && nee.indexOf(d) !== -1) || (fn !== 'strstr' && hay.indexOf(d) !== -1 && nee === d)) {
            this.deny = true; break;
          }
        }
      } catch (_) {}
    },
    onLeave: function (r) { if (this.deny) r.replace(ptr(0)); }
  });
});
H.log('strcmp', 'strstr/strcmp/strncmp/memmem keyword-filtered');

/* B : TCP probe to default Frida ports -> connection refused */
const connectPtr = Module.findExportByName('libc.so', 'connect');
if (connectPtr) Interceptor.attach(connectPtr, {
  onEnter: function (a) {
    this.deny = false;
    try {
      const family = a[1].readU16();
      if (family === 2) { const port = (a[1].add(2).readU8() << 8) | a[1].add(3).readU8();
        if (port === 27042 || port === 27043 || port === 27044) { this.deny = true; H.log('frida-port', 'blocked connect to :' + port); } }
    } catch (_) {}
  },
  onLeave: function (r) { if (this.deny) r.replace(ptr(-1)); }
});

/* F : emulator / device-prop checks */
Java.perform(function () {
  const Build = Java.use('android.os.Build');
  const fake = { DEVICE: 'hero2lte', HARDWARE: 'exynos9825', MODEL: 'SM-E625F',
                 BRAND: 'samsung', MANUFACTURER: 'samsung', PRODUCT: 'f62',
                 FINGERPRINT: 'samsung/f62xxx/f62:13/TP1A.220624.014/E625FXXS4CWK1:user/release-keys',
                 TAGS: 'release-keys', BOARD: 'exynos9825', HOST: '21DJ1212C1' };
  Object.keys(fake).forEach(function (k) {
    try { Build[k].value = fake[k]; } catch (_) {}
  });
  Build.VERSION.RELEASE.value = '13';
  H.log('emulator', 'android.os.Build spoofed -> samsung SM-E625F (matches the hardcoded IG User-Agent)');

  // File.exists() for root paths
  const File = Java.use('java.io.File');
  File.exists.implementation = function () {
    const p = this.getAbsolutePath().toLowerCase();
    for (const r of ROOT_PATHS) if (p.indexOf(r) !== -1) { H.log('root', 'File.exists("' + this.getAbsolutePath() + '") -> false'); return false; }
    return this.exists();
  };
  // Runtime.exec("su" / "which su")
  const RT = Java.use('java.lang.Runtime');
  RT.exec.overload('java.lang.String').implementation = function (c) {
    if (c && c.toLowerCase().indexOf('su') !== -1) { H.log('root', 'Runtime.exec("' + c + '") blocked'); throw Java.use('java.io.IOException').$new('permission denied'); }
    return this.exec(c);
  };
});

/* E : APK signature verification -> always report the ORIGINAL cert digest. */
Java.perform(function () {
  // E1. PackageManager.getPackageInfo(..., GET_SIGNATURES/GET_SIGNING_CERTIFICATES)
  const PM = Java.use('android.app.ApplicationPackageManager');
  PM.getPackageInfo.overloads.forEach(function (ov) {
    ov.implementation = function () {
      const r = ov.apply(this, arguments);
      try {
        const flags = (arguments.length > 1) ? arguments[1] : 0;
        const f = (typeof flags === 'number') ? flags : flags.value;
        if ((f & 0x40) || (f & 0x8000000)) {
          H.log('sig', 'getPackageInfo(flags=0x' + (f >>> 0).toString(16) + ') returned real signatures - OK (digest hooked below)');
        }
      } catch (_) {}
      return r;
    };
  });

  // E2. MessageDigest.digest() -> if the result equals nothing meaningful and the
  //     algorithm is SHA-256 while hashing a Signature, force the expected digest.
  const MD = Java.use('java.security.MessageDigest');
  MD.digest.overload().implementation = function () {
    const out = this.digest();
    const algo = this.getAlgorithm();
    if (algo === 'SHA-256' || algo === 'SHA256') {
      let hex = '';
      for (let i = 0; i < out.length; i++) hex += ('0' + (out[i] & 0xff).toString(16)).slice(-2);
      // If the app is hashing its (repackaged) signature, hand back the ORIGINAL one.
      if (hex !== EXPECTED_CERT_SHA256 && H.__sigHashContext) {
        H.log('sig', 'SHA-256 digest ' + hex + ' -> forced to ' + EXPECTED_CERT_SHA256);
        const fake = [];
        for (let i = 0; i < 32; i++) fake.push(parseInt(EXPECTED_CERT_SHA256.substr(i * 2, 2), 16));
        return Java.array('byte', fake);
      }
      H.log('sig', 'SHA-256 digest computed: ' + hex);
    }
    return out;
  };
  // Mark that Signature.toByteArray() was just called => next SHA-256 is the tamper check
  const Sig = Java.use('android.content.pm.Signature');
  Sig.toByteArray.implementation = function () { H.__sigHashContext = true; setTimeout(function () { H.__sigHashContext = false; }, 250); return this.toByteArray(); };

  // E3. Native-side digest: hook libart JNI Call*MethodV is overkill; instead hook
  //     the well-known reflection path used by x0018d3f7 (Class.forName -> getMethod -> invoke)
  const Cls = Java.use('java.lang.Class');
  Cls.forName.overload('java.lang.String').implementation = function (n) {
    if (n === 'java.security.MessageDigest' || n === 'android.content.pm.PackageManager')
      H.log('sig', 'native bootstrap reflectively loaded ' + n);
    return this.forName(n);
  };

  // G. Google Phonesky verification gate (d8.f.a) -> always true
  H.cls('d8.f', function (F) {
    F.a.overload('[Landroid.content.pm.Signature;').implementation = function (s) {
      H.log('phonesky', 'd8.f.a(Signature[' + (s ? s.length : 0) + ']) -> TRUE (Play Integrity gate forced open)');
      return true;
    };
  });

  // Kill-switches: never let the app terminate itself
  ['java.lang.System'].forEach(function (c) {
    const S = Java.use(c);
    S.exit.implementation = function (code) { H.log('kill', 'System.exit(' + code + ') SUPPRESSED'); };
  });
  const Proc = Java.use('android.os.Process');
  Proc.killProcess.implementation = function (pid) { H.log('kill', 'Process.killProcess(' + pid + ') SUPPRESSED'); };
  const RTE = Java.use('java.lang.Runtime');
  RTE.exit.overload('int').implementation = function (c) { H.log('kill', 'Runtime.exit(' + c + ') SUPPRESSED'); };
});

/* H : integrity gate -> force SharedPreferences SND=true, RID=3850153
 *     (set SND=false instead if you want to SKIP Play Integrity entirely) */
const FORCE_INTEGRITY = false;   // true = pass attestation path, false = bypass it
Java.perform(function () {
  const SPI = Java.use('android.app.SharedPreferencesImpl');
  SPI.getBoolean.implementation = function (k, def) {
    const v = this.getBoolean(k, def);
    if (k === 'SND') { H.log('gate', 'SharedPreferences.getBoolean("SND") ' + v + ' -> ' + FORCE_INTEGRITY); return FORCE_INTEGRITY; }
    return v;
  };
  SPI.getInt.implementation = function (k, def) {
    const v = this.getInt(k, def);
    if (k === 'RID') { H.log('gate', 'SharedPreferences.getInt("RID") ' + v + ' -> 3850153'); return 3850153; }
    return v;
  };
});

H.hr('anti-tamper killer ARMED');
console.log('Blocked open()/access() denials will accumulate; check with:');
console.log('   blockedOpens =', JSON.stringify(blockedOpens));

globalThis.__TF_BYPASS_ARMED = true;  // full baseline loaded: downstream scripts skip self-arm
