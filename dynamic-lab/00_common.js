/* ============================================================================
 * TopFollow (com.nivaroid.topfollow v8.4.5-Beta / versionCode 845)
 * Dynamic-analysis lab - shared helpers
 * ----------------------------------------------------------------------------
 * Target facts used by every script (all recovered by static RE):
 *   package          : com.nivaroid.topfollow
 *   native lib       : libtopfollow.so  (JNI_OnLoad -> RegisterNatives x22,
 *                      all methods of com.nivaroid.topfollow.helper.q)
 *   backend base URL : https://top.nivafollower.app/v840/   (server-rotatable
 *                      via SharedPreferences "Pin"/"PinActive" + ServerCheckModel)
 *   IG private API   : https://b.i.instagram.com/api/v1/ , https://i.instagram.com/api/v2/
 *   IG graphql/web   : https://www.instagram.com/graphql/query , https://www.instagram.com/
 *   self-cert SHA-256: d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e
 *                      (== SHA-256 of the APK signing cert, CN=Maryam Ahmadi/O=NivaRoid)
 *   Room DB          : "t_f_d_b_f_v_c" -> tables device, instagram_accounts, two_factors, app_info
 *   SharedPrefs      : "TOPFVC_Shared"
 * ==========================================================================*/
'use strict';

const PKG   = 'com.nivaroid.topfollow';
const SONAME = 'libtopfollow.so';

const H = {
  log(tag, msg)  { console.log('[' + tag + '] ' + msg); },
  hr(t)          { console.log('\n=== ' + t + ' ' + '='.repeat(Math.max(0, 60 - t.length))); },

  /* Wait for a Java class that may only exist after the app's own bootstrap. */
  cls(name, cb) {
    Java.perform(function () {
      try { cb(Java.use(name)); }
      catch (e) {
        Java.enumerateLoadedClasses({
          onMatch: function (c) { if (c === name) { try { cb(Java.use(name)); } catch (_) {} } },
          onComplete: function () {}
        });
      }
    });
  },

  /* Hook every overload of a Java method and log args + return. */
  traceAll(klass, method, argNames) {
    Java.perform(function () {
      const K = Java.use(klass);
      const overloads = K[method].overloads;
      overloads.forEach(function (ov, idx) {
        ov.implementation = function () {
          const args = Array.prototype.slice.call(arguments);
          let s = klass + '.' + method + '#' + idx + '(';
          s += args.map(function (a, i) {
                 const n = (argNames && argNames[i]) ? argNames[i] : ('a' + i);
                 let v; try { v = (a === null || a === undefined) ? String(a) : a.toString(); }
                          catch (_) { v = '<' + a + '>'; }
                 if (v.length > 400) v = v.slice(0, 400) + '...(' + v.length + ' chars)';
                 return n + '=' + v;
               }).join(', ');
          s += ')';
          const r = ov.apply(this, arguments);
          let rs; try { rs = (r === null || r === undefined) ? String(r) : r.toString(); }
                  catch (_) { rs = '<obj>'; }
          if (rs.length > 600) rs = rs.slice(0, 600) + '...(' + rs.length + ' chars)';
          console.log('  >> ' + s + '\n  << ret=' + rs);
          return r;
        };
      });
      H.log('hook', klass + '.' + method + ' (' + overloads.length + ' overload(s))');
    });
  },

  /* Resolve the runtime address of a native helper.q JNI function.
   * helper.q.xNNNNNNNN are registered via RegisterNatives in JNI_OnLoad, so the
   * symbol is NOT in .dynsym - we intercept RegisterNatives to build the table. */
  natives: {},
  captureRegisterNatives(onReady) {
    const art = Process.findModuleByName('libart.so');
    if (!art) { H.log('!', 'libart.so not loaded yet'); return; }
    const cands = art.enumerateSymbols().filter(function (s) {
      return s.name.indexOf('RegisterNatives') !== -1 && s.name.indexOf('CheckJNI') === -1;
    });
    if (!cands.length) { H.log('!', 'RegisterNatives symbol not found'); return; }
    Interceptor.attach(cands[0].address, {
      onEnter: function (a) {
        const clazz = a[0], methods = a[2], n = a[3].toInt32();
        let cname = '<unknown>';
        try {
          const env = Java.vm.getEnv();
          cname = env.getClassName(clazz);
        } catch (_) {}
        for (let i = 0; i < n; i++) {
          const base = methods.add(i * Process.pointerSize * 3);
          const nameP = base.readPointer(), sigP = base.add(Process.pointerSize).readPointer(),
                fnP = base.add(Process.pointerSize * 2).readPointer();
          const nm = nameP.readCString(), sig = sigP.readCString();
          const mod = Process.findModuleByAddress(fnP);
          const off = mod ? fnP.sub(mod.base) : ptr(0);
          if (cname.indexOf('helper.q') !== -1 || cname.indexOf('topfollow') !== -1) {
            H.natives[cname + '.' + nm] = { fn: fnP, module: mod ? mod.name : '?', offset: off, sig: sig };
            H.log('JNI', cname + '.' + nm + sig + '  ->  ' + (mod ? mod.name : '?') + '!0x' + off.toString(16));
          }
        }
      },
      onLeave: function () { if (onReady) { const f = onReady; onReady = null; f(H.natives); } }
    });
    H.log('hook', 'art::JNI::RegisterNatives intercepted - waiting for JNI_OnLoad');
  },

  /* SharedPreferences("TOPFVC_Shared") dumper. */
  dumpPrefs(ctx) {
    const sp = ctx.getSharedPreferences('TOPFVC_Shared', 0);
    const all = sp.getAll();
    const it = all.entrySet().iterator();
    const out = {};
    while (it.hasNext()) { const e = it.next(); out[e.getKey().toString()] = String(e.getValue()); }
    return out;
  },

  appContext() {
    const ActivityThread = Java.use('android.app.ActivityThread');
    return ActivityThread.currentApplication().getApplicationContext();
  }
};

if (typeof module !== 'undefined') module.exports = H;
