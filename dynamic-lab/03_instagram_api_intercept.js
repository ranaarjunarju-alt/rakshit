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
