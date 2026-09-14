'use strict';
/* ============================================================================
 * 10_java_crypto_layer.js
 * ----------------------------------------------------------------------------
 * Hooks the ONLY real cryptography in this app.
 *
 * A full sweep of all 4,146 DEX classes (work/out/all) found exactly two sites
 * that perform encryption or signing. Everything else is hashing. This script
 * instruments both, plus the hashing, plus the transport of the results.
 *
 * SITE 1 -- q8.t1.f(String plaintext, String pubKeyB64, String keyId)
 *     Instagram's own password-encryption protocol, version 4:
 *
 *         SecureRandom -> aesKey[32]            (AES-256)
 *         SecureRandom -> iv[12]                (GCM, 96-bit nonce)
 *         ts = System.currentTimeMillis()/1000
 *         pubKey = X509EncodedKeySpec(Base64.decode(pubKeyB64))
 *         Cipher("RSA/ECB/PKCS1PADDING").init(ENCRYPT, pubKey)
 *         encKey = cipher.doFinal(aesKey)                    <- RSA-wrapped key
 *         Cipher("AES/GCM/NoPadding").init(ENCRYPT,
 *                 SecretKeySpec(aesKey,"AES"), GCMParameterSpec(128, iv))
 *         cipher.updateAAD(ts.getBytes())                    <- ts is bound
 *         ct = cipher.doFinal(plaintext.getBytes())          <- ct||tag
 *         blob = 0x01 || keyId || iv[12] || u16le(encKey.len)
 *                || encKey || tag[16] || ciphertext
 *         return "#PWD_INSTAGRAM:4:" + ts + ":" + Base64(blob)
 *
 *     Where pubKey comes from (ia.m.java:215-218):
 *         Ig-Set-Password-Encryption-Key-Id   response header -> keyId
 *         Ig-Set-Password-Encryption-Pub-Key  response header -> pubKey
 *     i.e. Instagram's server supplies the RSA key at runtime. It is NOT
 *     embedded in the APK and NOT in .rodata -- verified by scanning all three
 *     ABIs for RSA SPKI/modulus DER prefixes and PEM headers: none present.
 *
 *     Called from ia.v.java:259:
 *         params.put("password", q8.t1.f(acct.getPassword(),
 *                                        info.getPub_key(), info.getKey_id()))
 *
 * SITE 2 -- com.nivaroid.topfollow.helper.T
 *     AndroidKeyStore-backed ECDSA device attestation, alias "top_key_4286":
 *       o(String) -> Base64( sig + "#" + Base64(pubkey) + "#" + [certChain] )
 *       sd(String) -> Base64( SHA256withECDSA signature )
 *
 *     NOTE (finding CRED-11): libtopfollow.so calls
 *         GetStaticMethodID(helper/T, "digest", "([B)[B")
 *     at arm64 VA 0x106660 and 0x162c4c -- but helper.T declares ONLY o() and
 *     sd(). There is no digest(byte[]) method anywhere in the DEX, and no
 *     method with descriptor ([B)[B in any com.nivaroid.topfollow class.
 *     That lookup returns NULL and raises NoSuchMethodError. This script hooks
 *     it so the failure is observable, and confirms no byte[]->byte[] crypto
 *     bridge exists between native and Java.
 *
 * Usage:
 *   frida -U -f com.nivaroid.topfollow -l 00_common.js -l 01_anti_tamper_killer.js \
 *         -l 02_ssl_pinning_bypass.js -l 10_java_crypto_layer.js
 * ============================================================================ */

Java.perform(function () {
    function L(tag) {
        var s = '[JCRYPTO] ' + tag + ' ';
        for (var i = 1; i < arguments.length; i++) s += arguments[i] + ' ';
        console.log(s);
    }
    function hex(bytes) {
        if (bytes === null || bytes === undefined) return 'null';
        var u = new Uint8Array(bytes);
        var out = '';
        for (var i = 0; i < u.length; i++) out += ('0' + u[i].toString(16)).slice(-2);
        return out;
    }
    function preview(bytes, n) {
        var h = hex(bytes);
        return h.length > n * 2 ? h.substring(0, n * 2) + '...(' + (h.length / 2) + 'B)' : h;
    }
    function stack() {
        try {
            return Java.use('android.util.Log')
                .getStackTraceString(Java.use('java.lang.Throwable').$new())
                .split('\n').slice(1, 9).join('\n      ');
        } catch (e) { return '<no stack>'; }
    }

    /* ------------------------------------------------------------ SITE 1 -- */
    /* Hook q8.t1.f -- the Instagram password encryptor. The class is
     * obfuscated to q8.t1; resolve defensively in case the mapping shifts. */
    var hooked = false;
    ['q8.t1', 'q8.T1'].forEach(function (cn) {
        if (hooked) return;
        try {
            var C = Java.use(cn);
            C.f.overload('java.lang.String', 'java.lang.String', 'java.lang.String')
                .implementation = function (plaintext, pubKeyB64, keyId) {
                L('=== q8.t1.f  INSTAGRAM PASSWORD ENCRYPTION ===');
                L('  plaintext (THE INSTAGRAM PASSWORD):', JSON.stringify(plaintext));
                L('  plaintext length :', plaintext === null ? 'null' : plaintext.length);
                L('  keyId            :', keyId);
                L('  pubKey b64 len   :', pubKeyB64 === null ? 'null' : pubKeyB64.length);
                L('  pubKey b64       :', pubKeyB64 === null ? 'null' :
                    (pubKeyB64.length > 96 ? pubKeyB64.substring(0, 96) + '...' : pubKeyB64));
                /* decode the RSA public key so its modulus size is visible */
                try {
                    var B64 = Java.use('android.util.Base64');
                    var raw = B64.decode(pubKeyB64.replace(/-(.*)-|\n/g, ''), 2);
                    L('  pubKey DER bytes :', raw.length, '(=> ~' + ((raw.length - 30) * 8) + '-bit RSA)');
                    L('  pubKey DER hex   :', preview(raw, 48));
                } catch (e) { L('  pubKey decode err:', '' + e); }
                L('  caller stack:\n      ' + stack());

                var out = this.f(plaintext, pubKeyB64, keyId);

                L('  RESULT:', out === null ? 'null' :
                    (out.length > 120 ? out.substring(0, 120) + '...(' + out.length + ' chars)' : out));
                /* dissect the #PWD_INSTAGRAM:4:<ts>:<b64> envelope */
                if (out && out.indexOf('#PWD_INSTAGRAM:4:') === 0) {
                    var p = out.split(':');
                    L('  envelope version :', p[1]);
                    L('  envelope ts      :', p[2], '(bound as GCM AAD)');
                    try {
                        var B64b = Java.use('android.util.Base64');
                        var blob = B64b.decode(p[3], 2);
                        var u = new Uint8Array(blob);
                        var ver = u[0];
                        var kid = u[1];
                        var iv = blob.slice ? blob.slice(2, 14) : null;
                        var ivHex = '';
                        for (var i = 2; i < 14 && i < u.length; i++) ivHex += ('0' + u[i].toString(16)).slice(-2);
                        var kl = u[14] | (u[15] << 8);
                        var encKeyHex = '';
                        for (var j = 16; j < 16 + kl && j < u.length; j++) encKeyHex += ('0' + u[j].toString(16)).slice(-2);
                        var tagHex = '';
                        for (var k = 16 + kl; k < 16 + kl + 16 && k < u.length; k++) tagHex += ('0' + u[k].toString(16)).slice(-2);
                        L('  blob total len   :', u.length);
                        L('  blob version byte:', ver);
                        L('  blob keyId byte  :', kid);
                        L('  blob GCM IV (12) :', ivHex);
                        L('  blob encKey len  :', kl, '(u16le)');
                        L('  blob encKey(RSA) :', encKeyHex.length > 128 ? encKeyHex.substring(0, 128) + '...' : encKeyHex);
                        L('  blob GCM tag(16) :', tagHex);
                        L('  blob ciphertext  :', u.length - 16 - kl - 16, 'bytes');
                        L('  => AES-256-GCM, 96-bit nonce, 128-bit tag, ts as AAD.');
                        L('  => The AES key is RSA-wrapped, so the blob is NOT');
                        L('     decryptable without Instagram\'s private key.');
                    } catch (e2) { L('  blob parse err   :', '' + e2); }
                } else {
                    L('  RESULT did not use the #PWD_INSTAGRAM:4 envelope -- encryption FAILED (returns "")');
                }
                return out;
            };
            L('hooked ' + cn + '.f (Instagram password encryptor)');
            hooked = true;
        } catch (e) { /* class not present under this name */ }
    });
    if (!hooked) L('!! could not locate q8.t1.f -- enumerate classes to find the new name');

    /* Hook the raw javax.crypto layer so ANY cipher use is visible, including
     * anything the static sweep could not attribute. */
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function (tf) {
            L('Cipher.getInstance("' + tf + '")');
            L('  caller:\n      ' + stack());
            return this.getInstance(tf);
        };
        var initOV = Cipher.init.overloads;
        initOV.forEach(function (ov) {
            ov.implementation = function () {
                var desc = [];
                for (var i = 0; i < arguments.length; i++) desc.push('' + arguments[i]);
                L('Cipher.init(' + desc.join(', ') + ')  [opmode ' + (arguments[0] === 1 ? 'ENCRYPT' : 'DECRYPT') + ']');
                /* if a SecretKeySpec was passed, dump the raw key bytes */
                for (var j = 0; j < arguments.length; j++) {
                    var a = arguments[j];
                    if (a === null || a === undefined) continue;
                    try {
                        var cn = a.getClass ? a.getClass().getName() : '';
                        if (cn === 'javax.crypto.spec.SecretKeySpec') {
                            L('  !! RAW SYMMETRIC KEY = ' + hex(a.getEncoded()) +
                              '  (' + a.getEncoded().length * 8 + '-bit, alg ' + a.getAlgorithm() + ')');
                        } else if (cn === 'javax.crypto.spec.GCMParameterSpec') {
                            L('  GCM spec: tLen=' + a.getTLen() + ' iv=' + hex(a.getIV()));
                        } else if (cn === 'javax.crypto.spec.IvParameterSpec') {
                            L('  IV = ' + hex(a.getIV()));
                        } else if (cn === 'java.security.spec.X509EncodedKeySpec' ||
                                   cn === 'java.security.spec.RSAPublicKeySpec') {
                            try { L('  pubkey spec = ' + preview(a.getEncoded(), 64)); } catch (e) {}
                        }
                    } catch (e) {}
                }
                return ov.apply(this, arguments);
            };
        });
        L('hooked javax.crypto.Cipher.getInstance + all init() overloads');
    } catch (e) { L('Cipher hook failed: ' + e); }

    /* updateAAD -- proves the timestamp binding */
    try {
        var Cipher2 = Java.use('javax.crypto.Cipher');
        Cipher2.updateAAD.overload('[B').implementation = function (aad) {
            L('Cipher.updateAAD(' + new Java.use('java.lang.String')(aad) + ')');
            return this.updateAAD(aad);
        };
        L('hooked Cipher.updateAAD');
    } catch (e) {}

    /* ------------------------------------------------------------ SITE 2 -- */
    try {
        var T = Java.use('com.nivaroid.topfollow.helper.T');
        T.o.overload('java.lang.String').implementation = function (s) {
            L('helper.T.o("' + (s === null ? 'null' : s.substring(0, Math.min(80, s.length))) + '")');
            var r = this.o(s);
            L('  -> ' + (r === null ? 'null' : (r.length > 100 ? r.substring(0, 100) + '...(' + r.length + ')' : r)));
            if (r && r !== 'null') {
                try {
                    var dec = new Java.use('java.lang.String')(Java.use('android.util.Base64').decode(r, 2));
                    var parts = dec.split('#');
                    L('  attestation parts: sig=' + parts[0].length + 'B  pubkey=' +
                      (parts[1] ? parts[1].length : 0) + 'B  certchain=' + (parts[2] ? parts[2].length : 0) + 'B');
                } catch (e) {}
            }
            return r;
        };
        T.sd.overload('java.lang.String').implementation = function (s) {
            L('helper.T.sd("' + (s === null ? 'null' : s.substring(0, Math.min(80, s.length))) + '")');
            var r = this.sd(s);
            L('  -> ECDSA sig ' + (r === null ? 'null' : r.length + ' b64 chars'));
            return r;
        };
        L('hooked helper.T.o / helper.T.sd (AndroidKeyStore ECDSA, alias top_key_4286)');

        /* CRED-11: prove the native digest() lookup has no target */
        var names = T.class.getDeclaredMethods().map(function (m) { return m.getName(); });
        L('helper.T declared methods = [' + names.join(', ') + ']');
        L('  -> native libtopfollow.so calls GetStaticMethodID(helper/T,"digest","([B)[B")');
        L('  -> "digest" present? ' + (names.indexOf('digest') >= 0 ? 'YES' :
            'NO  == the lookup returns NULL / NoSuchMethodError (dead JNI bridge)'));
    } catch (e) { L('helper.T hook failed: ' + e); }

    /* AndroidKeyStore itself -- key generation and any attestation challenge */
    try {
        var KS = Java.use('java.security.KeyStore');
        KS.getInstance.overload('java.lang.String').implementation = function (t) {
            L('KeyStore.getInstance("' + t + '")');
            return this.getInstance(t);
        };
        KS.getCertificate.overload('java.lang.String').implementation = function (a) {
            L('KeyStore.getCertificate("' + a + '")');
            return this.getCertificate(a);
        };
        var KPG = Java.use('java.security.KeyPairGenerator');
        KPG.getInstance.overload('java.lang.String').implementation = function (a) {
            L('KeyPairGenerator.getInstance("' + a + '")');
            L('  caller:\n      ' + stack());
            return this.getInstance(a);
        };
        L('hooked KeyStore + KeyPairGenerator');
    } catch (e) {}

    /* ------------------------------------------------------- hashing layer -- */
    try {
        var MD = Java.use('java.security.MessageDigest');
        MD.getInstance.overload('java.lang.String').implementation = function (alg) {
            L('MessageDigest.getInstance("' + alg + '")');
            return this.getInstance(alg);
        };
        MD.digest.overload('[B').implementation = function (inp) {
            var out = this.digest(inp);
            L('MessageDigest.digest(' + preview(inp, 24) + ') -> ' + hex(out));
            return out;
        };
        L('hooked MessageDigest (SHA-1/SHA-256/MD5 sites: d8.f, j8.b, n8.g, k9.c, j9.c, h8.t, ea.e, d3.c)');
    } catch (e) { L('MessageDigest hook failed: ' + e); }

    /* ------------------------------------- transport of the encrypted body -- */
    /* Show where the #PWD_INSTAGRAM blob ends up, and every header on the
     * request that carries it. */
    try {
        var RB = Java.use('okhttp3.RequestBody');
        var Buffer = Java.use('okio.Buffer');
        var MultipartBody = Java.use('okhttp3.MultipartBody');
        var FormBody = Java.use('okhttp3.FormBody');
        FormBody.prototype = FormBody.prototype;
        var FB = Java.use('okhttp3.FormBody');
        FB.writeTo.implementation = function (sink) {
            this.writeTo(sink);
            try {
                var buf = Buffer.$new();
                this.writeTo(buf);
                var s = buf.readUtf8();
                if (s.indexOf('password') >= 0 || s.indexOf('PWD_INSTAGRAM') >= 0) {
                    L('!!! FormBody carrying the password field:');
                    L('    ' + (s.length > 400 ? s.substring(0, 400) + '...' : s));
                }
            } catch (e) {}
        };
        L('hooked okhttp3.FormBody.writeTo (password transport)');
    } catch (e) { L('FormBody hook failed: ' + e); }

    L('=== java crypto layer instrumented ===');
    L('Now: open the Instagram login screen and submit credentials.');
    L('Every AES-256-GCM key, IV, tag, RSA-wrapped key and the plaintext');
    L('password itself will be printed as they are used.');
});
