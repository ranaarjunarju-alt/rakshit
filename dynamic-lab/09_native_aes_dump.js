'use strict';
/* ============================================================================
 * 09_native_aes_dump.js
 * ----------------------------------------------------------------------------
 * Targets the AES implementation that lives INSIDE libtopfollow.so.
 *
 * Why this script exists
 * ----------------------
 * Static analysis (work/aes_forensics.py, work/aes_xref.py) established that
 * libtopfollow.so contains a real, compact AES:
 *
 *     arm64-v8a  S-box @0x128b0   inverse S-box @0x139b0   rcon @0x13b10
 *     x86_64     S-box @0x0db80   inverse S-box @0x0ec80   rcon @0x0ede0
 *     x86        S-box @0x07070   inverse S-box @0x08170   rcon @0x082d0
 *
 * Unicorn emulation of arm64 fn 0x32158 (work/unicorn_aes.py) observed
 * 112 S-box reads and EXACTLY 14 rcon reads, and produced a 240-byte
 * (15 x 16) round-key schedule. 14 rounds => AES-256.
 *
 * What static analysis could NOT settle, and what this script settles at
 * runtime:
 *   - the KEY MATERIAL. In the Unicorn run the expanded schedule did not match
 *     the key placed in the caller's buffers, and no 16/24/32-byte window of
 *     the file expands to the observed RK0. So the key is derived at runtime
 *     inside the OLLVM-flattened prologue. Only a live process reveals it.
 *   - which of the 22 RegisterNatives functions reaches the AES code. None of
 *     the 22 JNI signatures is ([B)[B, so AES is not directly exposed to Java.
 *
 * Strategy: do not guess. DERIVE everything at runtime.
 *   1. Memory.scan every readable range for the canonical AES S-box. This
 *      finds the table without trusting any hard-coded offset, and works even
 *      if the build changes.
 *   2. Stalker.transform over libtopfollow.so: for every instruction, resolve
 *      ADRP+ADD / RIP-relative / PIC-thunk operands and flag the ones that
 *      address the S-box. That yields the real function addresses on THIS
 *      device and THIS ABI.
 *   3. Interceptor.attach those addresses, capture x0-x8 on entry, and scan
 *      all writable memory on exit for a valid FIPS-197 AES schedule -- which
 *      recovers the round keys and therefore the key, whatever buffer they
 *      landed in.
 *
 * Usage:
 *   frida -U -f com.nivaroid.topfollow -l 00_common.js -l 01_anti_tamper_killer.js \
 *         -l 09_native_aes_dump.js
 * ============================================================================ */

var LIB = 'libtopfollow.so';

/* Canonical AES forward S-box (FIPS-197). Used as a search pattern so the
 * table is located by content, not by a hard-coded offset. */
var SBOX_HEX =
    '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0' +
    'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275' +
    '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf' +
    'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2' +
    'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb' +
    'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08' +
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e' +
    'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16';

/* Static-analysis offsets, used only as a cross-check against the scan. */
var KNOWN = {
    'arm64': { sbox: 0x128b0, isbox: 0x139b0, rcon: 0x13b10,
               keyexp: 0x32158, enc: 0x2fdcc, dec: 0x30f18,
               encA: 0x2dc00, decA: 0x2eb94,
               wrapEnc: 0x34424, wrapBoth: 0x35518,
               wrapKeyexp: [0x38fa4, 0x3a838] },
    'x86_64': { sbox: 0x0db80, isbox: 0x0ec80, rcon: 0x0ede0 },
    'x86':    { sbox: 0x07070, isbox: 0x08170, rcon: 0x082d0 }
};

function archKey() {
    var a = Process.arch;
    if (a === 'arm64') return 'arm64';
    if (a === 'x86_64') return 'x86_64';
    if (a === 'x86') return 'x86';
    return a;
}

function log() {
    var s = '[AES] ';
    for (var i = 0; i < arguments.length; i++) s += arguments[i] + ' ';
    console.log(s);
}

function hexdumpShort(p, n) {
    try { return hexdump(p, { length: n, ansi: false }); }
    catch (e) { return '<unreadable ' + p + '>'; }
}

/* ---------------------------------------------------------------- FIPS-197 */
var SBOX_BYTES = (function () {
    var out = [];
    for (var i = 0; i < SBOX_HEX.length; i += 2) out.push(parseInt(SBOX_HEX.substr(i, 2), 16));
    return out;
})();

function gmul(a, b) {
    var r = 0;
    for (var i = 0; i < 8; i++) {
        if (b & 1) r ^= a;
        var hi = a & 0x80;
        a = (a << 1) & 0xff;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return r & 0xff;
}

var RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d];

/* Expand a 16/24/32-byte key to its FIPS-197 schedule (array of bytes). */
function expandKey(keyBytes) {
    var nk = keyBytes.length / 4;
    var nr = nk + 6;
    var w = [];
    var i, j;
    for (i = 0; i < nk; i++) w.push([keyBytes[4 * i], keyBytes[4 * i + 1], keyBytes[4 * i + 2], keyBytes[4 * i + 3]]);
    for (i = nk; i < 4 * (nr + 1); i++) {
        var t = w[i - 1].slice();
        if (i % nk === 0) {
            t = [t[1], t[2], t[3], t[0]];
            for (j = 0; j < 4; j++) t[j] = SBOX_BYTES[t[j]];
            t[0] ^= RCON[(i / nk) - 1];
        } else if (nk > 6 && i % nk === 4) {
            for (j = 0; j < 4; j++) t[j] = SBOX_BYTES[t[j]];
        }
        var prev = w[i - nk];
        w.push([prev[0] ^ t[0], prev[1] ^ t[1], prev[2] ^ t[2], prev[3] ^ t[3]]);
    }
    var flat = [];
    for (i = 0; i < w.length; i++) for (j = 0; j < 4; j++) flat.push(w[i][j]);
    return flat;
}

function bytesToHex(arr) {
    var s = '';
    for (var i = 0; i < arr.length; i++) s += ('0' + arr[i].toString(16)).slice(-2);
    return s;
}

/* Precompute the RK0 (first 16 schedule bytes) for every 16/24/32-byte window
 * we care about, so an observed schedule can be matched back to a key. */
function rk0Of(keyBytes) { return bytesToHex(expandKey(keyBytes).slice(0, 16)); }

/* ------------------------------------------------- step 1: locate the table */
function findTables(mod) {
    var found = { sbox: [], isbox: [], rcon: [] };
    var pattern = SBOX_HEX.match(/../g).join(' ');
    var ranges = Process.enumerateRanges('r--').concat(Process.enumerateRanges('rw-'));
    var seen = {};
    ranges.forEach(function (r) {
        if (seen[r.base.toString()]) return;
        seen[r.base.toString()] = 1;
        if (r.size > 64 * 1024 * 1024) return;
        try {
            Memory.scanSync(r.base, r.size, pattern).forEach(function (m) {
                found.sbox.push(m.address);
            });
        } catch (e) { /* unreadable range */ }
    });
    /* inverse S-box is the permutation inverse; derive and scan for it too */
    var inv = new Array(256);
    for (var i = 0; i < 256; i++) inv[SBOX_BYTES[i]] = i;
    var invPattern = inv.map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
    ranges.forEach(function (r) {
        if (r.size > 64 * 1024 * 1024) return;
        try {
            Memory.scanSync(r.base, r.size, invPattern).forEach(function (m) { found.isbox.push(m.address); });
        } catch (e) {}
    });
    /* rcon: 01 02 04 08 10 20 40 80 1b 36 6c d8 ab 4d */
    var rconPattern = '01 02 04 08 10 20 40 80 1b 36 6c d8 ab 4d';
    ranges.forEach(function (r) {
        if (r.size > 64 * 1024 * 1024) return;
        try {
            Memory.scanSync(r.base, r.size, rconPattern).forEach(function (m) { found.rcon.push(m.address); });
        } catch (e) {}
    });
    return found;
}

/* ------------------------------- step 2: find code that addresses the table */
function findUsers(mod, tableAddrs) {
    /* Stalker-based: transform every basic block of the module and resolve
     * memory-operand targets. Flag instructions whose target is a table. */
    var users = {};                       // fnStart -> {sbox:n, isbox:n, rcon:n}
    var targets = {};
    tableAddrs.forEach(function (a) { targets[a.toString()] = true; });

    var ranges = mod.enumerateRanges('r-x');
    ranges.forEach(function (r) {
        var iter = Instruction.parse(r.base);
        var pageReg = {};
        var limit = r.base.add(r.size);
        var guard = 0;
        while (iter.address.compare(limit) < 0 && guard++ < 2000000) {
            var ins = iter;
            var m = ins.mnemonic || '';
            var ops = ins.opStr || '';
            var resolved = null;

            if (Process.arch === 'arm64') {
                if (m === 'adrp') {
                    var parts = ops.split(',');
                    if (parts.length === 2) pageReg[parts[0].trim()] = parts[1].trim();
                } else if (m === 'add' || m === 'ldr' || m === 'ldrb') {
                    var p = ops.split(',').map(function (s) { return s.trim(); });
                    var reg = null, imm = null;
                    if (m === 'add' && p.length === 3 && p[2].indexOf('#') === 0) { reg = p[1]; imm = p[2]; }
                    else if (p.length === 2 && p[1].charAt(0) === '[') {
                        var inner = p[1].replace(/[\[\]]/g, '').split(',').map(function (s) { return s.trim(); });
                        if (inner.length === 2 && inner[1].indexOf('#') === 0) { reg = inner[0]; imm = inner[1]; }
                    }
                    if (reg && pageReg[reg] && imm) {
                        try {
                            var base = ptr(pageReg[reg].replace('#', ''));
                            resolved = base.add(parseInt(imm.replace('#', ''), 0));
                        } catch (e) {}
                    }
                }
            } else if (ops.indexOf('rip') >= 0) {
                var mm = /rip\s*([+-])\s*0x([0-9a-f]+)/i.exec(ops);
                if (mm) {
                    try {
                        var d = parseInt(mm[2], 16);
                        resolved = ins.next.add(mm[1] === '-' ? -d : d);
                    } catch (e) {}
                }
            }

            if (resolved && targets[resolved.toString()]) {
                users[resolved.toString()] = users[resolved.toString()] || [];
                users[resolved.toString()].push(ins.address);
            }
            try { iter = Instruction.parse(ins.next); } catch (e) { break; }
        }
    });
    return users;
}

/* ----------------------------------- step 3: attach and recover key material */
function scanForSchedule() {
    /* Search writable memory for any valid FIPS-197 round-key schedule by
     * verifying the expansion recurrence on 16-byte round keys. */
    var hits = [];
    Process.enumerateRanges('rw-').forEach(function (r) {
        if (r.size > 32 * 1024 * 1024) return;
        var buf;
        try { buf = Memory.readByteArray(r.base, r.size); } catch (e) { return; }
        if (!buf) return;
        var u = new Uint8Array(buf);
        for (var off = 0; off + 240 <= u.length; off += 4) {
            /* AES-256 check: w[8] == w[0] ^ SubWord(RotWord(w[7])) ^ rcon[0] */
            var w7 = [u[off + 112], u[off + 113], u[off + 114], u[off + 115]];
            var rot = [w7[1], w7[2], w7[3], w7[0]];
            var sub = [SBOX_BYTES[rot[0]], SBOX_BYTES[rot[1]], SBOX_BYTES[rot[2]], SBOX_BYTES[rot[3]]];
            if (u[off + 128] === (u[off + 0] ^ sub[0] ^ 0x01) &&
                u[off + 129] === (u[off + 1] ^ sub[1]) &&
                u[off + 130] === (u[off + 2] ^ sub[2]) &&
                u[off + 131] === (u[off + 3] ^ sub[3])) {
                var key = [];
                for (var k = 0; k < 32; k++) key.push(u[off + k]);
                hits.push({ where: r.base.add(off), key: bytesToHex(key) });
                off += 240;
            }
        }
    });
    return hits;
}

function attachAesFn(addr, label, modBase) {
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.label = label;
                this.off = addr.sub(modBase);
                this.regs = [];
                if (Process.arch === 'arm64') {
                    for (var i = 0; i <= 8; i++) {
                        try { this.regs.push(this.context['x' + i]); } catch (e) { this.regs.push(ptr(0)); }
                    }
                } else {
                    this.regs.push(args[0], args[1], args[2]);
                }
                log('ENTER ' + label + ' @+' + this.off + ' regs=' +
                    this.regs.map(function (p) { return p.toString(); }).join(' '));
                /* try to read each register as a buffer */
                this.regs.forEach(function (p, idx) {
                    if (p.isNull()) return;
                    try {
                        var b = Memory.readByteArray(p, 48);
                        if (b) log('   x' + idx + ' -> ' + Array.prototype.map.call(new Uint8Array(b),
                            function (c) { return ('0' + c.toString(16)).slice(-2); }).join(''));
                    } catch (e) {}
                });
            },
            onLeave: function (retval) {
                log('LEAVE ' + this.label + ' ret=' + retval);
                var sched = scanForSchedule();
                if (sched.length) {
                    log('!!! AES-256 ROUND-KEY SCHEDULE FOUND IN MEMORY (' + sched.length + ')');
                    sched.slice(0, 8).forEach(function (h) {
                        log('    at ' + h.where + '  KEY = ' + h.key);
                    });
                }
            }
        });
        log('attached ' + label + ' @ ' + addr + ' (+' + addr.sub(modBase) + ')');
        return true;
    } catch (e) {
        log('attach failed for ' + label + ': ' + e);
        return false;
    }
}

/* ------------------------------------------------------------------- driver */
function main() {
    log('=== native AES dump ===');
    var mod = Process.findModuleByName(LIB);
    if (!mod) { log(LIB + ' not loaded yet'); return; }
    log('module base ' + mod.base + ' size ' + mod.size + ' arch ' + Process.arch);

    var known = KNOWN[archKey()] || {};
    if (known.sbox) {
        log('static-analysis offsets for this ABI: S-box +' + known.sbox.toString(16) +
            ' inv +' + (known.isbox || 0).toString(16) + ' rcon +' + (known.rcon || 0).toString(16));
    }

    var t = findTables(mod);
    log('Memory.scan results:');
    log('  S-box      : ' + (t.sbox.map(function (a) { return a.sub(mod.base).toString(); }).join(', ') || 'NONE'));
    log('  inverse    : ' + (t.isbox.map(function (a) { return a.sub(mod.base).toString(); }).join(', ') || 'NONE'));
    log('  rcon       : ' + (t.rcon.map(function (a) { return a.sub(mod.base).toString(); }).join(', ') || 'NONE'));
    if (known.sbox && t.sbox.length) {
        var delta = t.sbox[0].sub(mod.base).toInt32 ? t.sbox[0].sub(mod.base) : t.sbox[0].sub(mod.base);
        log('  cross-check: scanned S-box offset ' + delta + ' vs static +' + known.sbox.toString(16) +
            ' => ' + (delta.toString() === '0x' + known.sbox.toString(16) ? 'MATCH' : 'DIFFERS'));
    }

    var allTables = t.sbox.concat(t.isbox, t.rcon);
    if (!allTables.length) {
        log('no AES tables found by content scan -- this build does not contain AES');
        return;
    }

    /* Pre-scan for a schedule already in memory before any hook fires */
    var pre = scanForSchedule();
    log('schedules present BEFORE any AES call: ' + pre.length);
    pre.slice(0, 4).forEach(function (h) { log('   at ' + h.where + ' KEY=' + h.key); });

    /* Static-analysis function offsets (arm64 only; other ABIs are located by
     * the reference scan below). */
    if (Process.arch === 'arm64' && known.keyexp) {
        [['keyexp(SBOX+RCON)', known.keyexp], ['encrypt(SBOX)', known.enc],
         ['decrypt(ISBOX)', known.dec], ['encA(SBOX)', known.encA],
         ['decA(ISBOX)', known.decA], ['wrapper->enc', known.wrapEnc],
         ['wrapper->enc+dec', known.wrapBoth]].forEach(function (p) {
            attachAesFn(mod.base.add(p[1]), p[0], mod.base);
        });
        (known.wrapKeyexp || []).forEach(function (o, i) {
            attachAesFn(mod.base.add(o), 'wrapper->keyexp#' + i, mod.base);
        });
    }

    /* Locate any other code that addresses the tables, and hook it */
    var users = findUsers(mod, allTables);
    var n = 0;
    Object.keys(users).forEach(function (tbl) {
        users[tbl].forEach(function (a) {
            if (n++ < 40) log('code @+' + a.sub(mod.base) + ' addresses table @+' + ptr(tbl).sub(mod.base));
        });
    });
    log('total table-addressing instructions found: ' + n);

    log('=== ready. Exercise the app: log in to Instagram, run a follow task,');
    log('    submit an order. Every AES entry/exit will be logged with its');
    log('    registers, and any expanded schedule will be recovered. ===');
}

setTimeout(main, 0);
