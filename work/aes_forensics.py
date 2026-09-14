"""
AES / white-box forensics for libtopfollow.so.

Triggered by the discovery of a 256-byte blob at file offset 0x128b0 whose first
16 bytes are the AES forward S-box, and a second at 0x139b0 matching the AES
inverse S-box. This script determines, with evidence:

  1. whether those blobs are the canonical AES S-box / inverse S-box
  2. whether AES T-tables (Te0..Te3 / Td0..Td3), rcon, or an expanded key
     schedule exist anywhere in the file
  3. whether any pointer in a data section references the S-box region
  4. whether any AArch64 ADRP/ADD or ADRP/LDR pair in .text computes an address
     inside the S-box region (i.e. real code that would use it)
  5. whether AES-NI / ARMv8 crypto-extension instructions (AESE/AESD/AESMC/
     AESIMC) appear anywhere in .text
  6. per-section entropy, to test the "packed / white-box table" hypothesis

Run:  .venv/bin/python work/aes_forensics.py
"""
import collections
import math
import re
import struct
import sys

import capstone
import lief

SO = sys.argv[1] if len(sys.argv) > 1 else 'work/apk/lib/arm64-v8a/libtopfollow.so'

# Canonical AES forward S-box, FIPS-197 Figure 7. Transcribed as a literal so
# detection does not depend on getting the algebra right, and cross-checked
# against build_sbox() below -- the two must agree or the script aborts.
SBOX = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76'
    'ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d83115'
    '04c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f84'
    '53d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa8'
    '51a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d1973'
    '60814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479'
    'e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a'
    '703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df'
    '8ca1890dbfe6426841992d0fb054bb16'
)

INV_SBOX = bytes.fromhex(
    '52096ad53036a538bf40a39e81f3d7fb'
    '7ce339829b2f8a9d1d89c8a37c0c9d31'
    '0c49b02c7123c3d8c37a3c9c9a2b1bd6'
    '5c02d1e510c3f4e9d2b8f5e04d0d6a00'
)  # first 64 bytes only; the full inverse is derived from SBOX below.


def gmul(a, b_):
    """Multiply in GF(2^8) with the AES polynomial x^8+x^4+x^3+x+1."""
    r = 0
    for _ in range(8):
        if b_ & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b_ >>= 1
    return r


def rotl8(v, n):
    return ((v << n) | (v >> (8 - n))) & 0xFF


def build_sbox():
    """Derive the AES S-box from first principles (FIPS-197).

    S(x) = (x^-1) ^ rotl(x^-1,1) ^ rotl(x^-1,2) ^ rotl(x^-1,3) ^ rotl(x^-1,4) ^ 0x63

    Two bugs worth recording, both of which made an earlier revision of this
    script report "no AES S-box present" for a binary that does contain one:
      * rotating a running accumulator instead of the original inverse;
      * computing the inverse with pow(i, 254, 0x11b), which is invalid --
        GF(2^8) is not Z/0x11b, so modular exponentiation gives the wrong
        element. The inverse must be found via gmul (or a search).
    """
    out = bytearray(256)
    for i in range(256):
        inv = 0
        if i != 0:
            for c in range(256):
                if gmul(i, c) == 1:
                    inv = c
                    break
        # S(x) = b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ 0x63
        # where b = x^-1 in GF(2^8).  All four rotations are of the *original*
        # inverse, then OR-ed together once -- XOR-ing into a running
        # accumulator rotates the already-mixed value and gives a wrong table.
        x = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4)
        out[i] = (x ^ 0x63) & 0xFF
    return bytes(out)


def selftest():
    """Abort rather than report a false negative from broken algebra."""
    sb = build_sbox()
    assert sb == SBOX, 'derived S-box disagrees with the FIPS-197 literal'
    assert sb[:16].hex() == '637c777bf26b6fc53001672bfed7ab76'
    assert sb[0x53] == 0xED and sb[0xFF] == 0x16
    inv = bytearray(256)
    for i, v in enumerate(SBOX):
        inv[v] = i
    assert bytes(inv)[:16].hex() == '52096ad53036a538bf40a39e81f3d7fb'
    return bytes(inv)


def entropy(d):
    if not d:
        return 0.0
    c = collections.Counter(d)
    n = len(d)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main():
    isbox = selftest()
    raw = open(SO, 'rb').read()
    b = lief.parse(SO)
    print(f"=== AES FORENSICS: {SO}  ({len(raw):,} bytes) ===\n")

    sbox = SBOX

    print("--- 1. S-box identification (literal + independent GF(2^8) derivation) ---")
    print(f"  derived fwd S-box[:16] : {build_sbox()[:16].hex()}")
    print(f"  derived inv S-box[:16] : {isbox[:16].hex()}")
    fwd = [m.start() for m in re.finditer(re.escape(sbox), raw)]
    inv = [m.start() for m in re.finditer(re.escape(isbox), raw)]
    print(f"  full 256B FORWARD S-box occurrences : {[hex(x) for x in fwd] or 'NONE'}")
    print(f"  full 256B INVERSE S-box occurrences : {[hex(x) for x in inv] or 'NONE'}")
    part = [m.start() for m in re.finditer(re.escape(sbox[:16]), raw)]
    print(f"  first-16-byte matches               : {[hex(x) for x in part] or 'NONE'}")
    if fwd and part and len(part) > len(fwd):
        print("  !! partial matches without a full S-box => the blob is NOT the AES S-box,")
        print("     it merely begins with those 16 bytes by coincidence or is truncated.")
    print()

    print("--- 2. T-tables / rcon / key schedule ---")
    for nm, word in [('Te0[0]', 0xc66363a5), ('Td0[0]', 0x51f4a750),
                     ('Te0[0] BE', 0xa56363c6), ('Td4 packed', 0x63636363)]:
        hits = []
        for p in (struct.pack('<I', word), struct.pack('>I', word)):
            hits += [m.start() for m in re.finditer(re.escape(p), raw)]
        print(f"  {nm:<12} {sorted(set(hits))[:6] if hits else 'NOT PRESENT'}")
    RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])
    rc = [m.start() for m in re.finditer(re.escape(RCON), raw)]
    print(f"  {'AES rcon':<12} {[hex(x) for x in rc] if rc else 'NOT PRESENT'}")
    print()

    print("--- 3. Data-section pointers into the S-box region ---")
    lo, hi = 0x12000, 0x14400
    cnt = 0
    for sec in b.sections:
        if sec.name in ('.data.rel.ro', '.got', '.data', '.rodata', '.got.plt'):
            d = bytes(sec.content)
            for i in range(0, max(0, len(d) - 8), 8):
                v = struct.unpack_from('<Q', d, i)[0]
                if lo <= v < hi:
                    print(f"  ptr in {sec.name:<13} @VA {sec.virtual_address + i:#x} -> {v:#x}")
                    cnt += 1
    print(f"  total: {cnt}")
    print()

    print("--- 4. Code references into the S-box region (ADRP + ADD/LDR) ---")
    text = [s for s in b.sections if s.name == '.text']
    refs = []
    if text:
        t = text[0]
        td = bytes(t.content)
        base = t.virtual_address
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        pg = {}
        for ins in md.disasm(td, base):
            if ins.mnemonic == 'adrp':
                parts = [x.strip() for x in ins.op_str.split(',')]
                if len(parts) == 2:
                    try:
                        pg[parts[0]] = int(parts[1].replace('#', ''), 0)
                    except ValueError:
                        pass
            elif ins.mnemonic in ('add', 'ldr', 'ldrb', 'ldrh', 'ldrsw', 'str', 'strb'):
                parts = [x.strip() for x in ins.op_str.split(',')]
                # add Xd, Xn, #imm  /  ldr Xd, [Xn, #imm]
                reg = None
                imm = None
                if ins.mnemonic == 'add' and len(parts) == 3 and parts[2].startswith('#'):
                    reg, imm = parts[1], parts[2][1:]
                elif ins.mnemonic != 'add' and len(parts) == 2 and parts[1].startswith('['):
                    inner = parts[1].strip('[]')
                    ip = [x.strip() for x in inner.split(',')]
                    if len(ip) == 2 and ip[1].startswith('#'):
                        reg, imm = ip[0], ip[1][1:]
                if reg is not None and reg in pg and imm:
                    try:
                        target = pg[reg] + int(imm, 0)
                    except ValueError:
                        continue
                    if lo <= target < hi:
                        refs.append((ins.address, ins.mnemonic, ins.op_str, target))
    print(f"  ADRP-relative accesses landing in {lo:#x}-{hi:#x}: {len(refs)}")
    for a, mn, op, tgt in refs[:60]:
        print(f"    VA {a:#x}  {mn:<5} {op:<30} -> {tgt:#x}")
    print()

    print("--- 5. ARMv8 crypto-extension instructions (AESE/AESD/AESMC/AESIMC/SHA*) ---")
    crypto = collections.Counter()
    if text:
        t = text[0]
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        for ins in md.disasm(bytes(t.content), t.virtual_address):
            if ins.mnemonic in ('aese', 'aesd', 'aesmc', 'aesimc',
                                'sha1c', 'sha1h', 'sha1m', 'sha1p', 'sha1su0', 'sha1su1',
                                'sha256h', 'sha256h2', 'sha256su0', 'sha256su1'):
                crypto[ins.mnemonic] += 1
    print(f"  {dict(crypto) if crypto else 'NONE — no hardware AES/SHA instructions anywhere'}")
    print()

    print("--- 6. Per-section entropy ---")
    print("  %-20s %12s %10s %9s" % ("section", "addr", "size", "entropy"))
    for s in sorted(b.sections, key=lambda x: -(x.size or 0)):
        if not s.size:
            continue
        print("  %-20s %#12x %10s %9.4f" % (s.name, s.virtual_address, f"{s.size:,}", entropy(bytes(s.content))))
    print(f"\n  whole-file entropy: {entropy(raw):.4f}")
    print()

    print("--- 7. Highest-entropy 4 KiB windows (white-box table detector) ---")
    W = 4096
    wins = sorted(((entropy(raw[i:i + W]), i) for i in range(0, len(raw) - W, W)), reverse=True)
    for e, i in wins[:10]:
        print(f"  {i:#09x}-{i + W:#09x}  entropy {e:.4f}  uniq {len(set(raw[i:i+W]))}/256")
    print()

    print("--- 8. Crypto API fingerprints (strings + imports) ---")
    for s in [b'OpenSSL', b'BoringSSL', b'libcrypto', b'mbedTLS', b'wolfSSL', b'Crypto++',
              b'libsodium', b'EVP_', b'AES_', b'SHA256', b'RSA_', b'OAEP', b'PBKDF2',
              b'HMAC', b'whitebox', b'white_box', b'chacha', b'ChaCha', b'GCM', b'SSL_CTX']:
        hits = [m.start() for m in re.finditer(re.escape(s), raw)]
        if hits:
            print(f"  !! {s.decode(errors='replace'):<12} x{len(hits)} @ {[hex(h) for h in hits[:4]]}")
    print("  DT_NEEDED:", [x.name for x in b.dynamic_entries
                           if x.tag == lief.ELF.DynamicEntry.TAG.NEEDED])
    print("  imports  :", sorted(s.name for s in b.imported_symbols))
    print("  exports  :", [s.name for s in b.exported_symbols])


if __name__ == '__main__':
    main()
