#!/usr/bin/env python3
"""TopFollow (com.nivaroid.topfollow) local 'encryption' cipher - com.bumptech.glide.d.p()/q()
   Reverse-engineered from DEX.  Used to "protect": Instagram password (u_w), IG bearer token
   (u_a), 2FA secret (s_k), SharedPreferences blobs (Pin, Sign, Aid, DeviceId, RD), x2 integrity
   token, xr message.  NO KEY. Pure static transform => trivially reversible."""
import base64

def _core(buf: bytearray):
    for i in range(len(buf)):                 # 1. XOR 0x6C
        buf[i] = (buf[i] ^ 0x6C) & 0xFF
    for i in range(len(buf)):                 # 2. rotate-left 3 bits
        v = buf[i]; buf[i] = (((v & 7) << 5) | (v >> 3)) & 0xFF
    lo, hi = 0, len(buf) - 1                  # 3. full reverse
    while lo < hi:
        buf[lo], buf[hi] = buf[hi], buf[lo]; lo += 1; hi -= 1
    for i in range(len(buf)):                 # 4. XOR position-dependent key (i*37)^0xA5
        buf[i] = (buf[i] ^ (((i * 37) ^ 0xA5) & 0xFF)) & 0xFF
    return buf

def _inv_core(buf: bytearray):
    for i in range(len(buf)):                 # undo 4
        buf[i] = (buf[i] ^ (((i * 37) ^ 0xA5) & 0xFF)) & 0xFF
    lo, hi = 0, len(buf) - 1                  # undo 3
    while lo < hi:
        buf[lo], buf[hi] = buf[hi], buf[lo]; lo += 1; hi -= 1
    for i in range(len(buf)):                 # undo 2 : rotate-right 3
        v = buf[i]; buf[i] = (((v & 0x1F) << 3) | (v >> 5)) & 0xFF
    for i in range(len(buf)):                 # undo 1
        buf[i] = (buf[i] ^ 0x6C) & 0xFF
    return buf

def encrypt(s: str) -> bytes:      # == d.q() inner transform (before native q.o + B64)
    return bytes(_core(bytearray(s.encode())))

def decrypt(b: bytes) -> str:      # == d.p() inner transform (after  B64 + native q.n)
    return bytes(_inv_core(bytearray(b))).decode('utf-8', 'replace')

if __name__ == "__main__":
    tests = ["my_instagram_password", "Bearer IGT:2:eyJkc191c2VyX2lkIjoiMTIzIn0=",
             "JBSWY3DPEHPK3PXP", "https://top.nivafollower.app/v840/", "123456"]
    print("%-52s %-24s %s" % ("PLAINTEXT", "TOPFOLLOW-CIPHER (hex)", "ROUND-TRIP OK"))
    print("-" * 100)
    ok = True
    for t in tests:
        c = encrypt(t); d = decrypt(c)
        ok &= (d == t)
        print("%-52s %-24s %s" % (t[:50], c.hex()[:22] + ("..." if len(c.hex()) > 22 else ""), d == t))
    print("-" * 100)
    print("cipher is an involution-free but KEYLESS static transform -> round-trip verified:", ok)
    print()
    print("Stored form in DB/prefs = base64( native_q.o( cipher ) ).  Because native q.o()/q.n() are")
    print("a fixed, keyless byte transform too, hooking ONE Java method (d.p / d.q) with Frida dumps")
    print("every credential in the app in cleartext - see dynamic-lab/05_dump_local_crypto.js")
    # demo: decrypt a synthetic stored blob end-to-end (pure-python path, native q.n assumed identity+b64)
    pt = "P@ssw0rd123!"
    blob = base64.b64encode(encrypt(pt)).decode()
    print()
    print("  synthetic stored blob :", blob)
    print("  recovered plaintext   :", decrypt(base64.b64decode(blob)))
