#!/usr/bin/env python3
"""
v2sign_pure.py — APK Signature Scheme v2 signer, 100 % dependency-free.

Byte-identical output layout to v2sign.py (AOSP APK Sig Block, same digest
chunking, same signed-data structure); the two `cryptography` calls are
replaced with textbook RSA-2048 PKCS#1 v1.5 (SHA-256) in pure Python.
"""
import base64, hashlib, struct, sys

MAGIC = b'APK Sig Block 42'
V2_BLOCK_ID = 0x7109871a
ALG_RSA_PKCS1_SHA256 = 0x0103
CHUNK = 1024 * 1024
# DigestInfo prefix for SHA-256 (RFC 8017 / IETF)
DINFO_SHA256 = bytes.fromhex('3031300d060960864801650304020105000420')


def u32(x):
    return struct.pack('<I', x)


def u64(x):
    return struct.pack('<Q', x)


def lp(b):
    return u32(len(b)) + b


def chunked_digest(regions):
    """AOSP APK-Sig-Scheme-v2 content digest (platform
    ApkSignatureSchemeV2Verifier.computeContentDigests, verbatim): EACH
    segment — [bytes before the signing block, central dir, EOCD-as-if-
    cd-offset-pointed-to-block-start] — is split into consecutive 1 MiB
    chunks independently; digest = SHA-256(0x5a || totalChunkCount ||
    concat of per-chunk SHA-256(0xa5 || chunkLen || chunk) in segment order).
    Empty segments produce no chunks.
    """
    digests = []
    count = 0
    for region in regions:
        for i in range(0, len(region), CHUNK):
            c = region[i:i + CHUNK]
            digests.append(hashlib.sha256(b'\xa5' + u32(len(c)) + c).digest())
            count += 1
    return hashlib.sha256(b'\x5a' + u32(count) + b''.join(digests)).digest()


# ---------------- DER parsing (just enough for PKCS#8 -> PKCS#1)
def der_len(d, i):
    l = d[i]
    if l < 0x80:
        return l, i + 1
    n = l & 0x7F
    return int.from_bytes(d[i + 1:i + 1 + n], 'big'), i + 1 + n


def der_seq(d, i):
    assert d[i] == 0x30, f'expected SEQUENCE at {i:#x}'
    ln, j = der_len(d, i + 1)
    return d[j:j + ln], j + ln


def rsa_params_from_pem(path):
    pem = open(path).read()
    kind = 'PKCS8' if 'BEGIN PRIVATE KEY' in pem else 'PKCS1'
    b64 = ''.join(l for l in pem.splitlines()
                  if '-----' not in l and l.strip())
    der = base64.b64decode(b64)
    if kind == 'PKCS8':
        inner, _ = der_seq(der, 0)          # SEQUENCE
        ver, j = der_len(inner, 1)
        i = 1 + j
        alglen, i = der_len(inner, i + 1)   # skip AlgorithmIdentifier SEQUENCE
        i += alglen
        assert inner[i] == 0x04, 'expected OCTET STRING (pkcs1)'
        k, i = der_len(inner, i + 1)
        pk1 = inner[i:i + k]
    else:
        pk1, _ = der_seq(der, 0)
    # PKCS#1: SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
    ints, i = [], 1
    ln0, i = der_len(pk1, 1)
    end = i + ln0
    while i < end:
        assert pk1[i] == 0x02, f'expected INTEGER at {i:#x}'
        ln, i = der_len(pk1, i + 1)
        ints.append(int.from_bytes(pk1[i:i + ln], 'big'))
        i += ln
    version, n, e, d, p, q = ints[:6]
    assert version == 0
    return n, e, d, p, q


def pkcs1_sign(msg, n, e, d, p, q):
    k = (n.bit_length() + 7) // 8
    h = hashlib.sha256(msg).digest()
    t = DINFO_SHA256 + h
    ps_len = k - len(t) - 3
    em = bytes([0, 1]) + b'\xff' * ps_len + b'\x00' + t
    m = int.from_bytes(em, 'big')
    # CRT
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)
    x1 = pow(m, dp, p)
    x2 = pow(m, dq, q)
    h_ = (qinv * (x1 - x2)) % p
    s = x2 + q * h_
    return s.to_bytes(k, 'big')


def spki_from_ne(n, e):
    def i2osp(x):
        b = x.to_bytes((x.bit_length() + 7) // 8, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
        return b

    def tlv(tag, content):
        l = len(content)
        if l < 0x80:
            lb = bytes([l])
        else:
            nb = (l.bit_length() + 7) // 8
            lb = bytes([0x80 | nb]) + l.to_bytes(nb, 'big')
        return bytes([tag]) + lb + content

    rsapub = tlv(0x02, i2osp(n)) + tlv(0x02, i2osp(e))
    rsaalg = tlv(0x30, tlv(0x06, bytes.fromhex('2a864886f70d010101')) + tlv(0x05, b''))
    keybits = tlv(0x03, b'\x00' + tlv(0x30, rsapub))
    return tlv(0x30, rsaalg + keybits)


def sign_apk(path, key_pem, cert_der, out_path):
    raw = open(path, 'rb').read()

    eocd_off = raw.rfind(b'PK\x05\x06')
    assert eocd_off >= 0
    cd_off, = struct.unpack_from('<I', raw, eocd_off + 16)
    assert raw[cd_off:cd_off + 4] == b'PK\x01\x02', 'CD offset sanity'

    r1 = raw[:cd_off]
    r2 = raw[cd_off:eocd_off]
    r3 = raw[eocd_off:]
    assert struct.unpack_from('<I', r3, 16)[0] == cd_off

    digest = chunked_digest([r1, r2, r3])

    digest_entry = lp(u32(ALG_RSA_PKCS1_SHA256) + lp(digest))
    digests_seq = lp(digest_entry)
    certs_seq = lp(lp(cert_der))
    addl_seq = lp(b'')
    signed_data = digests_seq + certs_seq + addl_seq

    n, e, d, p, q = rsa_params_from_pem(key_pem)
    sig = pkcs1_sign(signed_data, n, e, d, p, q)
    spki = spki_from_ne(n, e)

    signer = lp(signed_data) + lp(lp(u32(ALG_RSA_PKCS1_SHA256) + lp(sig))) + lp(spki)
    block_value = lp(lp(signer))
    pair = u32(V2_BLOCK_ID) + block_value
    block_body = u64(len(pair)) + pair
    size = len(block_body) + 8 + 16
    block = u64(size) + block_body + u64(size) + MAGIC

    r3 = bytearray(r3)
    struct.pack_into('<I', r3, 16, cd_off + len(block))
    r3 = bytes(r3)

    out = r1 + block + r2 + r3
    open(out_path, 'wb').write(out)
    print(f"signed {out_path}: {len(out)} bytes (block {len(block)} B, digest {digest.hex()[:16]}…)")
    return out


if __name__ == '__main__':
    sign_apk(sys.argv[1], 'work/repack/keys/research_key.pem',
             open('work/repack/keys/research_cert.der', 'rb').read(), sys.argv[2])
