#!/usr/bin/env python3
"""
v2sign.py — APK Signature Scheme v2 signer in pure Python (AOSP layout).

  digest  : SHA-256, 1 MiB chunking over (zip contents | central dir | EOCD)
  sig alg : 0x0103 = RSASSA-PKCS1-v1.5 with SHA-256
  block   : APK Signing Block inserted before the central directory;
            EOCD central-directory offset already points there.
"""
import hashlib, struct, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

MAGIC = b'APK Sig Block 42'
V2_BLOCK_ID = 0x7109871a
ALG_RSA_PKCS1_SHA256 = 0x0103
CHUNK = 1024 * 1024


def u32(x):
    return struct.pack('<I', x)


def u64(x):
    return struct.pack('<Q', x)


def lp(b):
    """length-prefixed bytes (u32 length)."""
    return u32(len(b)) + b


def chunked_digest(regions):
    digests = []
    count = 0
    for region in regions:
        for i in range(0, len(region), CHUNK):
            c = region[i:i + CHUNK]
            digests.append(hashlib.sha256(b'\xa5' + u32(len(c)) + c).digest())
            count += 1
    return hashlib.sha256(b'\x5a' + u32(count) + b''.join(digests)).digest()


def sign_apk(path, key_pem, cert_der, out_path):
    raw = open(path, 'rb').read()

    # ---- locate EOCD & central directory
    eocd_off = raw.rfind(b'PK\x05\x06')
    assert eocd_off >= 0
    cd_off, = struct.unpack_from('<I', raw, eocd_off + 16)
    assert raw[cd_off:cd_off + 4] == b'PK\x01\x02', 'CD offset sanity'

    r1 = raw[:cd_off]                 # local entries
    r2 = raw[cd_off:eocd_off]         # central directory
    r3 = raw[eocd_off:]               # EOCD (cd_offset field already == cd_off)
    assert struct.unpack_from('<I', r3, 16)[0] == cd_off

    digest = chunked_digest([r1, r2, r3])

    # ---- signed-data
    digest_entry = lp(u32(ALG_RSA_PKCS1_SHA256) + lp(digest))
    digests_seq = lp(digest_entry)
    certs_seq = lp(lp(cert_der))
    addl_seq = lp(b'')
    signed_data = digests_seq + certs_seq + addl_seq

    # ---- signature
    key = serialization.load_pem_private_key(open(key_pem, 'rb').read(), password=None)
    sig = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())

    spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)

    signer = lp(signed_data) + lp(lp(u32(ALG_RSA_PKCS1_SHA256) + lp(sig))) + lp(spki)
    block_value = lp(lp(signer))                # sequence of length-prefixed signers

    pair = u32(V2_BLOCK_ID) + block_value
    block_body = u64(len(pair)) + pair            # one id-value pair
    size = len(block_body) + 8 + 16               # pairs + trailing u64 + magic
    block = u64(size) + block_body + u64(size) + MAGIC

    # EOCD cd-offset must point to the (shifted) central directory
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
