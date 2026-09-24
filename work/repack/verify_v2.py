#!/usr/bin/env python3
"""Recompute the v2-dialect APK signature digest over a signed APK and compare
it with the value stored inside the block.

Usage:  python3 work/repack/verify_v2.py <signed.apk>

Mirrors work/repack/v2sign_pure.py exactly (the source of truth for the
device-accepted builds):
  * the signed regions are the UNSIGNED layout:
        r1 = bytes before the CD            (in the signed file: raw[:blk])
        r2 = the central directory
        r3 = the EOCD with cd_off pointing at the UNSIGNED CD start
      (v2sign computes the digest BEFORE patching the EOCD, so the unpatched
      cd_off is used; the block shifted the CD by len(block), not by the
      in-block size field L = len(block) - 8.)
  * each region is split into consecutive 1 MiB chunks independently, chunks
    in region order, one global sequence:
        per chunk:  SHA256(0xa5 || u32le(len) || chunk)
        digest =   SHA256(0x5a || u32le(count) || concat)
  * in-block layout (byte-verified against build #7, digest 16f8598e...):
        blk+0   u64 L
        blk+8   u64 len(pair)
        blk+16  pair = u32(0x7109871a) + u32(4+n_signer) + signer
        blk+28  signer = u32(969) + sd
        blk+32  sd     = u32(44) + u32(40) + u32(0x0103) + u32(32)
                          + digest[32] + cert-lps + empty lp
        blk+48  digest (32 B)
"""
import hashlib
import struct
import sys

MAGIC = b'APK Sig Block 42'
CHUNK = 1 << 20


def main(path):
    raw = open(path, 'rb').read()

    i = raw.rfind(MAGIC)
    assert i >= 0, 'v2 magic not found'
    L = struct.unpack('<Q', raw[i - 8:i])[0]
    blk = i - L + 8

    # ---- structure --------------------------------------------------------
    ln_pair = struct.unpack('<Q', raw[blk + 8:blk + 16])[0]
    # block = u64(L) + [u64(len(pair)) + pair] + u64(L) + magic
    block_len = ln_pair + 40
    assert block_len == i + 16 - blk, 'block length inconsistent'
    tag = struct.unpack('<I', raw[blk + 16:blk + 20])[0]
    assert tag == 0x7109871a, f'bad pair tag {tag:#x}'
    n_outer = struct.unpack('<I', raw[blk + 20:blk + 24])[0]
    n_signer = struct.unpack('<I', raw[blk + 24:blk + 28])[0]
    assert n_outer == 4 + n_signer, 'nested signer lengths disagree'
    n_sd = struct.unpack('<I', raw[blk + 28:blk + 32])[0]
    n_item = struct.unpack('<I', raw[blk + 32:blk + 36])[0]
    assert n_sd == 969 and n_item == 44, f'odd sd/item lengths {n_sd} {n_item}'
    assert raw[blk + 36:blk + 40] == b'\x28\x00\x00\x00', 'bad item inner len'
    assert raw[blk + 40:blk + 44] == b'\x03\x01\x00\x00', 'bad digest scheme prefix'
    dl = struct.unpack('<I', raw[blk + 44:blk + 48])[0]
    assert dl == 32, 'digest not 32 bytes'
    inblk = raw[blk + 48:blk + 48 + dl]

    # ---- regions (unsigned layout) ----------------------------------------
    e = raw.rfind(b'\x50\x4b\x05\x06')
    assert e >= 0, 'EOCD not found'
    cd_size = struct.unpack('<I', raw[e + 12:e + 16])[0]
    cd_off_s = struct.unpack('<I', raw[e + 16:e + 20])[0]
    ccomment = struct.unpack('<H', raw[e + 20:e + 22])[0]
    eocd_s = raw[e:e + 22 + ccomment]

    cd_off_u = cd_off_s - block_len
    assert cd_off_u > 0, 'cd_off underflow — not a v2-signed file?'
    assert cd_off_u == blk, 'block is not at the CD start (unexpected layout)'
    eocd_u = eocd_s[:16] + struct.pack('<I', cd_off_u) + eocd_s[20:]
    cd = raw[cd_off_s:cd_off_s + cd_size]

    # ---- recompute (verbatim chunked_digest from v2sign_pure.py) ----------
    digests, count = [], 0
    for region in (raw[:cd_off_u], cd, eocd_u):
        for off in range(0, len(region), CHUNK):
            c = region[off:off + CHUNK]
            digests.append(hashlib.sha256(
                b'\xa5' + struct.pack('<I', len(c)) + c).digest())
            count += 1
    digest = hashlib.sha256(
        b'\x5a' + struct.pack('<I', count) + b''.join(digests)).digest()

    print(f'block@{blk:#x} L={L} block_len={block_len} cd_off_u={cd_off_u} '
          f'cd_size={cd_size} chunks={count}')
    print(f'in-block : {inblk.hex()}')
    print(f'recompute: {digest.hex()}')
    ok = digest == inblk
    print('MATCH — digest in block == recomputed digest' if ok else 'MISMATCH')
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main(sys.argv[1])
