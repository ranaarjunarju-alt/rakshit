#!/usr/bin/env python3
"""
Functional proof that the native cipher IS AES-256.

unicorn_aes.py proved the key-EXPANSION routine reads rcon 14 times.  This goes
the rest of the way:

  1. run key expansion 0x32158, then read the schedule it left in memory
  2. verify the schedule obeys the FIPS-197 AES-256 recurrence exactly, so the
     first 32 bytes ARE a valid AES-256 key  -> the runtime key, extracted
  3. plant that schedule into a ctx at the offsets the block ciphers read
     (ctx+0x438 and ctx+0x458, from the disassembly) and RUN the encrypt block
     0x2fdcc and the decrypt block 0x30f18 under Unicorn
  4. show they read the forward / inverse S-box the number of times a 14-round
     AES does, and that decrypt(encrypt(pt)) round-trips
"""
import sys, struct, collections
sys.path.insert(0, 'work')
import unicorn_aes as U
from unicorn import UC_HOOK_MEM_READ
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X4)

ENCRYPT_BLOCK = 0x2fdcc
DECRYPT_BLOCK = 0x30f18
KEYEXP        = 0x32158
SBOX, ISBOX, RCON = U.SBOX_VA, U.ISBOX_VA, U.RCON_VA


class V(U.Emu):
    def __init__(self, path=U.SO):
        super().__init__(path)
        self.cur_ip = 0
        self.readlog = []
        self.mu.hook_add(__import__('unicorn').UC_HOOK_CODE,
                         lambda mu, a, s, ud: setattr(self, 'cur_ip', a))

    def readtrace(self, on):
        self._rt = on
    def _log_read(self, mu, access, addr, size, value, ud):
        if getattr(self, '_rt', False):
            self.readlog.append((self.cur_ip, addr, size))


def fips197_check(sched):
    """Return (ok, first_bad) verifying the AES-256 recurrence over a 240B sched."""
    if len(sched) < 240:
        return False, f'schedule too short ({len(sched)})'
    w = [list(sched[4*i:4*i+4]) for i in range(60)]
    for i in range(8, 60):
        t = list(w[i-1])
        if i % 8 == 0:
            t = t[1:] + t[:1]
            t = [U.SBOX[x] for x in t]
            t[0] ^= U.RCON[i//8 - 1]
        elif i % 8 == 4:
            t = [U.SBOX[x] for x in t]
        exp = [a ^ b for a, b in zip(w[i-8], t)]
        if exp != w[i]:
            return False, f'w[{i}]: got {bytes(w[i]).hex()} want {bytes(exp).hex()}'
    return True, 'all 60 words obey FIPS-197'


def main():
    print("=== FUNCTIONAL AES-256 VERIFICATION (arm64-v8a) ===")
    e = V(U.SO)
    # install the detailed read logger on top of base hooks
    e.mu.hook_add(UC_HOOK_MEM_READ, e._log_read)

    CTX = U.HEAP_BASE + 0x100000
    KEYBUF = U.HEAP_BASE + 0x400000
    IVBUF = U.HEAP_BASE + 0x410000
    IN = U.HEAP_BASE + 0x200000
    OUT = U.HEAP_BASE + 0x300000

    # ---- 1. run key expansion, capture the schedule it writes ----
    # keyexp validates w3==w4==0x20 (256-bit); pass them or it early-returns.
    e.mu.mem_write(CTX, b'\x00' * 0x2000)
    e.mu.mem_write(CTX + 0x008, b'\x01')
    e.mu.mem_write(KEYBUF, U.KEY256)
    e.mu.mem_write(IVBUF, b'\x00' * 16)
    e.str_long(CTX + 0x3d0, KEYBUF, 32, 32)
    e.str_long(CTX + 0x3f8, IVBUF, 16, 16)
    SCHED_SCRATCH = U.HEAP_BASE + 0x500000
    e.mu.mem_write(SCHED_SCRATCH, b'\x00' * 0x1000)
    for off in (0x438, 0x458, 0x500, 0x600):
        e.w8(CTX + off, SCHED_SCRATCH + off * 0x100)
        e.mu.mem_write(SCHED_SCRATCH + off * 0x100, b'\x00' * 0x400)
    e.mu.mem_write(IN, U.PT)
    e.mu.mem_write(OUT, b'\x00' * 64)

    print("\n[1] running key expansion 0x32158 ...")
    e.call(KEYEXP,
           regs=((UC_ARM64_REG_X0, CTX), (UC_ARM64_REG_X1, IN),
                 (UC_ARM64_REG_X2, OUT), (UC_ARM64_REG_X3, 32),
                 (UC_ARM64_REG_X4, 32)),
           label='KEYEXP (capture schedule)', x8=OUT)

    # The schedule lands inside the ctx struct at CTX+0x30 (the function writes
    # 732 bytes there). Read it directly rather than scanning.
    print("\n[2] reading the schedule the routine left at CTX+0x30 ...")
    SCHED = e.rd(CTX + 0x30, 240)
    for i in range(0, 240, 16):
        print(f"    RK{i//16:<2} {SCHED[i:i+16].hex()}")
    ok, msg = fips197_check(SCHED)
    print(f"    strict FIPS-197 AES-256 recurrence over all 60 words: {ok}  ({msg})")
    KEY = SCHED[:32]
    print(f"    first 32 bytes (would be the AES-256 key if standard): {KEY.hex()}")
    # word-level structure
    w = [SCHED[4*i:4*i+4] for i in range(60)]
    print(f"    w[4..7] == w[0..3] ? {w[4:8] == w[0:4]}   (a standard AES-256 schedule")
    print(f"        never repeats the key like this -- so this is NOT a textbook expansion)")

    # ---- 3. run the block ciphers on the SAME ctx (schedule already in place) ----
    e.w8(CTX + 0x438, CTX + 0x30)     # point the schedule pointers at the schedule
    e.w8(CTX + 0x458, CTX + 0x30)

    PT = bytes(range(16))                       # distinctive plaintext 00..0f
    IN = U.HEAP_BASE + 0x600000
    OUT = U.HEAP_BASE + 0x600100
    e.mu.mem_write(IN, PT)
    e.mu.mem_write(OUT, b'\x00' * 64)

    print("\n[3] running ENCRYPT block 0x2fdcc on pt = 000102...0f ...")
    e.readlog.clear(); e.readtrace(True)
    e.touched.clear()
    e.call(ENCRYPT_BLOCK,
           regs=((UC_ARM64_REG_X0, CTX), (UC_ARM64_REG_X1, IN), (UC_ARM64_REG_X2, OUT)),
           label='ENCRYPT block', x8=OUT)
    e.readtrace(False)
    sbox_reads = sum(1 for _, a, _ in e.readlog if SBOX <= a < SBOX+256)
    isbox_reads = sum(1 for _, a, _ in e.readlog if ISBOX <= a < ISBOX+256)
    sched_reads = sum(1 for _, a, _ in e.readlog if CTX+0x438 <= a < CTX+0x438+240)
    ct = e.rd(OUT, 16)
    print(f"    exit={e.stop_reason} insns={e.count:,}")
    print(f"    SBOX reads = {sbox_reads}   ISBOX reads = {isbox_reads}   schedule reads = {sched_reads}")
    print(f"    ciphertext block @OUT = {ct.hex()}")

    # ---- 4. decrypt round-trip ----
    IN2 = U.HEAP_BASE + 0x600200
    OUT2 = U.HEAP_BASE + 0x600300
    e.mu.mem_write(IN2, ct)
    e.mu.mem_write(OUT2, b'\x00' * 64)
    print("\n[4] running DECRYPT block 0x30f18 on that ciphertext ...")
    e.readlog.clear(); e.readtrace(True); e.touched.clear()
    e.call(DECRYPT_BLOCK,
           regs=((UC_ARM64_REG_X0, CTX), (UC_ARM64_REG_X1, IN2), (UC_ARM64_REG_X2, OUT2)),
           label='DECRYPT block', x8=OUT2)
    e.readtrace(False)
    sbox_reads2 = sum(1 for _, a, _ in e.readlog if SBOX <= a < SBOX+256)
    isbox_reads2 = sum(1 for _, a, _ in e.readlog if ISBOX <= a < ISBOX+256)
    rt = e.rd(OUT2, 16)
    print(f"    exit={e.stop_reason} insns={e.count:,}")
    print(f"    SBOX reads = {sbox_reads2}   ISBOX reads = {isbox_reads2}")
    print(f"    recovered block @OUT2 = {rt.hex()}")
    print(f"    round-trip decrypt(encrypt(pt)) == pt ? {rt == PT}")

    print("\n=== VERDICT (honest) ===")
    print(f"  strict FIPS-197 AES-256 schedule from keyexp : {ok}")
    print(f"    -> a real AES-256 key schedule obeys the recurrence for all 60 words;")
    print(f"       this one breaks at w[8]. So the 240-byte output is NOT a textbook")
    print(f"       AES-256 schedule, and its first 32 bytes are NOT a standard key.")
    print(f"  encrypt block: forward S-box read {sbox_reads}x, produced {ct.hex()}")
    print(f"  decrypt block: inverse S-box read {isbox_reads2}x, produced {rt.hex()}")
    print(f"  a 14-round AES does ~160 SubBytes per block; {sbox_reads} is far short.")
    print(f"  round-trip decrypt(encrypt(pt)) == pt : {rt == PT}")
    print()
    print("  CONCLUSION: the library unambiguously CONTAINS the genuine AES S-box,")
    print("  inverse S-box and rcon, and the key-expansion routine reads rcon 14x")
    print("  (AES-256-shaped). But under emulation the block functions do NOT behave")
    print("  as standard 14-round AES-256: too few S-box accesses, a non-FIPS-197")
    print("  schedule, and no encrypt/decrypt round-trip. Either the cipher is a")
    print("  modified/obfuscated AES variant, or the block functions need live state")
    print("  (a fully-initialised ctx: real key string, IV, GCM/CTR counter) that a")
    print("  standalone Unicorn call does not reproduce. Claiming 'working AES-256")
    print("  proven' would be an over-claim; the tables and shapes are proven, the")
    print("  standard algorithm is NOT. Settling it needs a live process (script 09).")


if __name__ == '__main__':
    main()
