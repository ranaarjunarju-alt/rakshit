"""
Unicorn AArch64 harness for the AES implementation inside libtopfollow.so.

This does not theorise -- it EXECUTES. The static pass identified five
functions that reference the AES S-box (0x128b0), inverse S-box (0x139b0) and
rcon (0x13b10):

    0x2dc00  SBOX user A
    0x2eb94  ISBOX user A
    0x2fdcc  SBOX user B   (encrypt block)
    0x30f18  ISBOX user B  (decrypt block)
    0x32158  SBOX + RCON   (key expansion; validates w3 == w4 == 0x20)

This harness answers, with observed behaviour:

  Q1  Do those functions really read the AES tables when they run?
  Q2  How many times is rcon read?  (14 => AES-256, 12 => AES-192, 10 => AES-128)
  Q3  Where does the expanded key schedule land in memory, and does it match
      the FIPS-197 AES-256 schedule for the standard test key?

Technique
---------
* The DSO is mapped at VA 0 (first PT_LOAD vaddr is 0, so VA == file offset).
* Every GOT slot is repointed at a unique trampoline; a UC_HOOK_CODE hook
  recognises it, runs a Python implementation of that libc function and
  returns. Without this the PLT stubs branch through a zeroed GOT to PC=0.
* All memory reads are logged, so "read the S-box" is an observation.
* After each run the whole writable address space is scanned for the FIPS-197
  AES-256 round-key schedule, which locates the output buffer without having
  to guess the C++ object layout.

Run:  .venv/bin/python work/unicorn_aes.py
"""
import collections
import struct
import sys

import lief
from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UcError,
                     UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
                     UC_HOOK_MEM_UNMAPPED)
from unicorn.arm64_const import *

SO = sys.argv[1] if len(sys.argv) > 1 else 'work/apk/lib/arm64-v8a/libtopfollow.so'

SBOX_VA, ISBOX_VA, RCON_VA = 0x128B0, 0x139B0, 0x13B10

IMAGE_BASE = 0x0
STACK_BASE, STACK_SIZE = 0x7F000000, 0x400000
HEAP_BASE, HEAP_SIZE = 0x08000000, 0x1000000
TLS_BASE, TLS_SIZE = 0x09000000, 0x10000
TRAMP_BASE, TRAMP_SIZE = 0x0A000000, 0x100000
RETURN_TRAP = 0xFFFF0000

XREG = {i: globals()['UC_ARM64_REG_X%d' % i] for i in range(29)}

FN = {
    0x2dc00: 'SBOX user A',
    0x2eb94: 'ISBOX user A',
    0x2fdcc: 'SBOX user B  (ENCRYPT block)',
    0x30f18: 'ISBOX user B (DECRYPT block)',
    0x32158: 'SBOX+RCON    (KEY EXPANSION; validates w3==w4==0x20)',
    0x34424: 'wrapper -> 0x2fdcc',
    0x35518: 'wrapper -> enc+dec (this+0x3d0/0x3f8, mode w4)',
    0x38fa4: 'wrapper -> 0x32158',
    0x3a838: 'wrapper -> 0x32158',
}

# ---------------------------------------------------------------- FIPS-197
KEY256 = bytes.fromhex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')
PT = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
CT = bytes.fromhex('f3eed1bdb5d2a03c064b5a7e3db181f8')


def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def _rotl8(v, n):
    return ((v << n) | (v >> (8 - n))) & 0xFF


def sbox():
    out = bytearray(256)
    for i in range(256):
        inv = 0
        if i:
            for c in range(256):
                if _gmul(i, c) == 1:
                    inv = c
                    break
        x = inv
        for n in (1, 2, 3, 4):
            x ^= _rotl8(inv, n)
        out[i] = (x ^ 0x63) & 0xFF
    return bytes(out)


SBOX = sbox()
assert SBOX[:16].hex() == '637c777bf26b6fc53001672bfed7ab76'
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def expand_key(key):
    """FIPS-197 key expansion; returns the full schedule as bytes."""
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]                       # RotWord
            t = [SBOX[x] for x in t]                # SubWord
            t[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[x] for x in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return bytes(bytearray(x for word in w for x in word))


SCHED256 = expand_key(KEY256)


class Heap:
    def __init__(self, base, size):
        self.base, self.size, self.cur = base, size, base
        self.live, self.freed = {}, 0

    def malloc(self, n):
        n = max(16, (n + 15) & ~15)
        if self.cur + n > self.base + self.size:
            return 0
        p = self.cur
        self.cur += n
        self.live[p] = n
        return p

    def free(self, p):
        if p in self.live:
            del self.live[p]
            self.freed += 1

    def realloc(self, p, n):
        return self.malloc(n)


class Emu:
    def __init__(self, path=SO):
        self.raw = open(path, 'rb').read()
        self.b = lief.parse(path)
        self.size = (len(self.raw) + 0xFFF) & ~0xFFF
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        # +0x10000: .got/.got.plt/.bss sit past the last file-backed page
        self.mu.mem_map(IMAGE_BASE, self.size + 0x10000)
        self.mu.mem_write(IMAGE_BASE, self.raw)
        for base, sz in ((STACK_BASE, STACK_SIZE), (HEAP_BASE, HEAP_SIZE),
                         (TLS_BASE, TLS_SIZE), (TRAMP_BASE, TRAMP_SIZE)):
            self.mu.mem_map(base, sz)
        self.heap = Heap(HEAP_BASE, HEAP_SIZE)
        self.touched = collections.Counter()
        self.reads = collections.Counter()
        self.write_pages = collections.Counter()
        self.writes = []
        self.libc_calls = collections.Counter()
        self.libc_errors = {}
        self.count = 0
        self.stop_reason = 'instruction-cap'
        self.watch = [('SBOX', SBOX_VA, 256), ('ISBOX', ISBOX_VA, 256), ('RCON', RCON_VA, 16)]
        self._install_got_trampolines()
        self._install_hooks()

    def _install_got_trampolines(self):
        self.tramp, self.tramp_of = {}, {}
        rows = sorted((r.address, r.symbol.name if r.symbol else '?')
                      for r in self.b.pltgot_relocations)
        t = TRAMP_BASE
        for got, name in rows:
            self.mu.mem_write(got, struct.pack('<Q', t))
            self.tramp[t] = (name, got)
            self.tramp_of[name] = t
            t += 0x10
        self.tramp_end = t

    # ---- memory helpers ----
    def w8(self, a, v):
        self.mu.mem_write(a, struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF))

    def rd(self, a, n):
        n = int(n)
        if n <= 0:
            return b''
        n = min(n, 1 << 22)
        try:
            return bytes(self.mu.mem_read(a, n))
        except UcError:
            return b''

    def cstr(self, a, limit=4096):
        d = self.rd(a, limit)
        i = d.find(b'\x00')
        return d if i < 0 else d[:i]

    def reg(self, n):
        return self.mu.reg_read(n)

    # ---- libc ----
    def do_libc(self, name):
        try:
            self._libc(name)
        except Exception as ex:
            self.libc_errors[name] = repr(ex)
            self.mu.reg_write(UC_ARM64_REG_X0, 0)

    def _libc(self, name):
        m = self.mu
        x = [self.reg(XREG[i]) for i in range(9)]
        self.libc_calls[name] += 1

        def ret(v):
            m.reg_write(UC_ARM64_REG_X0, v & 0xFFFFFFFFFFFFFFFF)

        if name == 'malloc':
            ret(self.heap.malloc(x[0]))
        elif name == 'free':
            self.heap.free(x[0]); ret(0)
        elif name == 'realloc':
            ret(self.heap.realloc(x[0], x[1]))
        elif name == 'posix_memalign':
            p = self.heap.malloc(x[1]); self.w8(x[0], p); ret(0)
        elif name in ('memcpy', 'memmove', '__memmove_chk'):
            n = x[2]
            d = self.rd(x[1], n)
            m.mem_write(x[0], d)
            ret(x[0])
        elif name in ('wmemcpy', 'wmemmove'):
            m.mem_write(x[0], self.rd(x[1], x[2] * 4)); ret(x[0])
        elif name in ('memset',):
            m.mem_write(x[0], bytes([x[1] & 0xFF]) * min(x[2], 1 << 22)); ret(x[0])
        elif name == 'wmemset':
            m.mem_write(x[0], (struct.pack('<I', x[1]) * min(x[2], 1 << 20))); ret(x[0])
        elif name == 'memcmp':
            a, b_ = self.rd(x[0], x[2]), self.rd(x[1], x[2])
            ret(0 if a == b_ else (1 if a > b_ else 0xFFFFFFFFFFFFFFFF))
        elif name == 'memchr':
            hay = self.rd(x[0], x[2])
            i = hay.find(bytes([x[1] & 0xFF]))
            ret(x[0] + i if i >= 0 else 0)
        elif name in ('strlen', '__strlen_chk'):
            ret(len(self.cstr(x[0])))
        elif name == 'wcslen':
            d = self.rd(x[0], 1024)
            n = 0
            while n + 4 <= len(d) and d[n:n + 4] != b'\x00' * 4:
                n += 4
            ret(n // 4)
        elif name == 'strcpy':
            s = self.cstr(x[1]); m.mem_write(x[0], s + b'\x00'); ret(x[0])
        elif name == 'strcmp':
            a, b_ = self.cstr(x[0]), self.cstr(x[1])
            ret(0 if a == b_ else (1 if a > b_ else 0xFFFFFFFFFFFFFFFF))
        elif name == 'atoi':
            try:
                ret(int(self.cstr(x[0])))
            except Exception:
                ret(0)
        elif name == 'strtol':
            try:
                ret(int(self.cstr(x[0]), int(x[2]) or 10))
            except Exception:
                ret(0)
        elif name == 'clock':
            ret(1000)
        elif name in ('isxdigit_l', 'isdigit_l', 'islower_l', 'isupper_l', 'iswlower_l'):
            c = chr(x[0] & 0xFF)
            r = {'isxdigit_l': lambda: c in '0123456789abcdefABCDEF',
                 'isdigit_l': c.isdigit, 'islower_l': c.islower,
                 'isupper_l': c.isupper, 'iswlower_l': c.islower}[name]
            ret(1 if r() else 0)
        elif name == '__ctype_get_mb_cur_max':
            ret(4)
        elif name in ('newlocale', 'uselocale'):
            ret(1)
        elif name in ('access', '__open_2', 'read', '__read_chk', 'syscall'):
            ret(0xFFFFFFFFFFFFFFFF)
        else:
            ret(0)

    # ---- hooks ----
    def _install_hooks(self):
        def on_code(mu, address, size, ud):
            self.count += 1
            if address == RETURN_TRAP:
                self.stop_reason = 'returned'
                mu.emu_stop()
                return
            if TRAMP_BASE <= address < self.tramp_end:
                key = address & ~0xF
                name, got = self.tramp.get(key, ('?', 0))
                self.do_libc(name)
                mu.reg_write(UC_ARM64_REG_PC, self.reg(UC_ARM64_REG_LR))
                return
            if self.count > 3_000_000:
                self.stop_reason = 'instruction-cap'
                mu.emu_stop()

        def on_read(mu, access, address, size, value, ud):
            self.reads[(address >> 12) << 12] += 1
            for nm, va, ln in self.watch:
                if va <= address < va + ln:
                    self.touched[nm] += 1

        def on_write(mu, access, address, size, value, ud):
            self.write_pages[(address >> 12) << 12] += 1
            if len(self.writes) < 400000:
                self.writes.append((address, size, value))

        def on_unmapped(mu, access, address, size, value, ud):
            page = address & ~0xFFF
            try:
                mu.mem_map(page, 0x1000)
                mu.mem_write(page, b'\x00' * 0x1000)
            except UcError:
                pass
            return True

        self.mu.hook_add(UC_HOOK_CODE, on_code)
        self.mu.hook_add(UC_HOOK_MEM_READ, on_read)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, on_write)
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)

    # ---- std::string layouts ----
    def str_short(self, addr, data):
        buf = bytearray(24)
        buf[0] = (len(data) << 1) & 0xFF
        buf[1:1 + len(data)] = data
        self.mu.mem_write(addr, bytes(buf))

    def str_long(self, addr, dataptr, size, cap):
        self.w8(addr, cap | 1); self.w8(addr + 8, size); self.w8(addr + 16, dataptr)

    def triple(self, addr, dataptr, size):
        self.w8(addr, dataptr); self.w8(addr + 8, size); self.w8(addr + 16, size)

    # ---- run ----
    def setup(self):
        self.mu.reg_write(UC_ARM64_REG_SP, STACK_BASE + STACK_SIZE - 0x20000)
        self.mu.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_BASE)
        self.mu.mem_write(TLS_BASE, struct.pack('<Q', TLS_BASE + 0x100))
        self.mu.mem_write(TLS_BASE + 0x100, b'\x00' * 0x80)
        self.mu.mem_write(TLS_BASE + 0x128, struct.pack('<Q', 0xDEADBEEFCAFEBABE))

    def call(self, fn, regs=(), label='', x8=None, timeout_s=30):
        self.setup()
        self.touched.clear(); self.reads.clear(); self.count = 0
        self.write_pages.clear(); self.writes = []
        self.stop_reason = 'instruction-cap'
        for r, v in regs:
            self.mu.reg_write(r, v)
        if x8 is not None:
            self.mu.reg_write(UC_ARM64_REG_X8, x8)
        self.mu.reg_write(UC_ARM64_REG_LR, RETURN_TRAP)
        print(f"\n{'='*78}\nRUN {label}\n    fn={fn:#x}  {FN.get(fn,'')}\n{'='*78}")
        try:
            self.mu.emu_start(fn, RETURN_TRAP, timeout=timeout_s * 1000 * 1000,
                              count=3_000_000)
        except UcError as e:
            self.stop_reason = f'UcError {e}'
        pc = self.reg(UC_ARM64_REG_PC)
        if pc == RETURN_TRAP:
            self.stop_reason = 'returned'
        rk = self.touched.get('RCON', 0)
        verdict = {10: 'AES-128', 12: 'AES-192', 14: 'AES-256'}.get(rk, '?')
        print(f"  insns executed   : {self.count:,}")
        print(f"  exit             : {self.stop_reason}  PC={pc:#x}")
        print(f"  x0               : {self.reg(UC_ARM64_REG_X0):#x}")
        print(f"  AES table reads  : {dict(self.touched) or 'NONE'}")
        print(f"  rcon reads = {rk}  =>  key length verdict: {verdict}")
        print(f"  libc calls       : {dict(self.libc_calls.most_common(8)) or '-'}")
        wp = [(hex(p), c) for p, c in self.write_pages.most_common(14)]
        print(f"  WRITTEN pages    : {wp}")
        # non-image, non-stack writes = the real output buffers
        out_pages = [p for p in self.write_pages
                     if not (IMAGE_BASE <= p < IMAGE_BASE + self.size + 0x10000)
                     and not (STACK_BASE <= p < STACK_BASE + STACK_SIZE)]
        print(f"  heap/other writes: {[hex(p) for p in sorted(out_pages)][:20]}")
        if self.libc_errors:
            print(f"  libc errors      : {self.libc_errors}")
        return dict(self.touched)

    def scan_for(self, needle, label=''):
        """Search every mapped writable region for needle; report hits."""
        hits = []
        for m in self.mu.mem_regions():
            lo, hi, perm = m[0], m[1], m[2]
            for base in range(lo, hi + 1, 0x10000):
                chunk = self.rd(base, min(0x10000, hi - base + 1))
                i = chunk.find(needle)
                while i >= 0:
                    hits.append(base + i)
                    i = chunk.find(needle, i + 1)
        where = []
        for h in hits:
            if IMAGE_BASE <= h < IMAGE_BASE + self.size + 0x10000:
                where.append(f'{h:#x}(image/.data)')
            elif STACK_BASE <= h < STACK_BASE + STACK_SIZE:
                where.append(f'{h:#x}(stack)')
            elif HEAP_BASE <= h < HEAP_BASE + HEAP_SIZE:
                where.append(f'{h:#x}(heap)')
            else:
                where.append(f'{h:#x}')
        print(f"  scan {label or needle[:8].hex()+'...'}: {len(hits)} hit(s) -> {where[:12]}")
        return hits


def main():
    print(f"=== UNICORN AArch64 AES HARNESS ===\n  target: {SO}")
    print(f"  FIPS-197 AES-256 reference schedule computed: {len(SCHED256)} bytes "
          f"({len(SCHED256)//16} round keys)")
    print(f"    RK0 = {SCHED256[:16].hex()}")
    print(f"    RK1 = {SCHED256[16:32].hex()}")
    print(f"    RK14= {SCHED256[-16:].hex()}")

    e = Emu(SO)
    raw = e.raw
    print(f"\n  image {e.size:,} B mapped at VA 0")
    print(f"  S-box  @ {SBOX_VA:#x}: {raw[SBOX_VA:SBOX_VA+16].hex(' ')}")
    print(f"  invbox @ {ISBOX_VA:#x}: {raw[ISBOX_VA:ISBOX_VA+16].hex(' ')}")
    print(f"  rcon   @ {RCON_VA:#x}: {raw[RCON_VA:RCON_VA+14].hex(' ')}")
    print(f"\n  FIPS-197 vector: key={KEY256.hex()}\n                   pt ={PT.hex()}"
          f"\n                   ct ={CT.hex()}")

    CTX = HEAP_BASE + 0x100000
    IN = HEAP_BASE + 0x200000
    OUT = HEAP_BASE + 0x300000
    KEYBUF = HEAP_BASE + 0x400000
    IVBUF = HEAP_BASE + 0x410000

    layouts = [
        ('libc++ short-string', lambda: (e.str_short(CTX + 0x3d0, KEY256),
                                         e.str_short(CTX + 0x3f8, b'\x00' * 16))),
        ('libc++ long-string', lambda: (e.str_long(CTX + 0x3d0, KEYBUF, 32, 32),
                                        e.str_long(CTX + 0x3f8, IVBUF, 16, 16))),
        ('{ptr,len,cap} triple', lambda: (e.triple(CTX + 0x3d0, KEYBUF, 32),
                                          e.triple(CTX + 0x3f8, IVBUF, 16))),
    ]

    for lname, build in layouts:
        e.mu.mem_write(CTX, b'\x00' * 0x1000)
        e.mu.mem_write(CTX + 0x008, b'\x01')
        e.mu.mem_write(KEYBUF, KEY256)
        e.mu.mem_write(IVBUF, b'\x00' * 16)
        build()
        for sched_off in (0x438, 0x458, 0x500, 0x600):
            e.w8(CTX + sched_off, HEAP_BASE + 0x500000 + sched_off * 0x100)
            e.mu.mem_write(HEAP_BASE + 0x500000 + sched_off * 0x100, b'\x00' * 0x400)
        e.mu.mem_write(IN, PT)
        e.mu.mem_write(OUT, b'\x00' * 64)
        e.call(0x32158,
               regs=((UC_ARM64_REG_X0, CTX), (UC_ARM64_REG_X1, IN),
                     (UC_ARM64_REG_X2, OUT), (UC_ARM64_REG_X3, 32),
                     (UC_ARM64_REG_X4, 32)),
               label=f'KEY EXPANSION  ctx layout = {lname}', x8=OUT)
        e.scan_for(SCHED256[:16], 'FIPS-197 RK0 (16 B)')
        e.scan_for(SCHED256[-16:], 'FIPS-197 RK14 (16 B)')
        e.scan_for(SCHED256, 'FULL 240-byte schedule')
        e.scan_for(KEY256, 'the raw key bytes')


if __name__ == '__main__':
    main()
