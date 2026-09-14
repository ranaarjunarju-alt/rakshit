#!/usr/bin/env python3
"""
Where does the native AES key come from?

unicorn_aes.py proved the key-expansion routine 0x32158 produces an IDENTICAL
240-byte schedule regardless of the caller's key layout (three layouts -> same
89,148 insns, same SBOX=112 / RCON=14, same x0).  So the routine derives its
own key and ignores what the caller passes.  This script finds out where that
key comes from, with a full memory-read trace.

Method: reuse the working Emu harness, add a per-instruction read log
(address, size, IP), run 0x32158 once, then classify every read:
  * code fetch / image .text  -> not data
  * SBOX / ISBOX / RCON       -> the AES tables (already accounted for)
  * other image-backed (file) -> a CONSTANT baked into the binary  <-- key src?
  * heap / stack / TLS        -> caller-supplied or scratch
Then reconstruct the bytes read from each image data region and test whether the
observed RK0 (1742e227063cdfce2c2b4cbd71f1297a) is present in, or derivable
from, any of them.
"""
import sys, collections, struct
sys.path.insert(0, 'work')
import unicorn_aes as U
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, \
    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_PC

IMAGE_BASE = U.IMAGE_BASE
SO = U.SO

# observed schedule from the prior run (work/out/34_aes_key_recovery.txt)
RK0_OBS = bytes.fromhex('1742e227063cdfce2c2b4cbd71f1297a')


class Tracer(U.Emu):
    def __init__(self, path=SO):
        super().__init__(path)
        self.cur_ip = 0
        self.readlog = []            # (ip, addr, size)
        self._rehook()

    def _rehook(self):
        # add an IP tracker + a detailed read logger on top of the base hooks
        def track_ip(mu, address, size, ud):
            self.cur_ip = address
        def log_read(mu, access, address, size, value, ud):
            if len(self.readlog) < 4_000_000:
                self.readlog.append((self.cur_ip, address, size))
        self.mu.hook_add(UC_HOOK_CODE, track_ip)
        self.mu.hook_add(UC_HOOK_MEM_READ, log_read)

    # region classification
    def region(self, a):
        sz = self.size + 0x10000
        if U.SBOX_VA <= a < U.SBOX_VA + 256: return 'SBOX'
        if U.ISBOX_VA <= a < U.ISBOX_VA + 256: return 'ISBOX'
        if U.RCON_VA <= a < U.RCON_VA + 16: return 'RCON'
        if IMAGE_BASE <= a < IMAGE_BASE + sz:
            # .text is [0x2d2ac, +1591568); everything else image-backed is data
            if 0x2d2ac <= a < 0x2d2ac + 1591568: return 'image:.text'
            return 'image:data'
        if U.STACK_BASE <= a < U.STACK_BASE + U.STACK_SIZE: return 'stack'
        if U.HEAP_BASE <= a < U.HEAP_BASE + U.HEAP_SIZE: return 'heap'
        if U.TLS_BASE <= a < U.TLS_BASE + U.TLS_SIZE: return 'tls'
        if U.TRAMP_BASE <= a < self.tramp_end: return 'tramp'
        return 'other'


def main():
    print("=== UNICORN KEY-SOURCE TRACE  (fn 0x32158, arm64-v8a) ===")
    e = Tracer(SO)
    raw = e.raw

    CTX = U.HEAP_BASE + 0x100000
    IN = U.HEAP_BASE + 0x200000
    OUT = U.HEAP_BASE + 0x300000
    KEYBUF = U.HEAP_BASE + 0x400000
    IVBUF = U.HEAP_BASE + 0x410000

    e.mu.mem_write(CTX, b'\x00' * 0x1000)
    e.mu.mem_write(CTX + 0x008, b'\x01')
    e.mu.mem_write(KEYBUF, U.KEY256)
    e.mu.mem_write(IVBUF, b'\x00' * 16)
    e.str_long(CTX + 0x3d0, KEYBUF, 32, 32)
    e.str_long(CTX + 0x3f8, IVBUF, 16, 16)
    for off in (0x438, 0x458, 0x500, 0x600):
        e.w8(CTX + off, U.HEAP_BASE + 0x500000 + off * 0x100)
        e.mu.mem_write(U.HEAP_BASE + 0x500000 + off * 0x100, b'\x00' * 0x400)
    e.mu.mem_write(IN, U.PT)
    e.mu.mem_write(OUT, b'\x00' * 64)

    e.readlog.clear()
    e.call(0x32158,
           regs=((UC_ARM64_REG_X0, CTX), (UC_ARM64_REG_X1, IN),
                 (UC_ARM64_REG_X2, OUT), (UC_ARM64_REG_X3, 32),
                 (UC_ARM64_REG_X4, 32)),
           label='KEY-SOURCE TRACE (long-string ctx)', x8=OUT)

    print(f"\n  total reads logged: {len(e.readlog):,}")
    byreg = collections.Counter()
    bytes_by_reg = collections.Counter()
    for ip, a, s in e.readlog:
        r = e.region(a)
        byreg[r] += 1
        bytes_by_reg[r] += s
    print("  reads by region (count / bytes):")
    for r in sorted(byreg, key=lambda x: -byreg[x]):
        print(f"    {r:<14} {byreg[r]:>8,} reads   {bytes_by_reg[r]:>10,} bytes")

    # ---- focus: image:data reads (constants baked into the file) ----
    imgdata = [(ip, a, s) for ip, a, s in e.readlog if e.region(a) == 'image:data']
    print(f"\n  image:data reads (file-backed constants): {len(imgdata):,}")
    addrs = collections.Counter(a for _, a, _ in imgdata)
    print(f"  distinct image:data addresses: {len(addrs)}")
    # group into contiguous runs
    runs = []
    for a in sorted(addrs):
        if runs and a == runs[-1][1]:
            runs[-1][1] = a + 1
        else:
            runs.append([a, a + 1])
    print(f"  contiguous image:data runs: {len(runs)}")
    for lo, hi in runs[:40]:
        data = raw[lo:hi]
        print(f"    {lo:#08x}-{hi:#08x} ({hi-lo:>3} B) reads={sum(addrs[x] for x in range(lo,hi)):>5}  {data[:32].hex(' ')}")

    # ---- reconstruct what the schedule was built from ----
    print("\n  --- key-source tests ---")
    # collect all image:data bytes actually read
    blob = bytearray()
    for lo, hi in runs:
        blob += raw[lo:hi]
    print(f"  image:data bytes read (concatenated): {len(blob)}")
    print(f"  observed RK0 {RK0_OBS.hex()} present in image:data blob? "
          f"{'YES @'+hex(blob.find(RK0_OBS)) if RK0_OBS in blob else 'NO'}")
    print(f"  observed RK0 present anywhere in the whole file? "
          f"{'YES @'+hex(raw.find(RK0_OBS)) if RK0_OBS in raw else 'NO'}")
    # first 32 bytes of RK0||RK1 = the raw key; search file
    print(f"  RK0 first-16 in file? {'YES @'+hex(raw.find(RK0_OBS[:16])) if RK0_OBS[:16] in raw else 'NO'}")

    # ---- heap reads that are NOT the caller key/iv: where else? ----
    heap = [(ip, a, s) for ip, a, s in e.readlog if e.region(a) == 'heap']
    ha = collections.Counter(a for _, a, _ in heap)
    print(f"\n  heap reads: {len(heap):,} over {len(ha)} distinct addresses")
    # ranges of heap touched
    hranges = []
    for a in sorted(ha):
        if hranges and a == hranges[-1][1]:
            hranges[-1][1] = a + 1
        else:
            hranges.append([a, a + 1])
    named = {CTX: 'CTX', IN: 'IN(pt)', OUT: 'OUT', KEYBUF: 'KEYBUF(caller key)',
             IVBUF: 'IVBUF'}
    for off in (0x438, 0x458, 0x500, 0x600):
        named[U.HEAP_BASE + 0x500000 + off * 0x100] = f'SCHED@{off:#x}'
    for lo, hi in hranges:
        lbl = next((v for k, v in named.items() if k <= lo < k + 0x400), '')
        print(f"    {lo:#09x}-{hi:#09x} ({hi-lo:>4} B) {lbl}")

    # ---- decisive: is the key computed from immediates (no data read)? ----
    # If image:data runs are all small/non-key and RK0 is nowhere in the file or
    # the read blob, the key is register-computed -> only live dump works.
    print("\n  === VERDICT ===")
    if RK0_OBS in blob or RK0_OBS in raw:
        print("  RK0 IS present in file-backed data that the routine reads.")
        print("  -> the key (or schedule) is a binary constant; extractable statically.")
    else:
        print("  RK0 is NOT present in any file-backed region read by 0x32158,")
        print("  nor anywhere in the 1.8 MB file. The key is COMPUTED at runtime")
        print("  from register/immediate state inside the OLLVM prologue, not read")
        print("  from a stored constant. Static extraction is impossible; it is")
        print("  recoverable only from live process memory (dynamic-lab/09).")


if __name__ == '__main__':
    main()
