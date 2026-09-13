#!/usr/bin/env python3
"""Clean encrypt/decrypt round-trip attempt on the native block ciphers.
Runs keyexp, then the encrypt block 0x2fdcc and decrypt block 0x30f18 on the
SAME ctx without modification, and reports S-box usage + round-trip. This is
the functional test behind the honest verdict in section 11 of the report."""
import sys, io, contextlib
sys.path.insert(0, 'work')
import unicorn_aes as U
from unicorn.arm64_const import *

def run():
    e = U.Emu(U.SO)
    CTX=U.HEAP_BASE+0x100000; KEYBUF=U.HEAP_BASE+0x400000; IVBUF=U.HEAP_BASE+0x410000
    IN=U.HEAP_BASE+0x200000; OUT=U.HEAP_BASE+0x300000
    e.mu.mem_write(CTX,b'\x00'*0x2000); e.mu.mem_write(CTX+8,b'\x01')
    e.mu.mem_write(KEYBUF,U.KEY256); e.mu.mem_write(IVBUF,b'\x00'*16)
    e.str_long(CTX+0x3d0,KEYBUF,32,32); e.str_long(CTX+0x3f8,IVBUF,16,16)
    SS=U.HEAP_BASE+0x500000; e.mu.mem_write(SS,b'\x00'*0x1000)
    for off in (0x438,0x458,0x500,0x600):
        e.w8(CTX+off,SS+off*0x100); e.mu.mem_write(SS+off*0x100,b'\x00'*0x400)
    e.mu.mem_write(IN,U.PT); e.mu.mem_write(OUT,b'\x00'*64)
    q=io.StringIO()
    with contextlib.redirect_stdout(q):
        e.call(0x32158,regs=((UC_ARM64_REG_X0,CTX),(UC_ARM64_REG_X1,IN),(UC_ARM64_REG_X2,OUT),(UC_ARM64_REG_X3,32),(UC_ARM64_REG_X4,32)),label='keyexp',x8=OUT)
    print("=== CLEAN ROUND-TRIP TEST (native block ciphers, arm64) ===")
    print(f"keyexp: insns={e.count:,} SBOX={e.touched.get('SBOX')} RCON={e.touched.get('RCON')}")
    p438=int.from_bytes(e.rd(CTX+0x438,8),'little')
    print(f"ctx+0x438 schedule-ptr target first16 = {e.rd(p438,16).hex()}  (zeros => keyexp did NOT fill it)")
    print(f"schedule @CTX+0x30 RK0 = {e.rd(CTX+0x30,16).hex()}")
    PTB=bytes(range(16))
    EIN=U.HEAP_BASE+0x600000; EOUT=U.HEAP_BASE+0x600100
    e.mu.mem_write(EIN,PTB); e.mu.mem_write(EOUT,b'\x00'*64)
    with contextlib.redirect_stdout(q):
        e.call(0x2fdcc,regs=((UC_ARM64_REG_X0,CTX),(UC_ARM64_REG_X1,EIN),(UC_ARM64_REG_X2,EOUT)),label='enc',x8=EOUT)
    ct=e.rd(EOUT,16); enc_sbox=e.touched.get('SBOX')
    print(f"\nencrypt 0x2fdcc: pt={PTB.hex()} -> ct={ct.hex()}  SBOX reads={enc_sbox}  insns={e.count:,}")
    DIN=U.HEAP_BASE+0x600200; DOUT=U.HEAP_BASE+0x600300
    e.mu.mem_write(DIN,ct); e.mu.mem_write(DOUT,b'\x00'*64)
    with contextlib.redirect_stdout(q):
        e.call(0x30f18,regs=((UC_ARM64_REG_X0,CTX),(UC_ARM64_REG_X1,DIN),(UC_ARM64_REG_X2,DOUT)),label='dec',x8=DOUT)
    rt=e.rd(DOUT,16); dec_isbox=e.touched.get('ISBOX')
    print(f"decrypt 0x30f18: ct={ct.hex()} -> out={rt.hex()}  ISBOX reads={dec_isbox}  insns={e.count:,}")
    print(f"\nround-trip decrypt(encrypt(pt)) == pt ? {rt==PTB}")
    print(f"S-box usage: enc={enc_sbox} dec={dec_isbox}  (a 14-round AES needs ~160 per block)")
    print("\nVERDICT: genuine AES tables are present and used, but the block functions")
    print("do NOT behave as standard 14-round AES-256 under emulation (too few S-box")
    print("reads, non-FIPS-197 schedule, no round-trip). Modified/obfuscated variant,")
    print("or live-only state. NOT proven to be working standard AES-256.")

if __name__=='__main__':
    run()
