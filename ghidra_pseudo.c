/* ============================================================================
 * ghidra_pseudo.c  —  HONEST SUBSTITUTE (Ghidra headless is NOT available)
 * ============================================================================
 * The mandate asked for `analyzeHeadless ... -import libtopfollow.so`. Ghidra is
 * NOT installed in this workspace and CANNOT be: its release assets are hosted on
 * objects.githubusercontent.com, which the sandbox egress firewall blocks, and the
 * Debian mirrors needed to fetch a JDK/Maven are also unreachable. This was
 * verified, not assumed. I will NOT fabricate Ghidra output.
 *
 * What this file actually is: real Capstone AArch64 disassembly of the genuine
 * key functions, plus manual reconstruction of their semantics. Every address and
 * instruction below is copied from the binary, not invented.
 *
 * The functions the mandate names — encryptWhiteBox, decryptWhiteBox,
 * stringDecryptor/sub_128A0, checkRoot, checkFrida, checkIntegrity, pbkdf2, hmac
 * — DO NOT EXIST in this library. See the ABSENT section at the bottom for the
 * byte-level evidence. The real equivalents are named on the right.
 *
 * One structural fact dominates everything: every non-trivial function here is
 * OLLVM control-flow-flattened (bcf/fla). JNI_OnLoad's first 8 KB alone contains
 * 195 cmp/ccmp and 271 branch instructions and opaque predicates such as
 *     mov  w10, #0xf2e9 ; movk w10,#0x52d3,lsl#16 ; mvn w9,w10 ;
 *     add  w9,w8,w9 ; add w9,w9,w10 ; mul w8,w9,w8 ; eor w9,w8,#0xfffffffe ;
 *     tst  w9,w8 ; cset w8,eq            // w9 = w8*(...) ; always-true test
 * which is why a clean C reconstruction is not achievable statically and why the
 * honest path is dynamic (Unicorn for pure-compute routines — done; Frida on a
 * device for the JNI-bound ones — not possible in this sandbox).
 * ==========================================================================*/

/* ---- JNI_OnLoad @ 0x3e1d4 : sole export; OLLVM-flattened; registers the 22 natives via RegisterNatives ---- */
void JNI_OnLoad(void) {   /* disassembly, first 44 instructions */
    /* 0x03e1d4 */  sub      sp, sp, #0xb0;
    /* 0x03e1d8 */  stp      x29, x30, [sp, #0x50];
    /* 0x03e1dc */  stp      x28, x27, [sp, #0x60];
    /* 0x03e1e0 */  stp      x26, x25, [sp, #0x70];
    /* 0x03e1e4 */  stp      x24, x23, [sp, #0x80];
    /* 0x03e1e8 */  stp      x22, x21, [sp, #0x90];
    /* 0x03e1ec */  stp      x20, x19, [sp, #0xa0];
    /* 0x03e1f0 */  add      x29, sp, #0x50;
    /* 0x03e1f4 */  mrs      x9, tpidr_el0;
    /* 0x03e1f8 */  str      x9, [sp];
    /* 0x03e1fc */  ldr      x9, [x9, #0x28];
    /* 0x03e200 */  adrp     x22, #0x1ba000;
    /* 0x03e204 */  ldr      x22, [x22, #0xb50];
    /* 0x03e208 */  sub      x8, x29, #0x10;
    /* 0x03e20c */  adrp     x23, #0x1ba000;
    /* 0x03e210 */  ldr      x23, [x23, #0xb58];
    /* 0x03e214 */  stur     x9, [x29, #-8];
    /* 0x03e218 */  str      x8, [sp, #8];
    /* 0x03e21c */  ldr      x8, [sp, #8];
    /* 0x03e220 */  ldr      w8, [x22];
    /* 0x03e224 */  mov      w10, #0xf2e9;
    /* 0x03e228 */  movk     w10, #0x52d3, lsl #16;
    /* 0x03e22c */  mvn      w9, w10;
    /* 0x03e230 */  add      w9, w8, w9;
    /* 0x03e234 */  add      w9, w9, w10;
    /* 0x03e238 */  ldr      w10, [x23];
    /* 0x03e23c */  mul      w8, w9, w8;
    /* 0x03e240 */  eor      w9, w8, #0xfffffffe;
    /* 0x03e244 */  tst      w9, w8;
    /* 0x03e248 */  cset     w8, eq;
    /* 0x03e24c */  cmp      w10, #0xa;
    /* 0x03e250 */  sturb    w8, [x29, #-0x16];
    /* 0x03e254 */  cset     w8, lt;
    /* 0x03e258 */  mov      w20, #0xa223;
    /* 0x03e25c */  mov      w21, #0x89f6;
    /* 0x03e260 */  mov      w24, #0xfd96;
    /* 0x03e264 */  mov      w25, #0x89f5;
    /* 0x03e268 */  mov      w26, #0x2db3;
    /* 0x03e26c */  mov      w27, #0xc046;
    /* 0x03e270 */  sturb    w8, [x29, #-0x15];
    /* 0x03e274 */  mov      w8, #0xfd96;
    /* 0x03e278 */  mov      x19, x0;
    /* 0x03e27c */  movk     w20, #0xb809, lsl #16;
    /* 0x03e280 */  movk     w21, #0x6910, lsl #16;
}

/* ---- aes_keyexp @ 0x32158 : reads S-box 112x + rcon 14x (AES-256 SubWord); validates w3==w4==0x20 ---- */
void aes_keyexp(void) {   /* disassembly, first 44 instructions */
    /* 0x032158 */  stp      x29, x30, [sp, #-0x60]!;
    /* 0x03215c */  stp      x28, x27, [sp, #0x10];
    /* 0x032160 */  stp      x26, x25, [sp, #0x20];
    /* 0x032164 */  stp      x24, x23, [sp, #0x30];
    /* 0x032168 */  stp      x22, x21, [sp, #0x40];
    /* 0x03216c */  stp      x20, x19, [sp, #0x50];
    /* 0x032170 */  mov      x29, sp;
    /* 0x032174 */  sub      sp, sp, #0x1b0;
    /* 0x032178 */  mvn      w8, w4;
    /* 0x03217c */  orr      w8, w8, #8;
    /* 0x032180 */  cmn      w8, #0x11;
    /* 0x032184 */  cset     w8, ne;
    /* 0x032188 */  cmp      w4, #0x20;
    /* 0x03218c */  cset     w10, ne;
    /* 0x032190 */  eor      w11, w10, w8;
    /* 0x032194 */  orr      w8, w10, w8;
    /* 0x032198 */  eor      w8, w8, #1;
    /* 0x03219c */  mov      w12, #0x7fc1;
    /* 0x0321a0 */  mov      w13, #0x5d13;
    /* 0x0321a4 */  mvn      w9, w3;
    /* 0x0321a8 */  orr      w8, w11, w8;
    /* 0x0321ac */  movk     w12, #0xbd33, lsl #16;
    /* 0x0321b0 */  movk     w13, #0xf140, lsl #16;
    /* 0x0321b4 */  orr      w9, w9, #8;
    /* 0x0321b8 */  cmp      w8, #0;
    /* 0x0321bc */  csel     w8, w13, w12, ne;
    /* 0x0321c0 */  cmn      w9, #0x11;
    /* 0x0321c4 */  str      w8, [sp, #0x1c];
    /* 0x0321c8 */  cset     w8, ne;
    /* 0x0321cc */  cmp      w3, #0x20;
    /* 0x0321d0 */  cset     w9, ne;
    /* 0x0321d4 */  eor      w10, w9, w8;
    /* 0x0321d8 */  orr      w8, w9, w8;
    /* 0x0321dc */  eor      w8, w8, #1;
    /* 0x0321e0 */  orr      w8, w10, w8;
    /* 0x0321e4 */  mov      w9, #0x9102;
    /* 0x0321e8 */  movk     w9, #0xb51d, lsl #16;
    /* 0x0321ec */  cmp      w8, #0;
    /* 0x0321f0 */  add      x8, x0, #0x3d4;
    /* 0x0321f4 */  csel     w20, w9, w12, ne;
    /* 0x0321f8 */  add      x9, x0, #0x418;
    /* 0x0321fc */  str      x8, [sp, #0xb8];
    /* 0x032200 */  add      x8, x0, #0x3cc;
    /* 0x032204 */  stp      x8, x9, [sp, #8];
}

/* ---- aes_encrypt_block @ 0x2fdcc : reads forward S-box; ctx+0x438/0x458 = schedule ---- */
void aes_encrypt_block(void) {   /* disassembly, first 44 instructions */
    /* 0x02fdcc */  sub      sp, sp, #0x110;
    /* 0x02fdd0 */  stp      x29, x30, [sp, #0xb0];
    /* 0x02fdd4 */  stp      x28, x27, [sp, #0xc0];
    /* 0x02fdd8 */  stp      x26, x25, [sp, #0xd0];
    /* 0x02fddc */  stp      x24, x23, [sp, #0xe0];
    /* 0x02fde0 */  stp      x22, x21, [sp, #0xf0];
    /* 0x02fde4 */  stp      x20, x19, [sp, #0x100];
    /* 0x02fde8 */  add      x29, sp, #0xb0;
    /* 0x02fdec */  adrp     x17, #0x1ba000;
    /* 0x02fdf0 */  ldr      x17, [x17, #0x840];
    /* 0x02fdf4 */  mov      x28, x0;
    /* 0x02fdf8 */  adrp     x0, #0x1ba000;
    /* 0x02fdfc */  mov      w9, #0xad39;
    /* 0x02fe00 */  ldr      w8, [x17];
    /* 0x02fe04 */  ldr      x0, [x0, #0x848];
    /* 0x02fe08 */  movk     w9, #0xc244, lsl #16;
    /* 0x02fe0c */  mvn      w10, w9;
    /* 0x02fe10 */  add      w10, w10, w8;
    /* 0x02fe14 */  add      w9, w10, w9;
    /* 0x02fe18 */  ldr      w10, [x0];
    /* 0x02fe1c */  mul      w8, w9, w8;
    /* 0x02fe20 */  eor      w9, w8, #0xfffffffe;
    /* 0x02fe24 */  tst      w9, w8;
    /* 0x02fe28 */  cset     w8, eq;
    /* 0x02fe2c */  cmp      w10, #0xa;
    /* 0x02fe30 */  strb     w8, [sp, #0x41];
    /* 0x02fe34 */  cset     w8, lt;
    /* 0x02fe38 */  strb     w8, [sp, #0x42];
    /* 0x02fe3c */  add      x9, x28, #0x438;
    /* 0x02fe40 */  add      x8, x28, #0x3d4;
    /* 0x02fe44 */  stp      x8, x9, [sp, #8];
    /* 0x02fe48 */  add      x8, x28, #0x458;
    /* 0x02fe4c */  str      x8, [sp];
    /* 0x02fe50 */  mov      x24, x2;
    /* 0x02fe54 */  mov      w25, #0x75d2;
    /* 0x02fe58 */  mov      w15, #0xc6b8;
    /* 0x02fe5c */  mov      w16, #0x85c5;
    /* 0x02fe60 */  mov      w22, #0x6698;
    /* 0x02fe64 */  mov      w20, #0x9a50;
    /* 0x02fe68 */  mov      w2, #0x314;
    /* 0x02fe6c */  mov      w3, #0xc561;
    /* 0x02fe70 */  mov      w26, #0x372e;
    /* 0x02fe74 */  mov      w27, #0x372f;
    /* 0x02fe78 */  mov      w4, #0xe48c;
}

/* ---- aes_decrypt_block @ 0x30f18 : reads inverse S-box ---- */
void aes_decrypt_block(void) {   /* disassembly, first 44 instructions */
    /* 0x030f18 */  sub      sp, sp, #0x150;
    /* 0x030f1c */  stp      x29, x30, [sp, #0xf0];
    /* 0x030f20 */  stp      x28, x27, [sp, #0x100];
    /* 0x030f24 */  stp      x26, x25, [sp, #0x110];
    /* 0x030f28 */  stp      x24, x23, [sp, #0x120];
    /* 0x030f2c */  stp      x22, x21, [sp, #0x130];
    /* 0x030f30 */  stp      x20, x19, [sp, #0x140];
    /* 0x030f34 */  add      x29, sp, #0xf0;
    /* 0x030f38 */  ldrb     w8, [x0, #8];
    /* 0x030f3c */  add      x9, x0, #0x3d4;
    /* 0x030f40 */  stp      x1, x2, [sp, #0x18];
    /* 0x030f44 */  adrp     x16, #0x1ba000;
    /* 0x030f48 */  str      w8, [sp, #0x60];
    /* 0x030f4c */  add      x8, x0, #0x438;
    /* 0x030f50 */  str      x8, [sp, #0x58];
    /* 0x030f54 */  add      x8, x0, #0x458;
    /* 0x030f58 */  stp      x8, x9, [sp];
    /* 0x030f5c */  adrp     x17, #0x1ba000;
    /* 0x030f60 */  ldr      x16, [x16, #0x860];
    /* 0x030f64 */  ldr      x17, [x17, #0x868];
    /* 0x030f68 */  mov      w24, #0x7d04;
    /* 0x030f6c */  mov      w28, #0xc6b8;
    /* 0x030f70 */  mov      w26, #0x85c5;
    /* 0x030f74 */  mov      w27, #0xe48c;
    /* 0x030f78 */  mov      w20, #0x372f;
    /* 0x030f7c */  mov      w25, #0x7d03;
    /* 0x030f80 */  mov      w22, #0x5c74;
    /* 0x030f84 */  mov      w19, #0x372e;
    /* 0x030f88 */  mov      w21, #0xf0b2;
    /* 0x030f8c */  str      x8, [sp, #0x50];
    /* 0x030f90 */  mov      w8, #0x9171;
    /* 0x030f94 */  mov      x23, x0;
    /* 0x030f98 */  movk     w24, #0xf1c6, lsl #16;
    /* 0x030f9c */  movk     w28, #0xd2fa, lsl #16;
    /* 0x030fa0 */  movk     w26, #0x9037, lsl #16;
    /* 0x030fa4 */  movk     w27, #0x6c9b, lsl #16;
    /* 0x030fa8 */  movk     w20, #0x5522, lsl #16;
    /* 0x030fac */  movk     w25, #0xf1c6, lsl #16;
    /* 0x030fb0 */  movk     w22, #0xaff0, lsl #16;
    /* 0x030fb4 */  movk     w19, #0x5522, lsl #16;
    /* 0x030fb8 */  movk     w21, #0x2bf9, lsl #16;
    /* 0x030fbc */  movk     w8, #0x8f71, lsl #16;
    /* 0x030fc0 */  str      x0, [sp, #0x10];
    /* 0x030fc4 */  b        #0x30fd4;
}

/* ---- aes_wrapper @ 0x35518 : w4==1 -> encrypt, w4==2 -> decrypt ---- */
void aes_wrapper(void) {   /* disassembly, first 44 instructions */
    /* 0x035518 */  sub      sp, sp, #0x140;
    /* 0x03551c */  stp      x29, x30, [sp, #0xe0];
    /* 0x035520 */  stp      x28, x27, [sp, #0xf0];
    /* 0x035524 */  stp      x26, x25, [sp, #0x100];
    /* 0x035528 */  stp      x24, x23, [sp, #0x110];
    /* 0x03552c */  stp      x22, x21, [sp, #0x120];
    /* 0x035530 */  stp      x20, x19, [sp, #0x130];
    /* 0x035534 */  add      x29, sp, #0xe0;
    /* 0x035538 */  ldrb     w8, [x0, #8];
    /* 0x03553c */  mov      w9, #0x98e;
    /* 0x035540 */  mov      w10, #0xb07f;
    /* 0x035544 */  movk     w9, #0x7fb, lsl #16;
    /* 0x035548 */  cmp      w8, #0;
    /* 0x03554c */  cset     w8, eq;
    /* 0x035550 */  cmp      x3, #0;
    /* 0x035554 */  sturb    w8, [x29, #-0x6a];
    /* 0x035558 */  cset     w8, eq;
    /* 0x03555c */  sturb    w8, [x29, #-0x69];
    /* 0x035560 */  movk     w10, #0xf7c7, lsl #16;
    /* 0x035564 */  mov      w11, #0x94f8;
    /* 0x035568 */  mov      w12, #0xc390;
    /* 0x03556c */  add      x13, x0, #0x3d0;
    /* 0x035570 */  cmp      w4, #2;
    /* 0x035574 */  movk     w11, #0xba4a, lsl #16;
    /* 0x035578 */  movk     w12, #0xa6f8, lsl #16;
    /* 0x03557c */  str      x13, [sp];
    /* 0x035580 */  csel     w13, w10, w9, eq;
    /* 0x035584 */  cmp      w4, #1;
    /* 0x035588 */  mov      w28, #0xc6b8;
    /* 0x03558c */  mov      w26, #0x85c5;
    /* 0x035590 */  mov      w24, #0x9db5;
    /* 0x035594 */  mov      w27, #0xe48c;
    /* 0x035598 */  mov      w20, #0x372f;
    /* 0x03559c */  mov      w25, #0xb512;
    /* 0x0355a0 */  mov      w21, #0xdb42;
    /* 0x0355a4 */  mov      w19, #0x372e;
    /* 0x0355a8 */  csel     w8, w12, w11, eq;
    /* 0x0355ac */  mov      w11, #0x94f7;
    /* 0x0355b0 */  mov      w9, #0xbac0;
    /* 0x0355b4 */  mov      x22, x3;
    /* 0x0355b8 */  movk     w28, #0xd2fa, lsl #16;
    /* 0x0355bc */  movk     w26, #0x9037, lsl #16;
    /* 0x0355c0 */  movk     w24, #0x6ffc, lsl #16;
    /* 0x0355c4 */  movk     w27, #0x6c9b, lsl #16;
}

/* ============================================================================
 * ABSENT — the named functions that are NOT in this library (byte-level proof)
 * ============================================================================
 * encryptWhiteBox / decryptWhiteBox : no white-box T-box table exists. .rodata is
 *     37,547 bytes TOTAL; a white-box AES table is ~2 MB. Only 3 high-entropy
 *     4 KiB windows exist in the whole file (the two S-box pages + a 549-byte
 *     whitening table @0x13b30). There is nothing to be a white-box function over.
 * stringDecryptor / sub_128A0 : 0x128A0 is in .rodata (.text starts at 0x2d2ac),
 *     16 bytes before the AES S-box. It is data (7b cb b0 b0 a8 fc 54 54 ...),
 *     not an instruction. Strings are de-obfuscated by inline single-byte XOR
 *     (keys 0x55 / 0x5A) at each reference site — see unicorn_decrypted_strings.txt.
 * checkRoot  : real logic = probe 9 su paths (XOR 0x5A list) via access/fopen.
 *     No Magisk/Zygisk/Shamiko strings exist. Inside the bootstrap mega-function.
 * checkFrida : real logic = read /proc/self/maps + match edxposed/substrate/riru/
 *     (deleted)/rwxp + a few base64 Frida markers. The literal ASCII "Frida" at
 *     0x15e68 is "Friday" from the C++ locale weekday table (strftime_l), NOT a
 *     detection. No 27042, no gum-js-loop, no inline-hook/SVC check.
 * checkIntegrity : real logic = getPackageInfo(signatures) -> reflective
 *     MessageDigest("SHA-256") -> compare to d845591e... (the signing-cert digest,
 *     which is also the TLS pin). No native dex-CRC. Java-side, not native.
 * pbkdf2 / hmac : ABSENT. No "PBKDF2", "HmacSHA", "sha512" bytes anywhere (raw,
 *     XOR55, XOR5A). No PBKDF2/HMAC in the native library. (Java does SHA-256/
 *     MD5/ECDSA only; no PBKDF2/HMAC anywhere in the DEX either.)
 * ==========================================================================*/
