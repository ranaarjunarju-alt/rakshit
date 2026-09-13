# Analysis toolchain

Every script here is the actual tooling used to produce the findings in
[`../TopFollow_Security_Analysis.html`](../TopFollow_Security_Analysis.html).
Nothing was hand-written from a disassembler UI — each claim traces to one of
these.

All scripts assume they are run from this directory (`work/`) against the
extracted APK at `work/apk/`, which is **gitignored** because it is 17 MB of
regenerable payload. Recreate it with:

```bash
unzip "../TopFollow_v845-Beta (1).apk" -d apk
```

Dependencies: a Python venv with `androguard`, `lief`, `capstone`,
`asn1crypto` (see the top-level README).

## Stage 1 — surface

| Script | Output | Purpose |
|---|---|---|
| `scan_manifest.py` | `out/01_manifest.json` | manifest attributes, permissions, components |
| `manifest_dump.py` | `out/07_AndroidManifest.xml` | decoded AXML (androguard cannot emit raw XML here) |
| `dex_full.py` | `out/02_dex_overview.json` | DEX header, map_list, class/method counts |
| `so_strings.py` | `out/04…06` | printable strings per ABI |
| `so_checksec.py` | `out/13_so_checksec.json` | RELRO / canary / FORTIFY / PIE / NX per ABI |

> ⚠️ The DEX `map_list` in this APK is **scrambled** — section offsets are
> reordered and out of range. Any tool that walks it linearly (including
> androguard's annotator) returns garbage or indexes out of bounds. Use the
> class-def walk instead.

## Stage 2 — Java layer

| Script | Output | Purpose |
|---|---|---|
| `dump_all.py` | `out/all/` *(gitignored, 24 MB)* | pseudocode for all 4,146 classes — the primary reading corpus |
| `smali_dump.py` | `out/smali/` *(gitignored)* | smali, for bodies the decompiler drops (e.g. `ia.v`) |
| `dex_annot.py` | `out/10_annotations.txt`, `out/10_retrofit_annotations.json`, `out/11_retrofit.txt` | raw DEX annotation parse — recovers Retrofit `@POST`/`@GET` path values that androguard loses |
| `models_fields.py` | — | dataclass field maps (`ServerCheckModel`, `PlayIntegrityModel`, `DeviceModel`, `Order`, `Account`, …) |
| `xref_dump.py` | `out/xref/` *(gitignored)*, `out/09_xref_classes.json` | cross-references for a target class/method |
| `annot.py` | `out/10_annotations.txt` | earlier androguard-based attempt; superseded by `dex_annot.py` |

## Stage 3 — native layer

This is where the OLLVM control-flow flattening had to be routed around. The
**code** is flattened; the **data** references are not.

| Script | Output | Purpose |
|---|---|---|
| `find_natives.py` | — | first pass at locating `JNINativeMethod` tables |
| `find_natives2.py` | `out/14_jni_natives.json` | working version. On **x86** the table is a literal array at file offset `0xd8fec` — all 22 entries resolve directly. On **64-bit** builds the pointers are materialised at runtime, so no static scan works; use the Frida `RegisterNatives` interceptor instead (`../dynamic-lab/07_native_jni_dumper.js`). |
| `disasm.py` | `out/15_disasm_key.txt` | Capstone disassembly of the key functions |
| `fn_strings.py` | — | ⚠️ **SUPERSEDED — DO NOT USE.** Resolved `.rodata` references against a single *global* GOT base, which mis-aligns on this binary and produces wrong strings. Kept only to document the dead end. |
| `fn_strings2.py` | `out/16_native_fn_strings.*` | intermediate: per-section base, still partially mis-aligned |
| `fn_strings3.py` | `out/17_native_strings.txt`, `out/17_text_rodata_refs.json`, `out/18_native_strings_by_fn.txt`, `out/18_text_refs.json` | ✅ **The working resolver.** Detects each position-independent thunk (`call $+5; pop reg; add reg, K` — 943 found), derives a **per-function** `.rodata` base from it, and resolves 760 references. This is what attributed every secret string to the function that uses it, including the 622 references inside `x0018d3f7`. |
| `find_blobs.py` | — | high-entropy blob scan (no embedded keys/certs found) |

## Stage 4 — secrets

| Script | Output | Purpose |
|---|---|---|
| `arsc.py` | `out/21_backup_rules.txt` | parses `resources.arsc` to locate `res/Qq.xml` (`fullBackupContent`) and `res/4j.xml` (`dataExtractionRules`), then decodes them. **Both are empty** — that is the finding. |
| `cipher_poc.py` | — | ✅ re-implementation of the `glide.d.p()`/`q()` cipher in Python: XOR `0x6C` → rotate-left 3 → reverse → XOR `(i*37)^0xA5`. Round-trip **verified**, which proves it is keyless. |
| *(inline in `fn_strings3.py`)* | `out/19_xor_decoded.txt` | exhaustive single-byte XOR sweep over keys 1–127 across every printable run. **Two keys crack everything:** `0x55` (backend URL, Instagram URLs, pin, UUID) and `0x5A` (anti-Frida keywords, root paths). |
| *(inline, signing-block parse)* | `out/20_signing.txt` | APK Signing Block walker. See the note below — the naive layout assumption is wrong. |

### Signing block: the layout gotcha

The v2 pair does **not** sit at `magic − 8 − size2 − 8`. Computing it that way
yields an absurd block size (~661 GB) because the block has a variable-length
prefix. The working approach, in order:

1. Scan backwards from the `APK Sig Block 42` magic for the pair id
   `0x7109871a` (v2 scheme).
2. Read the `u64` length at `id − 8`.
3. The pair body spans `id + 4 … id − 8 + len`.
4. Find the `30 82` DER sequence start inside it → that is the certificate.

Confirmed offsets in this APK: signing-block magic `@0x9d1608`, central
directory `@0x9d1618`, EOCD `@0x9e616c`, v2 pair `@0x9ce620`. There is **no
v1/JAR signature** — v2 block plus a verity padding block only.

## Rebuilding the report

```bash
cd .. && .venv/bin/python report/build_report.py
```

Reads `report/vulns_data.py` (the 63-finding register), the nine scripts in
`dynamic-lab/`, and the evidence files above, then emits the single-file HTML.
