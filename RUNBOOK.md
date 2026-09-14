# RUNBOOK — real-device runtime pass for TopFollow v8.4.5-Beta

This pass is **static-first**: every finding in `TopFollow_Security_Analysis.html`,
`MERGE_RECONCILIATION.md` and `report/vulns_data.py` is backed by byte-level or
Unicorn/Capstone evidence, reproducible with no device. The runtime pass below is
the **optional** extension that turns the remaining "inconclusive" items into live
proof. It requires hardware; nothing in the deliverables depends on it, and the
tooling **never simulates** — if no device is present it fails loudly.

> **Honesty guardrail:** `device/frida_runner.py` exits non-zero with
> `FATAL: no device` when nothing is connected. No `[STALKER]`/`[TEST]` line in
> `frida_logs.txt` was ever produced without a live process behind it.

---

## 0. Prerequisites

| Item | Detail |
|---|---|
| Device | rooted arm64-v8a phone **or** arm64/x64 Nox instance. The app's signature self-check + maps/root/Frida scanners run inside `JNI_OnLoad`, so spawn-time bypass is mandatory. |
| Host tools | `adb` on PATH, device authorized (`adb devices`) |
| Python | `pip install "frida==17.18.0" "frida-tools==14.10.4"` — the frida-server version **must equal** the host package (mismatch ⇒ connection rejected) |
| APK | the **original signed** `TopFollow_v845-Beta (1).apk` (SHA-256 `a60bcf06…98701a04`) — a repack fails the native signature compare (`d845591e…6bec5e`) |
| Optional | `mitmproxy` (`pip install mitmproxy`) + the repo addon `mitmproxy/topfollow_capture.py` for the wire capture (STEP D/E/F evidence) |

## 1. Install and start frida-server

```bash
adb install -g -r "TopFollow_v845-Beta (1).apk"
bash device/frida_server.sh 17.18.0        # resolves the right ABI build, pushes, starts
frida-ps -U | head                          # sanity: device visible
```

**TCP/wireless option (Nox, or phone without USB debugging):**

```bash
adb forward tcp:27042 tcp:27042
# then use --device 127.0.0.1:27042 in every frida/runner invocation below
```

## 2. Spawn (never attach) under the scripts

The signature check and Retrofit construction happen in `JNI_OnLoad`; attaching
after startup misses them. Always **spawn**:

```bash
python device/frida_runner.py --device usb --seconds 120 --out frida_logs.txt \
    --scripts dynamic-lab/00_common.js \
              dynamic-lab/01_anti_tamper_killer.js \
              dynamic-lab/02_ssl_pinning_bypass.js \
              dynamic-lab/03_instagram_api_intercept.js \
              dynamic-lab/04_credential_theft.js \
              dynamic-lab/05_coin_economy_bypass.js \
              dynamic-lab/06_task_verification_bypass.js \
              dynamic-lab/07_native_jni_dumper.js \
              dynamic-lab/08_backend_traffic_and_servercheck.js \
              dynamic-lab/09_native_aes_dump.js \
              dynamic-lab/10_java_crypto_layer.js
```

Single-script alternative (same spawn semantics):
`frida -U -f com.nivaroid.topfollow -l <script> --no-pause`
Every script 02–10 **self-arms** a minimal anti-tamper/SSL bypass if the full
baseline (01+02) is not loaded — but for the real pass always load the baseline.

## 3. What each script dumps, and how to verify it

| Script | Dumps | Verify by |
|---|---|---|
| 00_common | shared helpers, class resolver | n/a (loaded first, always) |
| 01_anti_tamper_killer | denial counters for su probes, maps-scrub stats, signature-gate result | counters increment as the bootstrap runs; app reaches the login screen on a rooted device |
| 02_ssl_pinning_bypass | every OkHttp `CertificatePinner.check` neutralised + ServerCheck pin/URL values | mitmproxy handshake to `top.nivafollower.app` succeeds |
| 03_instagram_api_intercept | all three IG Retrofit bases (`i.instagram.com/api/v1`, `b.i.instagram.com/api/v1`, `i.instagram.com/api/v2`), headers incl. `signed_body` | compare against the static header table (report §6) |
| 04_credential_theft | password blob `#PWD_INSTAGRAM:4:…`, bearer `IGT:2:…`, 2FA seed, cookies | decode the blob with report/cipher_poc.py logic (q8.t1 dissection in script 10) |
| 05_coin_economy_bypass | wallet inflation + `order_count`/`type` rewrite hook | UI balance flips to the forced value; rpc.exports.setorder works |
| 06_task_verification_bypass | `get_coin=true` forcing, `order_value` rewrite | syncOrder body shows the forged fields |
| 07_native_jni_dumper | live RegisterNatives table (22 `helper.q` natives), XOR-0x55/0x5A/0x37 + base64 decoded strings | diff against `unicorn_decrypted_strings.txt` and `work/analysis/all_decoded_strings.txt` |
| 08_backend_traffic_and_servercheck | all 26 backend endpoints live, ServerCheck JSON (pin/URL rotation) | endpoints match report §9 |
| 09_native_aes_dump | S-box location by content, Stalker over the 5 table-referencing functions, any live round-key-shaped schedule | **this is the script that settles the runtime-key pipeline mode** (0x2fdcc/0x30f18 + ctx `+0x438/+0x458`) and cross-checks RK0 `1742e227063cdfce2c2b4cbd71f1297a` |
| 10_java_crypto_layer | `q8.t1.f` password encryptor (AES-256-GCM key/IV/tag + RSA-wrapped key), every `Cipher.init` raw key, `helper.T` ECDSA `top_key_4286`, dead `digest([B)[B` proof | compare against report §12 and CRED-11 |

## 4. Wire capture of LOGIN → COINS EARN (mitmproxy)

```bash
mitmdump -p 8080 --set block_global=false -s mitmproxy/topfollow_capture.py
# device/proxy: WiFi -> proxy -> host:8080; install the mitmproxy CA once
```

The addon tags and saves, per phase: `ServerCheck` (`topfollow_check.php` JSON:
`url`, `pin`, `pin_active`), backend auth headers (`Token:`, `Active-Id:`,
`Top-Token:`), `instagramLogin.php`, IG login (`accounts/login/`,
`bloks/apps/com.bloks.www.bloks.caa.login.async.send_login_request`), task list
(`order/getOrders…`), task actions (`friendships/create/`, `media/{id}/like/`,
`/comment/`), and coin earn (`order/syncOrder.php` with `get_coin`/`order_value`).
Output: `topfollow_capture.jsonl` + human-readable summary. Script 02 must be
active or the pin will abort the TLS handshake.

## 5. Post-run checklist

- [ ] `frida_logs.txt` contains real `[send]` lines (not just script loads)
- [ ] anti-tamper counters > 0 (detections actually fired and were beaten)
- [ ] 22-row RegisterNatives dump present (matches `work/out/jni_table_verified.json`)
- [ ] if script 09 captured a schedule: paste it into `work/unicorn_aes.py`'s KAT path to classify the mode
- [ ] mitmproxy JSONL covers all five phases of §4
- [ ] nothing fabricated: if a phase produced no traffic (e.g. no tasks available), the log says so

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `FATAL: no device` | no adb device / frida-server not running — see §1 |
| protocol error on connect | frida host ≠ server version — pin both to 17.18.0 |
| app dies in `JNI_OnLoad` | not spawned (attached instead), or 01 missing |
| TLS fails to `top.nivafollower.app` | 02 not loaded, or ServerCheck rotated the pin mid-run (08 logs it) |
| `unable to find class` | class loads later — helpers retry via `Java.enumerateLoadedClasses`; re-run longer |
