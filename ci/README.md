# Runtime analysis in CI — what works, what doesn't, and the one caveat

These files let you produce **genuine Frida runtime logs** for
`com.nivaroid.topfollow` on GitHub Actions, which is exactly what a static
sandbox cannot do (no device, no emulator, no frida-server there).

| File | Role |
|---|---|
| `.github/workflows/runtime-analysis.yml` | Headless run: boot emulator → install APK → start frida-server → spawn app under the 11 scripts → upload `frida_logs.txt`. **Start here.** |
| `.github/workflows/runtime-analysis-vnc.yml` | Same, but the emulator renders into Xvfb and is exposed over **noVNC (Web VNC)** so you can log in / solve a captcha by hand while it captures. |
| `ci/emulator_steps.sh` | The in-emulator sequence (install, frida-server, run, pull sandbox). |
| `ci/frida_server.sh` | Download a version-matched frida-server for the device ABI and start it. |
| `ci/frida_runner.py` | Spawns the app, injects the scripts, routes `send()`/`console.log()` to a log. Fails loudly (exit≠0) if no device — it never simulates. |

Run it: **Actions → runtime analysis → Run workflow** (it is `workflow_dispatch`,
not on-push, because emulator boot is slow). Download the `frida-runtime-logs`
artifact.

## The caveat you must not skip — architecture

**GitHub-hosted runners are x86_64.** KVM only accelerates an x86_64 system
image, so these workflows instrument the APK's **`lib/x86_64/libtopfollow.so`**,
not `lib/arm64-v8a/libtopfollow.so`.

That is still real runtime analysis of the same code: the three ABIs are compiled
from one source and carry the same AES tables (x86_64 S-box `0xdb80`, inverse
`0xec80`, rcon `0xede0`), the same 22 JNI natives and the same detection logic.
Findings transfer. But the *exact* arm64 addresses differ.

**To instrument arm64-v8a specifically**, pick one:
- **Self-hosted arm64 runner** — bare-metal arm64 Linux with `/dev/kvm`, or an
  Apple-silicon macOS runner. Set `runs-on:` to your arm64 label and
  `arch: arm64-v8a` in the emulator steps; nothing else changes.
- **Your rooted arm64 device / arm64 Nox** (you said you have both) — push
  frida-server, then run `python ci/frida_runner.py --device usb …` locally. No CI
  needed. This is the cleanest path to true arm64 logs.

> Google's arm64→x86_64 libndk translation (Android 11+ images) can *load* an
> arm64-only `.so` on an x86_64 emulator, but Frida's Stalker/Interceptor do not
> follow translated arm64→x86 code reliably — so it is **not** a substitute for a
> real arm64 target. This APK ships an x86_64 build, so translation is not needed
> here anyway.

## Web VNC — what it is and isn't

Web VNC (noVNC) is a **viewing/interaction** channel, not what makes the analysis
work — Frida instruments the process directly and needs no display. VNC is useful
only for the manual parts: completing the Instagram login, solving a captcha,
navigating to the follow-task screen. Two practical notes:
- GitHub-hosted runners have **no public inbound IP**. The VNC workflow starts
  noVNC on port `6080`; to actually see it you need the runner UI's port-forward /
  live-preview control, or add a tunnel step (cloudflared/ngrok) and use its URL.
- The session only lives while the job runs, so `keep_alive_minutes` holds the
  emulator up for you, then the capture runs.

## Honesty guardrails baked in

- `frida_runner.py` **exits non-zero** if there is no device — it will not print
  fake `[STALKER]`/`[TEST]` lines.
- The frida-server version is pinned to match the host `frida` package
  (`17.18.0`), resolved from the release API rather than a guessed filename.
- The APK installed is the **original signed build**, so the app's own signature
  self-check passes; `01_anti_tamper_killer.js` handles the maps/root/Frida checks.
- If a step fails, the logs still upload (`if: always()`), so a partial capture is
  visible rather than hidden.

## Expect these real outputs (not simulated)

From the scripts as written, a successful run should show, in `frida_logs.txt`:
the resolved `RegisterNatives` table for the 22 `helper.q` natives (`07`), the
de-obfuscated XOR `0x55`/`0x5A` and base64 strings (`07`), live backend POSTs with
headers/bodies and the ServerCheck pin/URL (`08`), the `q8.t1.f` password-blob
dissection and `Cipher.init` raw keys (`10`), and — if the cipher is exercised
during the run — the AES S-box location and any recoverable round-key schedule
(`09`). Whatever it shows is the truth for that build; if the arm64-specific AES
questions matter, run it on arm64 as above.
