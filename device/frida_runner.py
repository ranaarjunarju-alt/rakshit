#!/usr/bin/env python3
"""
device/frida_runner.py — drive the dynamic-lab Frida scripts against a LIVE
device and capture their real output to a log file.

This is the piece that turns the 11 scripts into genuine runtime logs. It:
  * connects to a real device over USB, or to a frida-server on TCP,
  * SPAWNs com.nivaroid.topfollow (spawn mode is required — the signature
    self-check and Retrofit construction run inside JNI_OnLoad, so attaching
    after start misses them),
  * injects 00_common.js plus every script named on the command line,
  * routes all send()/console.log() output to a log file,
  * resumes the app, runs for --seconds, then detaches.

It does NOT simulate anything: if no device is present it fails loudly with a
non-zero exit code. Run it on a rooted device / arm64 Nox with frida-server
started (see device/frida_server.sh and device/README.md).

Usage (real device over USB):
  python device/frida_runner.py --device usb --seconds 60 --out frida_logs.txt \
      --scripts dynamic-lab/00_common.js \
                dynamic-lab/01_anti_tamper_killer.js \
                dynamic-lab/02_ssl_pinning_bypass.js \
                dynamic-lab/03_instagram_api_intercept.js \
                dynamic-lab/07_native_jni_dumper.js \
                dynamic-lab/09_native_aes_dump.js \
                dynamic-lab/10_java_crypto_layer.js
"""
import argparse
import sys
import time

import frida

PACKAGE = "com.nivaroid.topfollow"


def get_device(spec: str):
    dm = frida.get_device_manager()
    if spec in ("usb", "local", "remote"):
        return getattr(dm, f"get_{spec}_device")(timeout=25)
    if ":" in spec:                       # host:port -> frida-server over TCP
        host, port = spec.rsplit(":", 1)
        return dm.add_remote_device(f"{host}:{port}")
    return dm.get_device(spec, timeout=25)  # explicit device id


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", default="usb",
                    help="'usb', 'local', a device id, or host:port for TCP")
    ap.add_argument("--package", default=PACKAGE)
    ap.add_argument("--scripts", nargs="+", required=True,
                    help="JS files to inject, in order (00_common.js first)")
    ap.add_argument("--seconds", type=int, default=60,
                    help="how long to let the instrumented app run")
    ap.add_argument("--out", default="frida_logs.txt")
    args = ap.parse_args()

    out = open(args.out, "w", buffering=1)   # line-buffered

    def log(line: str):
        stamp = time.strftime("%H:%M:%S")
        out.write(f"[{stamp}] {line}\n")
        print(line, flush=True)

    log(f"frida {frida.__version__} | runner start")
    try:
        device = get_device(args.device)
    except Exception as e:
        log(f"FATAL: no device ({args.device}): {e}")
        log("       start frida-server on the device, or check --device.")
        return 2
    log(f"device: {device} (type={device.type})")

    # concatenate the scripts in the order given
    src = []
    for path in args.scripts:
        try:
            with open(path, "r", encoding="utf-8") as f:
                src.append(f"\n/* ===== {path} ===== */\n" + f.read())
            log(f"loaded script: {path}")
        except OSError as e:
            log(f"FATAL: cannot read {path}: {e}")
            return 2
    source = "\n".join(src)

    def on_message(message, data):
        if message.get("type") == "send":
            log("[send] " + repr(message.get("payload")))
        elif message.get("type") == "error":
            log("[script-error] " + str(message.get("stack") or message.get("description")))
        else:
            log("[msg] " + repr(message))

    try:
        pid = device.spawn([args.package])
        log(f"spawned {args.package} pid={pid} (suspended)")
        session = device.attach(pid)
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        log("scripts injected; resuming app")
        device.resume(pid)
    except Exception as e:
        log(f"FATAL: spawn/attach/inject failed: {e}")
        return 3

    log(f"running for {args.seconds}s — capturing live output ...")
    try:
        time.sleep(args.seconds)
    except KeyboardInterrupt:
        log("interrupted")

    try:
        script.unload()
        session.detach()
    except Exception:
        pass
    log(f"done. full log -> {args.out}")
    out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
