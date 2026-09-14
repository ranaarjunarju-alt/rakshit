#!/usr/bin/env python3
"""
mitmproxy/topfollow_capture.py — capture the LOGIN -> COINS EARN wire flow of
TopFollow v8.4.5 (com.nivaroid.topfollow).

Run:
    mitmdump -p 8080 --set block_global=false -s mitmproxy/topfollow_capture.py

Requires script 02_ssl_pinning_bypass.js to be active on the device, otherwise
the OkHttp pin (d845591e…6bec5e / ServerCheck-rotated pin) aborts the TLS
handshake before any request is visible.

What it records (one JSON object per line in topfollow_capture.jsonl):
  servercheck   GET/POST topfollow_check.php          -> url/pin/pin_active fields
  backend_auth  any top.nivafollower.app request      -> Token/Active-Id/Top-Token headers
  ig_login      i.instagram.com login paths           -> #PWD_INSTAGRAM blob presence
  ig_action     friendships/create, media/*/like, comment, save, seen
  coin_earn     order/syncOrder.php                   -> get_coin / order_value fields
  coin_spend    order/submitOrder.php                 -> set_order_stamp
  other         everything else to the two vendors' hosts

A human-readable summary is written to topfollow_capture_summary.txt on exit
(Ctrl-C of mitmdump). Nothing is modified — pure capture.
"""
import json
import re
import time

OUT_JSONL = "topfollow_capture.jsonl"
OUT_SUMMARY = "topfollow_capture_summary.txt"

BACKEND_HOSTS = ("top.nivafollower.app", "nivafollower-app.com")
IG_HOSTS = ("i.instagram.com", "b.i.instagram.com", "www.instagram.com")

IG_LOGIN_RX = re.compile(r"accounts/login|send_login_request|bloks\.www\.bloks\.caa\.login")
IG_ACTION_RX = re.compile(
    r"friendships/(create|destroy|show)|media/[0-9]+/(like|comment)|/comment/|/save/|/seen/"
)

PHASE_ORDER = ["servercheck", "backend_auth", "ig_login", "ig_action",
               "coin_spend", "coin_earn", "other"]


def _body_text(flow, limit=200_000):
    try:
        raw = flow.request.get_content()
    except Exception:
        return ""
    if raw is None:
        return ""
    try:
        return raw[:limit].decode("utf-8", "replace")
    except Exception:
        return ""


def _classify(flow):
    host = flow.request.pretty_host
    path = flow.request.path
    if host in BACKEND_HOSTS:
        if "topfollow_check.php" in path:
            return "servercheck"
        if "syncOrder" in path:
            return "coin_earn"
        if "submitOrder" in path:
            return "coin_spend"
        return "backend_auth"
    if host in IG_HOSTS:
        if IG_LOGIN_RX.search(path):
            return "ig_login"
        if IG_ACTION_RX.search(path):
            return "ig_action"
        return "other"
    return None  # not a vendor host: ignore


class TopFollowCapture:
    def __init__(self):
        self.fh = open(OUT_JSONL, "a", buffering=1)
        self.counts = {p: 0 for p in PHASE_ORDER}
        self.started = time.time()
        print(f"[topfollow_capture] writing {OUT_JSONL}")

    def request(self, flow):
        phase = _classify(flow)
        if phase is None:
            return
        self.counts[phase] += 1
        req = flow.request
        body = _body_text(flow)
        rec = {
            "t": time.strftime("%H:%M:%S"),
            "phase": phase,
            "method": req.method,
            "host": req.pretty_host,
            "path": req.path[:400],
            "headers": {
                k: v for k, v in req.headers.items()
                if k.lower() in (
                    "token", "active-id", "top-token", "user-agent", "x-ig-app-id",
                    "authorization", "cookie", "content-type", "x-ig-connection-type",
                    "x-bloks-version-id", "x-ig-capabilities",
                )
            },
            "body_len": len(body),
        }
        # targeted field extraction — the manipulation surface
        if phase == "coin_earn":
            for f in ("get_coin", "order_value", "order_id", "type", "i_type",
                      "pk", "username", "active_pk", "x4", "x5", "x6", "x7"):
                m = re.search(re.escape(f) + r"=([^&\s]{0,200})", body)
                if m:
                    rec.setdefault("fields", {})[f] = m.group(1)[:160]
        if phase == "coin_spend":
            m = re.search(r"set_order_stamp=([^&\s]{0,400})", body)
            if m:
                rec.setdefault("fields", {})["set_order_stamp"] = m.group(1)[:300]
        if phase == "ig_login":
            rec["pwd_instagram_blob"] = "#PWD_INSTAGRAM" in body
            m = re.search(r"#PWD_INSTAGRAM:(\d+):([0-9]+):([0-9]+):", body)
            if m:
                rec["pwd_envelope"] = {
                    "scheme": m.group(1),
                    "ts": m.group(2),
                    "keyid_or_len": m.group(3),
                }
        if phase == "servercheck":
            # ServerCheck may be GET with query or POST form
            rec["query"] = req.query if hasattr(req, "query") else ""
        if body and phase != "ig_login":
            rec["body_head"] = body[:600]
        self.fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"[topfollow_capture] {phase:12s} {req.method} {req.pretty_host}{req.path[:110]}")

    def response(self, flow):
        phase = _classify(flow)
        if phase is None:
            return
        if phase in ("servercheck", "coin_earn"):
            try:
                text = flow.response.get_content()[:4000].decode("utf-8", "replace")
            except Exception:
                text = ""
            rec = {"t": time.strftime("%H:%M:%S"), "phase": phase + "_response",
                   "status": flow.response.status_code, "body_head": text[:1200]}
            if phase == "servercheck":
                for k in ("url", "pin", "pin_active", "repair_mode",
                          "update_available", "update_url"):
                    m = re.search('"' + k + r'"\s*:\s*"?([^",}\]]{0,300})', text)
                    if m:
                        rec.setdefault("fields", {})[k] = m.group(1)
            self.fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def done(self):
        self.fh.close()
        dur = int(time.time() - self.started)
        with open(OUT_SUMMARY, "w") as f:
            f.write("TopFollow wire capture summary\n")
            f.write(f"duration: {dur}s   lines: {OUT_JSONL}\n\n")
            for p in PHASE_ORDER:
                f.write(f"  {p:12s} {self.counts[p]:5d}\n")
            f.write("\nPhases with zero requests mean the journey did not reach "
                    "them during the capture window — that is a real observation, "
                    "not a failure to log.\n")
        print(f"[topfollow_capture] summary -> {OUT_SUMMARY}: {self.counts}")


addons = [TopFollowCapture()]
