#!/usr/bin/env python3
"""AVADO Electrum Server: runs Fulcrum on the AVADO Bitcoin Node, and its page.

- Gets its own RPC login from the Bitcoin Node app (which hands it out only to
  this app's container), writes it into fulcrum.conf (readable only by this
  app) and never shows it.
- Starts Fulcrum only when the Bitcoin node keeps the full history. On a
  space-saving (pruned) node the page says, in plain words, that the Electrum
  Server needs the full node.
- Shows the index progress, and the exact address and port to type into
  Sparrow, Electrum and other wallets.
- Fulcrum listens on 127.0.0.1 only; the wallet ports 50001/50002 are served
  by gate.py, which lets in only the home network, VPNs and other AVADO apps
  (the DAPPMANAGER asks the router to forward published ports to the internet).
"""

import collections
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

import avadoweb
import gate
import wamp
from avadoweb import log
from bitcoinrpc import RPC_IN_WARMUP, BitcoinRpc, RpcError, fetch_login

_HERE = os.path.dirname(os.path.abspath(__file__))
_VERSION_FILE = os.path.join(_HERE, "package-version")
VERSION = open(_VERSION_FILE).read().strip() if os.path.exists(_VERSION_FILE) else "dev"

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_DIR = os.path.join(DATA_DIR, "db")
STATE_DIR = os.path.join(DATA_DIR, "avado")
CONF_FILE = os.path.join(STATE_DIR, "fulcrum.conf")
CERT_FILE = os.path.join(STATE_DIR, "server.crt")
KEY_FILE = os.path.join(STATE_DIR, "server.key")
BANNER_FILE = os.path.join(STATE_DIR, "banner.txt")
PUBLIC_DIR = os.path.join(_HERE, "public")
GB = 1000 ** 3

# Fulcrum's database for Bitcoin mainnet, Nov 2026, with room to grow.
INDEX_SIZE_GB = 250
CHAIN_NAMES = {"main": "Bitcoin", "test": "testnet3", "testnet4": "testnet4", "signet": "signet", "regtest": "regtest"}


def env_int(name, default, low=None, high=None, env=os.environ):
    try:
        value = int(str(env.get(name, default)).strip())
    except ValueError:
        value = default
    if low is not None:
        value = max(low, value)
    if high is not None:
        value = min(high, value)
    return value


class Config:
    def __init__(self, env=os.environ):
        self.bitcoin_host = env.get("BITCOIN_HOST") or "DAppNodePackage-bitcoincore.avado.dnp.dappnode.eth"
        self.db_mem_mb = env_int("DB_MEM_MB", 2048, 200, 32000, env=env)
        self.tcp_port = env_int("TCP_PORT", 50001, 1, 65535, env=env)
        self.ssl_port = env_int("SSL_PORT", 50002, 1, 65535, env=env)
        # Where Fulcrum itself listens (127.0.0.1 only, behind gate.py)
        self.fulcrum_tcp_port = 60001
        self.fulcrum_ssl_port = 60002
        self.admin_port = 8000
        self.fulcrum = env.get("FULCRUM", "/usr/bin/Fulcrum")
        self.wamp_host = env.get("WAMP_HOST") or "wamp.my.ava.do"


def render_conf(config, user, password, rpc_port):
    lines = [
        "# Written by the AVADO Electrum Server app at every start: changes here are lost.",
        "datadir = %s" % DB_DIR,
        "bitcoind = %s:%d" % (config.bitcoin_host, rpc_port),
        "rpcuser = %s" % user,
        "rpcpassword = %s" % password,
        # Only the gate (gate.py) reaches these; wallets use tcp_port/ssl_port.
        "tcp = 127.0.0.1:%d" % config.fulcrum_tcp_port,
        "ssl = 127.0.0.1:%d" % config.fulcrum_ssl_port,
        "cert = %s" % CERT_FILE,
        "key = %s" % KEY_FILE,
        "admin = 127.0.0.1:%d" % config.admin_port,
        # A private server: never tell the public Electrum network about it.
        "peering = false",
        "announce = false",
        "db_mem = %d" % config.db_mem_mb,
        "banner = %s" % BANNER_FILE,
        "ts_format = utc",
    ]
    return "\n".join(lines) + "\n"


BANNER = "Your own Electrum Server on your AVADO, using your own Bitcoin node.\n"


def ensure_certificate():
    """A self-signed certificate made on this box (valid for 10 years), so
    wallets that pin the certificate are not asked again every year."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    log("making the server certificate")
    subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-sha256", "-nodes", "-x509", "-days", "3650",
                    "-subj", "/O=AVADO/CN=fulcrum.my.ava.do",
                    "-addext", "subjectAltName=DNS:fulcrum.my.ava.do",
                    "-keyout", KEY_FILE + ".tmp", "-out", CERT_FILE + ".tmp"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chmod(KEY_FILE + ".tmp", 0o600)
    os.replace(KEY_FILE + ".tmp", KEY_FILE)
    os.replace(CERT_FILE + ".tmp", CERT_FILE)


def certificate_fingerprint(path=CERT_FILE):
    """SHA-256 fingerprint of the server certificate, as wallets show it (AA:BB:...)."""
    try:
        with open(path, "r", encoding="ascii") as handle:
            der = ssl.PEM_cert_to_DER_cert(handle.read())
    except (OSError, ValueError):
        return None
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def admin_call(port, method, timeout=5):
    """One call to Fulcrum's admin port (JSON-RPC, one JSON object per line)."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}) + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > 4 * 1024 * 1024:
                break
    reply = json.loads(data.decode("utf-8"))
    if reply.get("error"):
        raise RuntimeError(str(reply["error"]))
    return reply.get("result")


def port_open(port, host="127.0.0.1"):
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


class Fulcrum:
    """Keeps Fulcrum running while it should run."""

    def __init__(self, config):
        self.config = config
        self.lock = threading.RLock()
        self.proc = None
        self.lines = collections.deque(maxlen=80)
        self.started_at = None
        self.last_exit = None
        self.restarts = 0
        self.next_start = 0
        self.progress_line = None
        self.wanted = True  # False while the index is being deleted

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def _reader(self, proc):
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode("utf-8", "replace").rstrip()
            # Fulcrum never logs the RPC password; the line goes to the container log as is.
            self.lines.append(line)
            # Only the index lines: "Block height N" is the node's height, not the index's.
            if "Processed height:" in line:
                self.progress_line = line
            print(line, flush=True)

    def start(self):
        with self.lock:
            if self.running():
                return
            args = [self.config.fulcrum, CONF_FILE]
            log("starting Fulcrum")
            self.lines.clear()
            self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.started_at = time.time()
            threading.Thread(target=self._reader, args=(self.proc,), daemon=True).start()

    def stop(self, timeout=600):
        with self.lock:
            proc = self.proc
            if proc is None or proc.poll() is not None:
                self.proc = None
                return
            log("stopping Fulcrum")
            proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        with self.lock:
            if self.proc is proc:
                self.proc = None

    def reap(self):
        """Notices a stop; returns True when it is time to start again."""
        with self.lock:
            if self.proc is not None and self.proc.poll() is not None:
                code = self.proc.returncode
                uptime = time.time() - (self.started_at or time.time())
                self.restarts = 0 if uptime > 600 else self.restarts + 1
                pause = min(300, 10 * (2 ** min(self.restarts, 5)))
                why = explain_exit(list(self.lines))
                self.last_exit = {"code": code, "at": time.time(), "why": why, "pause": pause}
                log("Fulcrum stopped (exit %s, %s); next try in %d s" % (code, why or "no reason given", pause))
                self.proc = None
                self.next_start = time.time() + pause
            return self.wanted and self.proc is None and time.time() >= self.next_start


def explain_exit(lines):
    text = "\n".join(lines[-40:])
    if re.search(r"No space left on device|disk full", text, re.I):
        return "disk"
    # Checked before the login: block hashes in these lines can contain "401".
    if re.search(r"corrupt|not consistent|inconsistent state|delete the datadir|full resynch|rocksdb.*error",
                 text, re.I):
        return "database"
    if re.search(r"txindex verification failed", text, re.I):
        return "txindex"
    if re.search(r"\b401\b|Unauthorized|authentication fail", text, re.I):
        return "login"
    return None


class App:
    def __init__(self, config):
        self.config = config
        os.makedirs(DB_DIR, exist_ok=True)
        os.makedirs(STATE_DIR, exist_ok=True)
        self.fulcrum = Fulcrum(config)
        self.login = None
        self.login_at = 0
        self.login_error = None
        self.node = {}  # last getblockchaininfo
        self.txindex = None  # getindexinfo()["txindex"], or {} when the node has none
        self.node_error = None
        self.rate = avadoweb.Rate(window=3600)
        self.lan_ip = None
        self.lan_ip_at = 0
        self.db_size = None
        self.db_size_at = 0
        self.cache = {"at": 0, "model": None}
        self.cache_lock = threading.Lock()

    # -- talking to the Bitcoin Node app
    def refresh_login(self, force=False):
        if self.login and not force and time.time() - self.login_at < 300:
            return self.login
        try:
            login = fetch_login(self.config.bitcoin_host, "fulcrum")
            changed = self.login is not None and self.login != login
            self.login = login
            self.login_at = time.time()
            self.login_error = None
            if changed:
                log("the Bitcoin Node app gave a new login; restarting Fulcrum")
                self.fulcrum.stop()
        except RpcError as err:
            self.login_error = {"code": err.code, "text": str(err)}
            if err.code == 403:
                log("the Bitcoin Node app refused the login:", err)
        return self.login

    def check_node(self):
        login = self.refresh_login()
        if not login:
            self.node, self.node_error = {}, "unreachable"
            return
        rpc = BitcoinRpc(self.config.bitcoin_host, login[2], login[0], login[1], timeout=8)
        try:
            self.node = rpc.call("getblockchaininfo")
            self.node_error = None
            self.txindex = (rpc.call("getindexinfo") or {}).get("txindex") or {}
        except RpcError as err:
            self.node = {}
            self.txindex = None
            if err.code == RPC_IN_WARMUP:
                self.node_error = "warmup"
            elif err.code == 401:
                self.node_error = "login"
                self.refresh_login(force=True)
            else:
                self.node_error = "unreachable"

    def should_run(self):
        # Fulcrum needs a full node with the transaction index (txindex=1).
        return bool(self.login) and bool(self.node) and not self.node.get("pruned") and bool(self.txindex)

    def loop(self):
        while True:
            try:
                self.check_node()
                if self.should_run():
                    if self.fulcrum.reap() and not self.fulcrum.running():
                        user, password, port = self.login
                        avadoweb.write_text(CONF_FILE, render_conf(self.config, user, password, port), mode=0o600)
                        self.fulcrum.start()
                elif self.node.get("pruned") and self.fulcrum.running():
                    log("the Bitcoin node is pruned: the Electrum Server cannot run on it")
                    self.fulcrum.stop()
                else:
                    self.fulcrum.reap()
            except Exception as err:  # keep the loop alive
                log("check failed:", repr(err))
            time.sleep(15)

    # -- actions
    def action_rebuild_index(self, _body):
        """Deletes Fulcrum's index and builds it again (after damage, e.g. a power cut)."""
        def rebuild():
            with self.fulcrum.lock:
                self.fulcrum.wanted = False
            self.fulcrum.stop()
            log("deleting the index to build it again (asked on the page)")
            shutil.rmtree(DB_DIR, ignore_errors=True)
            os.makedirs(DB_DIR, exist_ok=True)
            with self.fulcrum.lock:
                self.fulcrum.last_exit = None
                self.fulcrum.restarts = 0
                self.fulcrum.next_start = 0
                self.fulcrum.wanted = True
            self.rate = avadoweb.Rate(window=3600)
            self.db_size_at = 0

        threading.Thread(target=rebuild, daemon=True).start()
        return {"message": "The Electrum Server deletes its index and builds it again. This takes about 1 to 2 days."}

    # -- page
    def box_ip(self):
        if time.time() - self.lan_ip_at > 600 or (self.lan_ip is None and time.time() - self.lan_ip_at > 60):
            self.lan_ip = wamp.box_lan_ip(host=self.config.wamp_host)
            self.lan_ip_at = time.time()
        return self.lan_ip

    def index_size(self):
        if time.time() - self.db_size_at > 120:
            self.db_size = avadoweb.dir_size(DB_DIR)
            self.db_size_at = time.time()
        return self.db_size

    def gather(self):
        info = {"node": self.node, "nodeError": self.node_error, "loginError": self.login_error,
                "txindex": self.txindex,
                "running": self.fulcrum.running(), "lastExit": self.fulcrum.last_exit,
                "progressLine": self.fulcrum.progress_line}
        info["free"], _ = avadoweb.disk_free(DATA_DIR)
        info["indexSize"] = self.index_size()
        info["nodeInstalled"] = bool(avadoweb.resolve_ips(self.config.bitcoin_host))
        if info["running"]:
            try:
                info["fulcrum"] = admin_call(self.config.admin_port, "getinfo")
            except (OSError, ValueError, RuntimeError):
                info["fulcrum"] = None
            info["ready"] = port_open(self.config.fulcrum_tcp_port)
        info["lanIp"] = self.box_ip()
        info["fingerprint"] = certificate_fingerprint()
        return info

    def status(self):
        with self.cache_lock:
            if self.cache["model"] is not None and time.time() - self.cache["at"] < 4:
                return self.cache["model"]
        model = build_model(self.gather(), self.config, self.rate)
        with self.cache_lock:
            self.cache = {"at": time.time(), "model": model}
        return model

    def run(self):
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)
        ensure_certificate()
        with open(BANNER_FILE, "w", encoding="utf-8") as handle:
            handle.write(BANNER)
        # The wallet ports: only the home network, VPNs and AVADO apps get through.
        gate.Gate(self.config.tcp_port, self.config.fulcrum_tcp_port).start()
        gate.Gate(self.config.ssl_port, self.config.fulcrum_ssl_port).start()
        avadoweb.WebApp(PUBLIC_DIR, self.status, actions={"rebuild-index": self.action_rebuild_index},
                        version=VERSION, title="Electrum Server").serve(port=env_int("PORT", 80))
        threading.Thread(target=self.loop, daemon=True).start()
        while True:
            time.sleep(3600)

    def shutdown(self, *_args):
        log("shutting down")
        self.fulcrum.stop(timeout=600)
        sys.exit(0)


# ---------------------------------------------------------------- page model

def fmt_int(n):
    return "{:,}".format(int(n))


PROCESSED_RE = re.compile(r"Processed height: (\d+)")


def index_height(fulcrum, progress_line):
    """How far the index is. Fulcrum opens its admin port only after its first sync, so
    during the first 1 to 2 days the height comes from its "Processed height: N" log line."""
    height = (fulcrum or {}).get("height")
    if isinstance(height, int):
        return height
    match = PROCESSED_RE.search(progress_line or "")
    return int(match.group(1)) if match else None


def build_model(info, config, rate):
    node = info.get("node") or {}
    fulcrum = info.get("fulcrum") or {}
    free = info.get("free")
    model = {"title": "Electrum Server", "facts": [], "sections": [], "refresh": 10}
    ready = bool(info.get("ready"))
    blocks = node.get("blocks") or 0
    headers = node.get("headers") or blocks
    node_progress = float(node.get("verificationprogress") or 0)
    node_ibd = bool(node.get("initialblockdownload")) or (node and node_progress < 0.9999)
    height = index_height(fulcrum, info.get("progressLine"))
    network = CHAIN_NAMES.get(node.get("chain"), node.get("chain"))
    test_note = "" if not node or node.get("chain") == "main" else " (test network: %s)" % network

    if not info.get("nodeInstalled"):
        model["state"] = "error"
        model["headline"] = "Install the Bitcoin Node first"
        model["text"] = ["The Electrum Server works on top of the Bitcoin Node app, which is not installed. Install "
                         "\"Bitcoin Node\" from the AVADO store; this page then updates by itself."]
    elif (info.get("loginError") or {}).get("code") == 403:
        model["state"] = "error"
        model["headline"] = "The Bitcoin Node does not let the Electrum Server in"
        model["text"] = ["Restart the Bitcoin Node app and then this app in the AVADO Admin. If this stays, contact "
                         "AVADO support."]
    elif node.get("pruned"):
        model["state"] = "warn"
        model["headline"] = "The Electrum Server needs the full Bitcoin node"
        model["text"] = ["Your Bitcoin Node is in space-saving mode: it keeps only the newest blocks. The Electrum "
                         "Server needs the whole Bitcoin history to find the transactions of your wallet, so it cannot "
                         "run on it.",
                         "The full node and the Electrum Server together need at least 1.5 TB of free space. If your "
                         "AVADO has that much free now, open the Bitcoin Node page and choose \"Switch to the full "
                         "node\". Otherwise you can remove this app; it does nothing on a space-saving node."]
        model["sections"].append({"id": "node", "title": "Bitcoin Node", "links": [
            {"label": "Open the Bitcoin Node page", "href": "http://bitcoincore.my.ava.do", "style": "primary"}]})
        model["facts"].append({"k": "Free on your AVADO", "v": avadoweb.human_bytes(free)})
        return model
    elif node and info.get("txindex") == {}:
        model["state"] = "error"
        model["headline"] = "The Bitcoin node has no transaction index"
        model["text"] = ["The Electrum Server needs the transaction index of the Bitcoin Node, which a normal full node "
                         "on AVADO keeps. Check the settings of the Bitcoin Node app in the AVADO Admin (the EXTRA_OPTS "
                         "setting should be empty), or contact AVADO support."]
    elif not node:
        model["state"] = "working"
        model["headline"] = "Waiting for your Bitcoin node"
        model["text"] = ["Your Bitcoin node is starting. The Electrum Server begins as soon as the node answers."]
    elif not info.get("running"):
        last = info.get("lastExit") or {}
        model["state"] = "error" if last else "working"
        if last.get("why") == "txindex":
            model["state"] = "working"
            model["headline"] = "Waiting for your Bitcoin node's transaction index"
            model["text"] = ["Your Bitcoin node is still building its index of all transactions. The Electrum Server "
                             "starts by itself when it is done."]
        elif last.get("why") == "disk":
            model["headline"] = "The Electrum Server stopped: the disk is full"
            model["text"] = ["Make room on your AVADO by removing apps you no longer use. It tries again by itself."]
        elif last.get("why") == "database":
            model["headline"] = "The Electrum Server's index is damaged"
            model["text"] = ["This can happen after a power cut, or when the Bitcoin Node had to start its download "
                             "again. The index has to be built again from your node, which takes about 1 to 2 days. "
                             "Your coins are not affected: they are safe on your hardware wallet."]
            model["sections"].append({"id": "repair", "title": "Repair", "buttons": [
                {"action": "rebuild-index", "label": "Build the index again", "style": "primary",
                 "confirm": "The Electrum Server deletes its index and builds it again from your Bitcoin node. "
                            "Wallets cannot connect until it is done (about 1 to 2 days). Continue?"}]})
        elif last:
            wait = max(0, int(last.get("at", 0) + last.get("pause", 0) - time.time()))
            model["headline"] = "The Electrum Server is starting again"
            model["text"] = ["It stopped unexpectedly and starts again in %s." % avadoweb.human_duration(wait)]
        else:
            model["headline"] = "The Electrum Server is starting"
            model["text"] = ["This takes a moment."]
    elif ready and not node_ibd:
        model["state"] = "ok"
        model["headline"] = "Your Electrum Server is ready%s" % test_note
        model["text"] = ["Your wallet can now ask your own node about your coins. Type the address below into "
                         "Sparrow, Electrum or another wallet that supports your own Electrum server."]
    elif node_ibd:
        model["state"] = "working"
        model["headline"] = "Your Bitcoin node is still downloading the history"
        # Fulcrum indexes the blocks as the node downloads them (seen on the test box).
        if isinstance(height, int) and height > 0:
            index_note = "Electrum index: block %s" % fmt_int(height)
        else:
            index_note = "The Electrum Server indexes the blocks as they arrive"
        model["progress"] = {"percent": round(node_progress * 100, 2),
                             "left": "Bitcoin node: %.1f%% done" % (node_progress * 100),
                             "right": index_note}
        model["text"] = ["The Electrum Server needs a complete node. It builds its own index while and after the node "
                         "downloads; in total this takes about 2 to 4 days on an AVADO. You can close this page."]
    else:
        model["state"] = "working"
        model["headline"] = "Your Electrum Server is building its index%s" % test_note
        if isinstance(height, int) and blocks:
            frac = min(1.0, max(0.0, height / float(max(blocks, headers))))
            rate.add(frac)
            left = rate.seconds_left()
            model["progress"] = {"percent": round(frac * 100, 2),
                                 "left": "Block %s of %s" % (fmt_int(height), fmt_int(blocks)),
                                 "right": ("%s left" % avadoweb.human_duration(left)) if left else "Working out how long this takes"}
        model["text"] = ["It reads every block of your node once and notes which transactions belong to which address. "
                         "On an AVADO this takes about 1 to 2 days. Your wallet can connect when it is done."]

    if free is not None and free < 30 * GB and info.get("running"):
        if model.get("state") != "error":
            model["state"] = "warn"
        model.setdefault("text", []).append("Your AVADO has only %s of free space left." % avadoweb.human_bytes(free))

    facts = model["facts"]
    if isinstance(height, int):
        facts.append({"k": "Index up to block", "v": fmt_int(height)})
    if fulcrum.get("clients_connected") is not None:
        facts.append({"k": "Wallets connected now", "v": str(fulcrum.get("clients_connected"))})
    facts.append({"k": "Disk used by the index", "v": avadoweb.human_bytes(info.get("indexSize"))})
    facts.append({"k": "Free on your AVADO", "v": avadoweb.human_bytes(free),
                  "tone": "warn" if free is not None and free < 50 * GB else None})

    model["sections"].append(connect_section(info, config, ready and not node_ibd))
    adv = [
        {"k": "Fulcrum version", "v": str(fulcrum.get("version") or "Unknown")},
        {"k": "Network", "v": network or "Unknown"},
        {"k": "Port with SSL", "v": str(config.ssl_port)},
        {"k": "Port without SSL", "v": "%d (only for wallets without SSL, on your home network)" % config.tcp_port},
        {"k": "Certificate fingerprint (SHA-256)", "v": info.get("fingerprint") or "Unknown"},
        {"k": "Shared with the public Electrum network", "v": "No (private server)"},
    ]
    model["sections"].append({"id": "details", "title": "About this server",
                              "text": ["The server answers only wallets on your home network, the AVADO Wi-Fi or "
                                       "AVADO Remote Access. Anyone else on the internet is turned away, even if "
                                       "your router forwards the port. It is not announced to anyone."],
                              "advanced": adv})
    return model


def connect_section(info, config, ready):
    ip = info.get("lanIp")
    s = {"id": "connect", "title": "Connect your hardware wallet to your own node"}
    s["text"] = ["Type these into your wallet app (Sparrow, Electrum, Trezor Suite, BitBoxApp and others). Your "
                 "hardware wallet stays plugged into your computer as usual."]
    if not ready:
        s["text"].append("You can enter them now. The wallet connects as soon as the server is ready.")
    fields = []
    if ip:
        fields.append({"k": "Address", "v": ip, "copy": True})
    else:
        fields.append({"k": "Address", "v": "fulcrum.my.ava.do", "copy": True})
    fields.append({"k": "Port", "v": str(config.ssl_port), "copy": True})
    fields.append({"k": "SSL", "v": "On"})
    s["fields"] = fields
    host = ip or "fulcrum.my.ava.do"
    s["steps"] = [
        "Sparrow: open Settings (Preferences on a Mac), then Server. Choose \"Private Electrum\". Type the address "
        "and port above, switch \"Use SSL\" on and press \"Test Connection\". Accept the certificate when Sparrow asks.",
        "Electrum: open Tools, then Network. Switch off \"Select server automatically\" and type %s:%d:s as the "
        "server. Accept the certificate when Electrum asks." % (host, config.ssl_port),
        "Other wallets: look for \"custom server\", \"Electrum server\" or \"connect your own node\" in the settings "
        "and use the address and port above with SSL on.",
    ]
    after = []
    if ip:
        after.append("This address works on your home network. Away from home, with AVADO Remote Access on (or on "
                     "the AVADO Wi-Fi), use fulcrum.my.ava.do instead.")
    else:
        after.append("fulcrum.my.ava.do works when your computer is on the AVADO Wi-Fi or uses AVADO Remote Access. "
                     "On your home network, use the address your router shows for the AVADO.")
    s["after"] = after
    return s


if __name__ == "__main__":
    App(Config()).run()
