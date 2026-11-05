import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import avadoweb  # noqa: E402
import gate  # noqa: E402
import main  # noqa: E402

GB = 1000 ** 3


def node(**kw):
    base = {"chain": "main", "blocks": 920000, "headers": 920000, "verificationprogress": 0.999999,
            "initialblockdownload": False, "pruned": False}
    base.update(kw)
    return base


def model(**info):
    base = {"nodeInstalled": True, "free": 1500 * GB, "indexSize": 10 * GB, "fingerprint": "AB:CD"}
    base.update(info)
    return main.build_model(base, main.Config({}), avadoweb.Rate())


def main_view_words(m):
    """Words an owner sees without opening "Details"."""
    parts = [m.get("headline")] + list(m.get("text") or [])
    parts += [(m.get("progress") or {}).get(k) for k in ("left", "right")]
    for f in m.get("facts") or []:
        parts += [f["k"], f["v"]]
    for s in m.get("sections") or []:
        parts += [s.get("title")] + list(s.get("text") or []) + list(s.get("howto") or []) + list(s.get("steps") or [])
        parts += [s.get("after")] if isinstance(s.get("after"), str) else list(s.get("after") or [])
        for f in s.get("fields") or []:
            parts += [f["k"], f["v"]] + (["Copy"] if f.get("copy") else [])
        parts += [b["label"] for b in (s.get("links") or []) + (s.get("buttons") or [])]
        if s.get("more") or s.get("advanced"):
            parts.append(s.get("advancedTitle") or "Details")
    return len(" ".join(p for p in parts if p).split())


class ConfTest(unittest.TestCase):
    def test_private_server(self):
        conf = main.render_conf(main.Config({}), "fulcrum", "s3cret", 8332)
        self.assertIn("peering = false", conf)
        self.assertIn("announce = false", conf)
        self.assertIn("bitcoind = DAppNodePackage-bitcoincore.avado.dnp.dappnode.eth:8332", conf)
        self.assertIn("admin = 127.0.0.1:8000", conf)
        # Fulcrum itself is reachable only through the gate
        self.assertIn("ssl = 127.0.0.1:60002", conf)
        self.assertIn("tcp = 127.0.0.1:60001", conf)
        self.assertNotIn("0.0.0.0", conf)
        self.assertNotIn("fast-sync", conf)


class ModelTest(unittest.TestCase):
    def test_pruned_node_says_it_needs_the_full_node(self):
        m = model(node=node(pruned=True))
        self.assertEqual(m["state"], "warn")
        self.assertEqual(m["headline"], "The Electrum Server needs the full Bitcoin node")
        self.assertIn("1.5 TB", " ".join(m["text"]))
        self.assertEqual(m["sections"][0]["links"][0]["href"], "http://bitcoincore.my.ava.do")

    def test_ready_shows_exact_address(self):
        m = model(node=node(), running=True, ready=True, fulcrum={"height": 920000, "clients_connected": 1},
                  lanIp="192.168.1.23")
        self.assertEqual(m["state"], "ok")
        connect = [s for s in m["sections"] if s["id"] == "connect"][0]
        self.assertEqual(connect["fields"][0]["v"], "192.168.1.23")
        self.assertEqual(connect["fields"][1]["v"], "50002")
        more = " ".join(" ".join(m.get("steps") or []) for m in connect["more"])
        self.assertIn("192.168.1.23:50002:s", more)

    def test_ready_page_is_short(self):
        """Address, port, SSL and one Sparrow line on top; the rest behind "Details" (about 120 words)."""
        m = model(node=node(), running=True, ready=True, fulcrum={"height": 920000, "clients_connected": 1},
                  lanIp="192.168.1.23")
        self.assertEqual([s["id"] for s in m["sections"]], ["connect"])
        connect = m["sections"][0]
        self.assertEqual([f["k"] for f in connect["fields"]], ["Address", "Port", "SSL"])
        self.assertIn("Sparrow", connect["howto"][0])
        self.assertNotIn("steps", connect)
        self.assertLessEqual(main_view_words(m), 120)
        # still shown while the index is built
        m = model(node=node(), running=True, ready=False, fulcrum={"height": 460000}, lanIp="192.168.1.23")
        self.assertLessEqual(main_view_words(m), 120)

    def test_without_lan_ip_uses_avado_name(self):
        m = model(node=node(), running=True, ready=True, fulcrum={"height": 1})
        connect = [s for s in m["sections"] if s["id"] == "connect"][0]
        self.assertEqual(connect["fields"][0]["v"], "fulcrum.my.ava.do")

    def test_indexing_progress(self):
        m = model(node=node(), running=True, ready=False, fulcrum={"height": 460000})
        self.assertEqual(m["state"], "working")
        self.assertEqual(m["progress"]["percent"], 50.0)

    def test_node_still_downloading(self):
        m = model(node=node(verificationprogress=0.3, initialblockdownload=True), running=True, fulcrum={"height": 10})
        self.assertIn("still downloading", m["headline"])

    def test_node_without_txindex(self):
        m = model(node=node(), txindex={})
        self.assertIn("no transaction index", m["headline"])

    def test_txindex_not_ready_yet(self):
        m = model(node=node(), running=False, txindex={"synced": False},
                  lastExit={"why": "txindex", "at": 0, "pause": 10})
        self.assertEqual(m["state"], "working")

    def test_damaged_index_offers_rebuild(self):
        m = model(node=node(), running=False, txindex={"synced": True},
                  lastExit={"why": "database", "at": 0, "pause": 10})
        self.assertIn("damaged", m["headline"])
        repair = [s for s in m["sections"] if s["id"] == "repair"][0]
        self.assertEqual(repair["buttons"][0]["action"], "rebuild-index")
        self.assertIn("confirm", repair["buttons"][0])

    def test_node_not_installed(self):
        m = model(nodeInstalled=False)
        self.assertEqual(m["headline"], "Install the Bitcoin Node first")

    def test_login_refused(self):
        m = model(loginError={"code": 403, "text": "x"})
        self.assertIn("does not let", m["headline"])

    def test_no_secrets(self):
        m = model(node=node(), running=True, ready=True, fulcrum={"height": 5, "config": {"rpcpassword": "x"}})
        self.assertNotIn("password", repr(m).lower())


class ExitTest(unittest.TestCase):
    def test_login(self):
        self.assertEqual(main.explain_exit(["<BitcoinD> 401 Unauthorized"]), "login")

    def test_damaged_index(self):
        lines = ["<Controller> We have height 22, but bitcoind reports height 3. Possible reorg ...",
                 "<Controller> Applied undo for block 22 hash 53e63b34af736b299f954833793691d134628407cf1da0",
                 "<Controller> FATAL: Failed to rewind: Unable to retrieve undo info for 21",
                 "The database is now likely in an inconsistent state. To recover, you will need to delete the "
                 "datadir and do a full resynch. Sorry!"]
        self.assertEqual(main.explain_exit(lines), "database")

    def test_hash_with_401_is_not_a_login_problem(self):
        self.assertIsNone(main.explain_exit(["Processed block hash 00004019ab"]))

    def test_disk(self):
        self.assertEqual(main.explain_exit(["IO error: No space left on device"]), "disk")


class GateTest(unittest.TestCase):
    def test_home_vpn_and_avado_callers_get_in(self):
        for ip in ("192.168.1.23", "10.20.30.40", "172.16.0.9", "172.33.1.7", "100.101.102.103", "127.0.0.1",
                   "::1", "fd12:3456::1", "fe80::1%eth0", "::ffff:192.168.0.5", "169.254.1.1"):
            self.assertTrue(gate.allowed_source(ip), ip)

    def test_internet_callers_are_turned_away(self):
        for ip in ("8.8.8.8", "185.199.108.1", "172.34.0.1", "2001:4860::8888", "::ffff:8.8.8.8", "0.0.0.0",
                   "224.0.0.1", "", None, "not-an-ip"):
            self.assertFalse(gate.allowed_source(ip), ip)

    def test_passes_bytes_both_ways(self):
        import socket
        import threading
        backend = socket.socket()
        backend.bind(("127.0.0.1", 0))
        backend.listen(1)

        def echo():
            conn, _ = backend.accept()
            with conn:
                conn.sendall(conn.recv(100).upper())

        threading.Thread(target=echo, daemon=True).start()
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        g = gate.Gate(port, backend.getsockname()[1], host="127.0.0.1").start()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
            c.sendall(b"ping")
            self.assertEqual(c.recv(100), b"PING")
        g.sock.close()
        backend.close()


class CertTest(unittest.TestCase):
    def test_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
            try:
                subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-x509", "-days", "1",
                                "-subj", "/CN=test", "-keyout", key, "-out", cert], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (OSError, subprocess.CalledProcessError):
                self.skipTest("no openssl")
            fp = main.certificate_fingerprint(cert)
            self.assertEqual(len(fp.split(":")), 32)


class FramingTest(unittest.TestCase):
    """The Admin's Setup tab shows this page in a frame; other sites may not."""

    def test_only_the_admin_may_frame_the_page(self):
        import avadoweb
        csp = avadoweb.SECURITY_HEADERS["Content-Security-Policy"]
        self.assertIn("frame-ancestors 'self' http://my.ava.do https://my.ava.do;", csp)
        self.assertNotIn("X-Frame-Options", avadoweb.SECURITY_HEADERS)


class NodeDownloadTest(unittest.TestCase):
    """While the node downloads, Fulcrum already indexes; the page must not say "next"."""

    def test_index_height_shown_during_node_download(self):
        m = model(node=node(blocks=142000, headers=974000, verificationprogress=0.001, initialblockdownload=True),
                  fulcrum={"height": 72000}, running=True)
        self.assertEqual(m["progress"]["right"], "Electrum index: block 72,000")

    def test_no_height_yet(self):
        m = model(node=node(blocks=10, headers=974000, verificationprogress=0.0, initialblockdownload=True),
                  fulcrum={}, running=True)
        self.assertNotIn("next", m["progress"]["right"])

    def test_index_height_from_the_log_line_before_the_admin_port_opens(self):
        line = "[2026-11-04 19:22:09.124] <Controller> Processed height: 72000, 7.4%, 132.8 blocks/sec"
        self.assertEqual(main.index_height(None, line), 72000)
        self.assertEqual(main.index_height({"height": 80000}, line), 80000)
        self.assertIsNone(main.index_height(None, "<Controller> Block height 142417, downloading new blocks ..."))
        m = model(node=node(blocks=974000, headers=974000), fulcrum=None, running=True, progressLine=line)
        self.assertEqual(m["headline"], "Your Electrum Server is building its index")
        self.assertEqual(m["progress"]["left"], "Block 72,000 of 974,000")


if __name__ == "__main__":
    unittest.main()
