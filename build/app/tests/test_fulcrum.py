import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import avadoweb  # noqa: E402
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


class ConfTest(unittest.TestCase):
    def test_private_server(self):
        conf = main.render_conf(main.Config({}), "fulcrum", "s3cret", 8332)
        self.assertIn("peering = false", conf)
        self.assertIn("announce = false", conf)
        self.assertIn("bitcoind = DAppNodePackage-bitcoincore.avado.dnp.dappnode.eth:8332", conf)
        self.assertIn("admin = 127.0.0.1:8000", conf)
        self.assertIn("ssl = 0.0.0.0:50002", conf)
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
        self.assertIn("192.168.1.23:50002:s", " ".join(connect["steps"]))

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


if __name__ == "__main__":
    unittest.main()
