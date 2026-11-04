"""Lets only nearby wallets reach the Electrum server (Python standard library only).

The wallet ports 50001 and 50002 are published on the box, and the AVADO
DAPPMANAGER asks the home router (UPnP) to forward every published port to the
internet. Fulcrum itself has no list of allowed callers, so it listens on
127.0.0.1 only and this gate passes connections on to it, byte for byte (SSL
stays end to end between the wallet and Fulcrum), but only from:

- private networks: the home network, the AVADO Wi-Fi and AVADO Remote Access
  (10/8, 172.16/12, 192.168/16, fc00::/7, link-local),
- the AVADO apps' own network 172.33.0.0/16 (the Bitcoin Explorer uses it;
  note that it is outside the private ranges above),
- the shared range 100.64/10 that VPNs such as Tailscale use,
- the box itself (127/8, ::1).

Anyone else is disconnected at once. Docker forwards published ports with
DNAT, so the gate sees the caller's real address.
"""

import ipaddress
import socket
import threading

from avadoweb import log

ALSO_ALLOWED = [
    ipaddress.ip_network("172.33.0.0/16"),  # dncore_network, where the AVADO apps run
    ipaddress.ip_network("100.64.0.0/10"),  # shared range (Tailscale and other VPNs)
]
MAX_CONNECTIONS = 200


def allowed_source(address):
    """True for callers on the home network, a VPN, the AVADO Wi-Fi or the box itself."""
    try:
        ip = ipaddress.ip_address((address or "").split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified or ip.is_multicast:
        return False
    if ip.is_loopback or ip.is_link_local:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and any(ip in net for net in ALSO_ALLOWED):
        return True
    return ip.is_private


def _pump(src, dst, end_dst=False):
    """Copies src to dst until src ends; then tells dst no more data comes."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        if end_dst:
            # Fulcrum hung up: end the wallet side too, so no connection lingers.
            try:
                dst.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class Gate:
    """Listens on listen_port and passes allowed connections on to 127.0.0.1:target_port."""

    def __init__(self, listen_port, target_port, host="0.0.0.0"):
        self.listen_port = listen_port
        self.target_port = target_port
        self.host = host
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.refused = 0
        self.sock = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.listen_port))
        self.sock.listen(64)
        threading.Thread(target=self._accept, name="gate-%d" % self.listen_port, daemon=True).start()
        return self

    def _accept(self):
        while True:
            try:
                client, addr = self.sock.accept()
            except OSError:
                return
            if not allowed_source(addr[0]):
                self.refused += 1
                if self.refused <= 5 or self.refused % 100 == 0:
                    log("port %d: refused a wallet connection from outside the home network (%s); %d so far"
                        % (self.listen_port, addr[0], self.refused))
                client.close()
                continue
            if not self.slots.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        upstream = None
        try:
            upstream = socket.create_connection(("127.0.0.1", self.target_port), timeout=5)
            upstream.settimeout(None)
            client.settimeout(None)
            back = threading.Thread(target=_pump, args=(upstream, client, True), daemon=True)
            back.start()
            _pump(client, upstream)
            back.join()
        except OSError:
            pass  # Fulcrum not listening yet (still indexing): the wallet tries again
        finally:
            for s in (client, upstream):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
            self.slots.release()
