# AVADO Electrum Server

An AVADO package that runs [Fulcrum](https://github.com/cculianu/Fulcrum), an
Electrum server, on the AVADO Bitcoin Node, with a plain-language page at
`http://fulcrum.my.ava.do`. Wallet apps such as Sparrow, Electrum, Trezor
Suite and BitBoxApp connect to it, so they ask the owner's own node about
their coins instead of a stranger's server.

Needs the Bitcoin Node package (`bitcoincore.avado.dnp.dappnode.eth`, repo
AVADO-DNP-BitcoinCore) in full mode.

## What it does

- **Gets its own login from the Bitcoin Node** (`/internal/rpc-login/fulcrum`,
  answered only to this app's container), writes it into `fulcrum.conf`
  (readable only by this app) and never shows it. That login may call only the
  RPC methods Fulcrum needs.
- **Runs only on a full node.** On a pruned node (or one without the
  transaction index) Fulcrum is not started and the page says, in plain
  words, that the Electrum Server needs the full Bitcoin node and how much
  free disk that takes.
- **The page shows the exact address to type into the wallet**: the box's
  address on the home network (asked from the DAPPMANAGER with `getParams`,
  read-only) or `fulcrum.my.ava.do`, port 50002 with SSL, plus step-by-step
  instructions for Sparrow and Electrum, the index progress and the
  certificate fingerprint (under Details).
- **A private server**: no peering, not announced to the public Electrum
  network. A self-signed certificate (10 years) is made on the box.
- **Repair button**: when Fulcrum reports a damaged index (power cut, or the
  node started its download again), the page offers "Build the index again".

Ports 50001 (plain) and 50002 (SSL) are published on the box so wallets on the
home network can reach it. The AVADO DAPPMANAGER asks the home router (UPnP)
to forward every published port to the internet, and Fulcrum has no list of
allowed callers, so Fulcrum listens on 127.0.0.1 only (ports 60001/60002) and
`build/app/gate.py` serves the wallet ports: it passes a connection on to
Fulcrum byte for byte (SSL stays end to end) only when it comes from a private
network (home network, AVADO Wi-Fi, AVADO Remote Access), the AVADO apps'
network 172.33.0.0/16, the VPN range 100.64.0.0/10 or the box itself. Docker
forwards published ports with DNAT, so the gate sees the caller's real
address; anyone else is disconnected at once.

Setting: `DB_MEM_MB` (Fulcrum's database memory, default 2048).

## Image

Based on Fulcrum's own image `cculianu/fulcrum` (pinned by digest), plus the
AVADO page and supervisor (Python standard library only, `build/app`; unit
tests run during the build). Runs as an unprivileged user.

**HTTPS.** The page also answers on https://fulcrum.my.ava.do (port 443) with the box's
`*.my.ava.do` certificate, the one the Admin and the other AVADO apps with https use (the
box's DAPPMANAGER serves it at http://dappmanager.my.ava.do; iso.ava.do is the second source).
Chrome tries https first ("Always use secure connections"), so without it Chrome showed "This
site doesn't support a secure connection". The certificate is used only when it is for
`*.my.ava.do`, valid for at least another hour and matches its key; until then the page stays
http only and it is checked every 5 minutes, after that daily. http works as before, also in
the Admin's Setup tab. `build/app/avadotls.py` (Python standard library only; the same file in every AVADO package with `avadoweb.py`).

## Licence and reuse

GPL-3.0 (see LICENSE). Fulcrum is GPL-3.0, Copyright Calin Culianu and
contributors; it is used unchanged from its official image.

## Development

```
cd build/app && python3 -m unittest discover -s tests
docker buildx build --platform linux/amd64 --load -t fulcrum-test -f build/Dockerfile .
```

Release after the Bitcoin Node is published in the store (store dependency).
Merge with a merge commit, not squash.
