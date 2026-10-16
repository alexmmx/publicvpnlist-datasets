# PublicVPNList VPN for Linux

Published October 16, 2026 · Version 0.1.8 beta

[Download and installation guide](https://publicvpnlist.com/vpn-app/)

PublicVPNList's desktop client selects public VPN servers, checks connectivity
through the tunnel and offers connection controls in the window and tray.

## Install

Choose DEB for compatible Debian/Ubuntu/Mint systems, or TAR.GZ for other
compatible distributions. Download packages and checksums from the official
page above.

For DEB, open a terminal in the download folder:

```sh
sudo apt install ./publicvpnlist-vpn_0.1.8_amd64.deb
publicvpnlist
```

For the generic archive:

```sh
tar -xzf publicvpnlist-vpn-0.1.8-linux-x64.tar.gz
cd publicvpnlist-vpn-0.1.8-linux-x64
python3 -I install.py --check
sudo python3 -I install.py
publicvpnlist
```

Follow the official dependency instructions first. Run the desktop app as your
normal user. Disconnect and quit before updating; use one installation format.

## Compatibility and status

Requires x86_64, glibc 2.35+, systemd, a graphical desktop and administrator
approval. VPN connectivity was tested on Ubuntu 24.04; other distribution
compatibility remains preliminary. ARM, 32-bit, musl and immutable systems are
outside this release's support.

The download page provides checksums, signatures, component sources and
licenses. Follow its recovery and removal instructions if needed.

Public servers may fail or log traffic; a connection check does not guarantee
anonymity. Read the [Privacy Policy](https://publicvpnlist.com/privacy-policy/).

For integrations, see the [API introduction](publicvpnlist-api.md). For the
other desktop platform, see the [Windows preview](vpn-app-windows.md).
