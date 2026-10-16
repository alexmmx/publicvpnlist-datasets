# PublicVPNList VPN for Windows: test build preview

Published October 16, 2026 · Version 0.2.0 beta.1

**Publication status:** a Windows test build has been prepared. At publication
review, the intended website download page was unavailable (HTTP 404), so this
article does not offer a public installer download. This preview will be
updated when the download page and its release files are verified publicly.

## What the client does

The Windows desktop client is designed to select a public VPN server, establish
a system tunnel and check connectivity through it. A Windows service manages
the network connection; the desktop interface provides connection and recovery
controls.

The test build targets **Windows 11 x64 on Intel/AMD**. Windows 10, Windows
Server, ARM and 32-bit Windows are outside this release's support.

## Observed testing

The build's testing record reports a real VLESS + REALITY connection in a
Windows 11 Enterprise LTSC 2024 evaluation VM with Secure Boot and TPM enabled:
the exit IP changed, Google access worked and TikTok video playback was
observed. It also records exercised service/core failure and recovery paths,
installer approval and cancellation, and protected update/removal guards.

These observations cover the exercised environment and scenarios. They are
not an independent security audit or a guarantee of every Windows computer,
protocol, website or TikTok feature. Only VLESS + REALITY has completed live
Windows connection acceptance in the supplied testing record. Physical-device
sleep and early-boot protection are not established by those tests.

## Signing and known limits

This is a **test release with no publicly trusted publisher signature**. The
installer uses a self-signed test certificate, has no trusted timestamp, and
its inner binaries are not Authenticode signed. Windows may warn or block it.
Do not install a test root certificate or disable security software.

OpenVPN and IPv6 transport endpoints are not enabled in this build. Filtering
may remain active after a service failure until an explicit disconnect or
internet recovery. Public server availability varies and operators may log
traffic; successful technical checks do not establish privacy or anonymity.

## Available now

Use the published [Linux beta](vpn-app-linux.md) or integrate the
[PublicVPNList API](publicvpnlist-api.md). For project information and contact
details, visit [PublicVPNList](https://publicvpnlist.com/).
