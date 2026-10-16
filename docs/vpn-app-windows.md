# PublicVPNList VPN for Windows: download the test beta

Published October 16, 2026 · Version 0.2.0 beta.1

**Available now:** download the Windows 11 x64 test beta from the official
website, with installation instructions, checksums and release sources.

- [Download and installation guide](https://publicvpnlist.com/vpn-app/windows/)
- [Download Windows x64 installer — EXE, 36.6 MiB](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.1/PublicVPNList-0.2.0-Windows-x64-TEST.exe)
- [SHA-256 checksums](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.1/SHA256SUMS)
- [Testing status and known limits](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.1/TESTING-STATUS.txt)

## Install and verify

Read the test-signing limitations below before installing. Download the EXE
and check it in PowerShell:

```powershell
Get-FileHash .\PublicVPNList-0.2.0-Windows-x64-TEST.exe -Algorithm SHA256
```

Expected SHA-256:

```text
69c618db2c500f10ba1b514f9007891655f86ee62d2edbfa771973eba1756a27
```

The installer is 38,405,624 bytes. A full public HTTPS download was verified
against the published checksum. The checksum list's Ed25519 signature was
also verified; that does not make the Windows publisher certificate trusted.

Run the installer and review the administrator prompt, then launch
PublicVPNList from the Start menu as your normal user. Installation does not
connect automatically. Select Connect and wait for the connection checks.
Disconnect and quit through the tray before updating or uninstalling.

The official page also links the
[checksum signature](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.1/SHA256SUMS.sig),
[release public key](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.1/release-public.pem),
[source and build input](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.1/publicvpnlist-windows-0.2.0-build-input.zip),
component sources, licenses and build instructions.

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
Windows connection acceptance in the
[published testing record](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.1/release-acceptance.json).
That record additionally reports armed reboot without automatic reconnection,
hibernate/resume and a virtual link interruption. Physical-device S3 sleep
and early-boot protection are not established by those tests.

## Signing and known limits

This is a **test release with no publicly trusted publisher signature**. The
installer uses a self-signed test certificate, has no trusted timestamp, and
its inner binaries are not Authenticode signed. Windows may warn or block it.
Do not install a test root certificate or disable security software.

OpenVPN and IPv6 transport endpoints are not enabled in this build. Filtering
may remain active after a service failure until an explicit disconnect or
internet recovery. Public server availability varies and operators may log
traffic; successful technical checks do not establish privacy or anonymity.

## Other ways to use PublicVPNList

Use the published [Linux beta](vpn-app-linux.md) or integrate the
[PublicVPNList API](publicvpnlist-api.md). For project information and contact
details, visit [PublicVPNList](https://publicvpnlist.com/).
