# PublicVPNList VPN for Windows 10 and 11: download beta.2

Updated October 23, 2026 · Version 0.2.0 beta.2

**Available now:** download the Windows 10/11 x64 test beta from the official
website, with installation instructions, checksums and release sources.

- [Download and installation guide](https://publicvpnlist.com/vpn-app/windows/)
- [Download Windows x64 installer — EXE, 36.6 MiB](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.2/PublicVPNList-0.2.0-Windows-10-11-x64-beta.2.exe)
- [SHA-256 checksums](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.2/SHA256SUMS)
- [Testing status and known limits](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.2/TESTING-STATUS.txt)

## Install and verify

Read the publisher-signing limitations below before installing. Download the EXE
and check it in PowerShell:

```powershell
Get-FileHash .\PublicVPNList-0.2.0-Windows-10-11-x64-beta.2.exe -Algorithm SHA256
```

Expected SHA-256:

```text
e560b9528180962c43ab5c3a8b1fddd360039fad4a1f39e08fd23c661b2ab148
```

The installer is 38,409,279 bytes. A full public HTTPS download was verified
against the published checksum. The checksum list's Ed25519 signature was
also verified; that does not establish a trusted Windows publisher.

Run the installer and review the administrator prompt, then launch
PublicVPNList from the Start menu as your normal user. Installation does not
connect automatically. Select Connect and wait for the connection checks.
Disconnect and quit through the tray before updating or uninstalling.

The official page also links the
[checksum signature](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.2/SHA256SUMS.sig),
[release public key](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.2/release-public.pem),
[source and build input](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.2/publicvpnlist-windows-0.2.0-build-input.zip),
component sources, licenses and build instructions.

## What the client does

The Windows desktop client is designed to select a public VPN server, establish
a system tunnel and check connectivity through it. A Windows service manages
the network connection; the desktop interface provides connection and recovery
controls.

The test build targets **Windows 10 22H2 (build 19045+) and Windows 11 x64 on Intel/AMD**. Windows Server, ARM and 32-bit Windows are outside this release's support.

## What changed in beta.2

The installer now accepts Windows 10 22H2 alongside Windows 11, fixing the
previous unsupported-Windows rejection before installation. Native build
preflight uses the same minimum build. The application, helper and VPN core
remain the accepted version 0.2.0; beta.2 identifies the compatibility package.

## Observed testing

On October 23, installation on a physical Windows 10 Pro 22H2 ThinkPad exited
successfully; service, protected core/configuration, IPC and normal desktop UI
checks passed. The owner tested the app and confirmed it works, then authorized
publication. This is not a new automated packet-capture or failure matrix.


The unchanged runtime's October 16 testing record reports a real VLESS + REALITY connection in a
Windows 11 Enterprise LTSC 2024 evaluation VM with Secure Boot and TPM enabled:
the exit IP changed, Google access worked and TikTok video playback was
observed. It also records exercised service/core failure and recovery paths,
installer approval and cancellation, and protected update/removal guards.

These observations cover the exercised environment and scenarios. They are
not an independent security audit or a guarantee of every Windows computer,
protocol, website or TikTok feature. Only VLESS + REALITY has completed live
Windows connection acceptance in the
[Windows 11 testing record](https://publicvpnlist.com/downloads/vpn/0.2.0-windows-beta.2/windows11-beta1-acceptance.json).
That record additionally reports armed reboot without automatic reconnection,
hibernate/resume and a virtual link interruption. Physical-device S3 sleep
and early-boot protection are not established by those tests.

## Signing and known limits

This is a **test release with no publicly trusted publisher signature**. The
beta.2 installer is unsigned, has no trusted timestamp, and its inner binaries
are not Authenticode signed. Windows may warn or block it.
Do not install a test root certificate or disable security software.

OpenVPN and IPv6 transport endpoints are not enabled in this build. Filtering
may remain active after a service failure until an explicit disconnect or
internet recovery. Public server availability varies and operators may log
traffic; successful technical checks do not establish privacy or anonymity.

## Other ways to use PublicVPNList

Use the published [Linux beta](vpn-app-linux.md) or integrate the
[PublicVPNList API](publicvpnlist-api.md). For project information and contact
details, visit [PublicVPNList](https://publicvpnlist.com/).
