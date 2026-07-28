# Security policy

Do not submit passwords, API tokens, private keys, credentials or complete VPN
profiles in public issues. Report sensitive findings through
https://publicvpnlist.com/contacts/.

Validation rejects credential patterns in repository files and generated
artifacts, including ZIP members. It also rejects path traversal, Unicode path
ambiguity, symlinks, special files, encryption, duplicate names, nested
archives, size/ratio bombs, local profile paths and executable OpenVPN hooks.

Documentation and tests may name forbidden patterns only through exact,
reviewable line fingerprints in `secret-scan-allowlist.json`. The allowlist
does not disable scanning for an entire directory.

A passed scanner is not evidence of redistribution rights, operator safety,
privacy or trust.
