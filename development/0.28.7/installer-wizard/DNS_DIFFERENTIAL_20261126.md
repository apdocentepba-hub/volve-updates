# DNS compatibility — evidence as of 2026-11-26

Status: **BLOCKED FOR RELEASE**. No production DNS changes authorized.

- Main candidate 7f3ea59: 7/8 workflows succeeded. Native-DNS guest run 45885277875, job 140134442611 failed with 10057; strict reboot and independent DNS restoration succeeded. Independent reference listener saw zero forced-TCP connections or queries; automatic UDP truncation/TCP fallback succeeded.
- Independent hosted Server 2022 reference run 45889804338, job 140149366974, commit 5723f11: build 20348, dnsapi.dll 10.0.20348.5866. Explicit IPv4 and IPv6 TCP both pass, configured normal IPv4 and dual-stack both pass, configured forced TCP fails with 10057 and no packets in both configurations. Original DNS restored. Neither motor nor single-stack configuration is necessary to reproduce the observed failure.
- Server 2025 reference run 45835188002 and actual motor run 45872979363 passed their configured TCP controls. This is not evidence for Windows 10/11.
- Native archive rehearsal 45888771357 passed real host census and before/after archive verification. Run 45889237082 passed all three string decode tests including native synthetic HKCU roundtrip, but actual census failed with generic diagnostic. No weakened gate; next test reports first failed stage and bounded reason code.

Next: diagnose the intermittent census failure, use independently verified Windows 10/11 environments if available, keep forced-TCP and release gates intact. Do not rerun the 10 GB nested guest without a new hypothesis. Do not expose DNS listeners on non-loopback interfaces as a workaround. No new product compatibility claims.

- Run 45890229214, job 140150797528, commit 2f48af3: 26/26 top-level tests passed, including actual Windows four-archive census, native NTFS and synthetic REG_SZ roundtrip. The previous intermittent census error did not recur; root cause is still unknown. No claim of full registry recovery or resolution of configured TCP.

- Runs 45897015190 (130262b) and 45898576102 (fba77a2): both jobs succeeded. Native synthetic REG_SZ present/empty/absent reconstruction into a second random HKCU fixture matched the independent original fingerprint and verified cleanup. The second run requires that evidence explicitly. No real browser policy restoration authorized.
- Native DNS API differential added on separate laboratory branch at fbfd24419a33f0806865b44a1c9ea3d5a41f8888: compare DnsQuery_W default/forced TCP against Resolve-DnsName using the existing loopback-only reference fixture; original restore checks and forced-TCP gate remain unchanged. Windows execution not yet verified. No release authorization.

- Native API differential run 45898850845, job 140179398434, commit fbfd244: native default DNS passes IPv4 and dual; native forced TCP returns 10057 with zero observed queries in both. Original DNS restored. This reproduces independently of both VOLVE and the PowerShell cmdlet; exact Windows root cause remains unknown. Added six option-variant controls at 1405419b7db4656a94ebd4a803b0898a2dc2a48f, retaining original full-option and release gates; execution pending.
