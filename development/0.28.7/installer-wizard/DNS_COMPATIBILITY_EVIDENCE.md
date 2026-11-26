# VOLVÉ 0.28.7 — Evidence and release boundary (2026-11-26)

Candidate source: `a8e63c5e4aaee783e331b9256e9aec8cd86b554b`.
Evidence branch adds a laboratory workflow only; no motor source, production installer,
signature, or activation authorization is changed.

| Environment | Actual motor configured resolver | Independent reference | Status |
|---|---|---|---|
| Windows Server 2025 hosted | Five exact synthetic answers, including forced TCP and TCP-only upstream challenge; exact original DHCP DNS and hosts readback | Eight answer/wire checks | Lab IPv4 configured-path PASS |
| Windows Server 2022 hosted / isolated guest | Forced configured TCP fails 10057; explicit TCP, ordinary configured DNS, upstream truncation and recovery separately verified | Seven of eight; forced loopback configured TCP fails 10057 without VOLVE | Incompatible observed path; no activation |
| Windows 10 / 11 client | Not tested by this evidence | Not established | UNVERIFIED |

## Exact evidence
- [2025 actual motor ephemeral process](https://github.com/apdocentepba-hub/volve-updates/actions/runs/45872979363/job/140092859002), commit `ef33f93b938ca1bbcd639b37a57fd46203b5a509`: five distinct expected A answers (explicit normal, explicit TCP, configured normal, configured TCP, configured truncation), original DNS restored=true, production_authorized=false. IPv4 adapter changed temporarily; motor listeners were checked on both loopback families. No persistent task, no end-user installation or SYSTEM identity claim. The normal explicit query was not independently packet-captured.
- [2025 independent reference](https://github.com/apdocentepba-hub/volve-updates/actions/runs/45835188002/job/139962060076): 8/8 answers and corresponding wire observations, original DNS restored.
- [2022 independent reference](https://github.com/apdocentepba-hub/volve-updates/actions/runs/45835593474/job/139963475319): 7/8; forced TCP on configured IPv4 loopback returns 10057 with no reference traffic; configured local-interface address succeeds. This does not authorize binding a product resolver to a LAN address.
- [2022 isolated actual motor](https://github.com/apdocentepba-hub/volve-updates/actions/runs/45865140236/job/140066071517): forced configured TCP fails, explicit dual-stack transport and upstream truncation pass, 5/5 restoration regressions pass. Preserve failure as evidence; do not rewrite the gate to return success.
- [Installer preview](https://github.com/apdocentepba-hub/volve-updates/actions/runs/45837759614/job/139971051023): signed CI bundle and read-only inspection pass; configured_resolver_tcp_verified=false; no production installation.

## Acceptance boundaries
A successful Server 2025 observation is not proof of Windows 11 compatibility.
Do not use a build number, a cached test receipt, or explicit-server TCP success as
an installation permit. Keep loopback isolation and preserve the user's ability
to repair or remove software. No production activation without informed consent,
verified original configuration, recovery independent of the installer, live
configured-resolver health and rollback if verification fails. Do not change
the legacy failing result or repeat the identical 2022 guest without a new
hypothesis.

Next evidence required: client Windows 10/11 disposable environments, configured
resolver with both address families, actual installation and recovery including
interruption, and production publisher signature. Existing hosted runner is not
a substitute for those client environments. NO RELEASE.
