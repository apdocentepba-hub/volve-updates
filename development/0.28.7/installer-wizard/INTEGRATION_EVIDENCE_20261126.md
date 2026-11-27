# Consolidated candidate evidence — 2026-11-26

This branch combines the verified original-hosts capture/store, the verified
three-key browser capture/store and the isolated SYSTEM startup check.
No production install, deployment, live DNS change or restoration permit.

- Hosts: 11/11 on disposable native Windows, including real NTFS DACL checks
  and exact restoration of a synthetic file. [Run 45875790368](https://github.com/apdocentepba-hub/volve-updates/actions/runs/45875790368).
- Browser: 12/12, three read-only HKLM policy locations and real NTFS archive
  readback using synthetic payloads. [Run 45877202472](https://github.com/apdocentepba-hub/volve-updates/actions/runs/45877202472).
  Does not prove full registry restoration, other views, HKCU or enforcement.
- Main candidate ef38583: 6/8 workflow runs succeeded. The fresh SYSTEM
  pilot failed to listen on loopback, cleanup confirmed no hosts/DNS change.
  [Failed run 45876259075](https://github.com/apdocentepba-hub/volve-updates/actions/runs/45876259075).
- Isolated startup test dee524f: ready=true, process_alive=true,
  task_state=Running, tcp=2, udp=2; external DNS and TCP reuse tests passed,
  same-task restart passed, cleanup passed. [Run 45879311675](https://github.com/apdocentepba-hub/volve-updates/actions/runs/45879311675).
  This supports the readiness guard but does not establish the root cause
  of the intermittent earlier failure.
- Native Server 2022 configured TCP remains failed (10057), while strict
  reboot and two other jobs succeeded. [Run 45876258997](https://github.com/apdocentepba-hub/volve-updates/actions/runs/45876258997).
  The failing requirement is retained; no skip or waiver is authorized.

The existing fresh SYSTEM workflow now incorporates the exact tested final
step from dee524f. Its original triggers, permissions, reconstruction, compile
and required proof checks are retained. Combined-branch test execution is not
claimed. Windows 10/11 and complete production installer remain unverified.

## Integration candidate — 2026-11-27

The verified recovery branch at d6d9397112baab960a98c615194b3f25103c9ff7 is a direct descendant of candidate 7f3ea59cd5d795daf4e31af992965619c2ef4312 (79 commits ahead, zero behind). The integrated one-EXE workflow at 62bb3c67ae51e27ade1d30ecb7d35961bae08e72 now checks exact SHA-256 equivalence of seven updated motorupdate source/test files after reconstructing the pinned source, executes the two native recovery tests on that same source and requires ten distinct real evidence markers before compiling the actual embedded motor. This is not yet an execution result. Recovery evidence remains read-only/unarmed; neither test fixtures nor synthetic certificate are production credentials. The existing signed bundle, real motor embedding, preview, tamper rejection and no-install gates remain unchanged. No release authorized. The configured forced TCP failure is still unresolved (Server 2022); Windows 10/11 evidence and full recovery authorization remain required. Nexo excluded at user request.

- Integrated run #627 46027382420/job 140602168873: all preceding signing, seven-component staging and reconstruction steps succeeded; new integrity gate failed on browser_policy_inventory_windows.go before native recovery tests. Static review of apply_overlay.go confirms go/format.Source intentionally transforms source before writing, so comparing raw source hash was inappropriate. Candidate 7d08927d independently computes expected formatted bytes with the installed Go toolchain gofmt, compares exact bytes to the actual reconstructed source (never normalizes actual), prints seven verified SHA256 values and retains all two native tests/ten proof markers and release prohibitions. Pending execution. No claim that formatting is the only difference until the corrected comparison passes. No Nexo.

## Integrated one-EXE approval — 2026-11-27

- Run #628 [46027895131](https://github.com/apdocentepba-hub/volve-updates/actions/runs/46027895131), job 140603903249, exact tested commit `7d08927ddcc08eda69f41cd391bc8b3e951e5cdd`: SUCCESS. All 24 reported steps succeeded, on Microsoft Windows Server 2025 (`windows-2025-vs2026`). No skip or waiver. The seven canonical formatted source digests were verified byte-for-byte; native actual census (198.32 s) and bound transaction (177.56 s) passed; all ten mandatory native recovery evidence markers were emitted. The actual DNS motor compiled, was signed by an ephemeral CI-only certificate and embedded with the signed seven-component lab bundle in a single NSIS EXE. Actual motor Authenticode/hash verified and tampered motor rejected; DNS/hosts/tasks unchanged. Six-inventory protected preview, signed handoff and embedded tampering checks passed. The EXE was a disposable lab build, not a downloadable release or activated installer. Previous #627 source format discrepancy resolved.
- Release decision: **HOLD**. No client Windows 10/11 verification, no production trusted publisher credentials/authorization, no complete authorized recovery transaction, no release. Strict configured TCP remains failed on Server 2022 in independent differential #10. Do not generalize Server 2025 to Windows client compatibility or reuse old 7/8 workflow ratio as the new candidate's completion. Keep exact tested commit immutable as the baseline. Nexo excluded; no customer computer touched.
