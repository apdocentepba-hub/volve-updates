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

## DNS policy census extension — 2026-11-27

New branch work/0287-dns-overrides-preflight-20261127 derives from the approved one-EXE baseline plus its evidence record (60a9c179). Candidate 83acc199/dd31106b/72cdb600/aacd2645 adds a fixed read-only Windows census for local and effective NRPT, known DoH server definitions and the 64-bit HKLM DNSClient group policy key, reporting bounded counts only and explicit DoH cmdlet availability. Strict schema rejects missing/null/duplicate/foreign/private fields and contradictory counts. Integrated pipeline compares eight canonical source files and requires both native and malformed-evidence tests before embedding. No actual DoH usage inference, no per-interface encrypted DNS restoration or full group policy preservation, no authorization. Missing cmdlet is not evidence of absence. Native validation pending. Microsoft Learn: Get-DnsClientNrptPolicy, Get-DnsClientDohServerAddress and ADMX_DnsClient. Nexo excluded. Release HOLD.

- Run 46030432120/job 140612545373: all 25 reported steps succeeded on tested commit aacd2645. Eight formatted source files verified; native override census local/effective NRPT 0/0, DoH command available, 12 known definitions, DNS policy key absent. New atomic candidate attaches fixed native before/after count checks to the same protected review mutex, projects counts only in the protected preview, retains explicit preservation=false and all no-install flags, and checks the JSON contract. Count equality is not content equality. New native integration pending; no authorization or release. Nexo excluded.

- #630 run 46034426039/job 140626113372 passed all 25 steps on b7da1c2; actual protected DNS override count marker present. New candidate extends comparison with four private SHA-256 digests of observed CIM NRPT/DoH typed property rows and machine DNS policy registry subtree typed values (bounded recursion and counts, ordinal row ordering). Preview only reports stable observed content boolean, not raw properties or fingerprints. Synthetic order/content/type discrimination and strict schema tests added; native execution pending. Not an exhaustive policy inventory, active DoH proof, restoration snapshot or install permit. Missing DoH command remains explicit. Nexo excluded.

- #631 run 46036955470/job 140634661513 passed all 25 steps on b78d9a7 including synthetic fingerprint discrimination and protected native content comparison. Candidate integrates the policy guard into the existing unexported SYSTEM DNS activation path (no new executable entrypoint): captures native baseline under transition lease before nonce consumption, conservatively refuses NRPT rules, existing machine DNS group policy key, missing DoH observer or incomplete fingerprints; compares private evidence before arm/health/commit and native writer, and never blocks independent emergency recovery. Known DoH definitions do not certify active encrypted DNS. Ten source files gated, deterministic guard regressions plus existing non-SYSTEM rejection. Native integrated validation pending. No actual activation or restore executed, existing publisher/watchdog prerequisites and release HOLD retained. Nexo excluded.

- While integrated #632 (46038781159) runs on 76e63d5, separate activation-order branch corrects an additional callback race identified in review. All policy/watchdog attestations precede final native adapter read; no lengthy attestation inside the writer wrapper. Recheck policy after inner arm attestation. Memory-only transaction tests target drift during inner attestation before the first write and after the first write, with recovery and no commit required. Separate bounded targeted CI, no real DNS mutation. Residual unavoidable external OS race between observation and write is not claimed eliminated. No production authorization, release, Nexo or client PC access.

- Activation order targeted run 46039298467/job 140642620421 on 725175b: all ten top-level tests PASS, including both before-first-write and after-first-write subcases, actual marker VOLVE_DNS_POLICY_DRIFT_DURING_ATTESTATION_TRANSACTION_RECOVERY and existing adapter TOCTOU regression. In-memory backend only, no OS DNS writes, no actual SYSTEM recovery. Commit d4587385 prepares integrated one-EXE workflow to require these regressions before embedding, with three explicit top-level PASS checks and new proof marker; integration not yet executed. Keep #632 running on its own exact commit, do not cancel or weaken. The new branch remains separate until integrated baseline status known. Nexo excluded.

- Candidate 2b24c846 enables the existing native fresh SYSTEM DNS53 pilot on the corrected activation-order branch, aligns journal overlay precedence with one-EXE reconstruction, and requires policy/order regressions before real motor compilation. No adapter writes in the SYSTEM startup pilot; earlier signed recovery tests retain their existing guarded lab scope. Native execution not yet verified. Release remains blocked on a connected production activation/controller/watchdog, authenticated durable complete recovery, configured resolver TCP and actual Windows client compatibility; no completion percentages are measured. Preserve earlier approved candidates; no Nexo, no production deployment.
