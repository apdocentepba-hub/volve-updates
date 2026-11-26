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
