## Plan: NTLM TLS-Unique Task 1

Validate the JDBC `tls-unique` implementation against real SQL Server Extended Protection in the isolated four-VM lab. Compare the existing reflection-based preview driver with the future API-based JDK/JDBC build, use controlled client-side CBT omission/corruption to prove SQL01 enforcement, treat the existing RELAY01 Layer-4 path as a one-session transport control, and use a synthetic two-channel simulator only to illustrate why independently terminated TLS sessions produce different bindings. Do not implement or forward real NTLM authentication messages between two TLS sessions.

**Steps**

### Phase 1 — Freeze inputs and establish observability
1. Record immutable test inputs before changing guest state: repository commit, SQL Server version/instance, current SQL Extended Protection and Force Encryption values, SQL certificate thumbprint, CLIENT01 JDK version/provider, JDBC jar names/SHA-256 hashes, and current TLS policy. Retrieve VM credentials only through `Secrets/Get-LabCredential.ps1`; never print or persist plaintext secrets.
2. Add an artifact-intake gate for the new API-based implementation (*blocks Phase 4 for that variant*): require the JDK directory, JDBC jar, source commit/build identifier, supported JDK version, and SHA-256 hashes. Until supplied, mark that variant `NOT RUN` rather than substituting the stock driver.
3. Make driver selection deterministic in `client-app/Run-Client.ps1`: accept explicit JDK/JDBC jar inputs and fail if ambiguous. Do not use the current “first matching jar” behavior. Print only safe provenance (Java version, jar filename/hash, config endpoint), never passwords or token/binding bytes.
4. Extend `client-app/src/MitmLabClient.java` observability to query and print `auth_scheme`, `encrypt_option`, client/server network addresses, and SQL session ID after login. Require `auth_scheme=NTLM` and `encrypt_option=TRUE`; fail the test otherwise. Add a correlation/run ID through `application_name` so SQL events can be tied to one test.

### Phase 2 — Add defensive CBT test controls
5. In the custom JDBC CBT branch, refactor binding acquisition behind a minimal internal provider boundary so both implementations can be tested consistently: existing reflection-based `tls-unique` and future public JDK API-based extraction. The normal production path must remain unchanged when no test mode is enabled.
6. Add test-only, opt-in controls compiled or enabled only for lab/test execution: `normal`, `omit`, and `corrupt-one-byte`. Apply the mutation to a private copy immediately before NTLM channel-binding hashing; never expose, log, return, or persist raw CBT or SSPI/NTLM data. Reject test controls unless an explicit lab enable flag is also present.
7. Add focused unit tests for provider selection, absent binding behavior, defensive copying, one-byte corruption, TLS-version eligibility, and cleanup between connections. Assert lengths/digests only with synthetic fixtures—never real TLS or authentication material.
8. Resolve the existing preview branch build blocker before using a rebuilt jar: replace direct compile-time dependence on `sun.security.jgss.krb5.internal.TlsChannelBindingImpl` for this NTLM-focused task or isolate Kerberos from the NTLM build. Do not rely solely on the untraceable prebuilt jar; record the exact source commit and reproducible Maven command.

### Phase 3 — Build an idempotent lab orchestrator
9. Create a host-side PowerShell test orchestrator that checks all four VMs, DNS, SQL port, canary database, low-privilege `MITMLAB\driveruser`, JDK/JDBC artifacts, and SQL service health before testing. Start only stopped VMs and record their initial state; do not alter AD or production systems.
10. Add TLS 1.2 preflight and enforcement suitable for `tls-unique`: verify the actual negotiated protocol rather than assuming it. If a temporary Schannel/SQL TLS policy change is required, export original values, restart only the required service/VM, validate TLS 1.2, and restore policy during cleanup. TLS 1.3 is explicitly out of Task 1 and must cause a skip/fail with a clear reason.
11. Wrap `sql-security/Set-SqlExtendedProtection.ps1` from the orchestrator to transition through `Off`, `Allowed`, and `Required`, waiting for SQL readiness after each restart. Capture the initial mode for reporting but, by decision, leave SQL01 in `Required` after all tests—even after failure.
12. Add timestamped evidence collection per case: client stdout/stderr and exit code, selected artifact hashes, SQL EP mode, SQL service readiness, relevant SQL/Application events (including 17806/`0x80090346` where produced), and connection metadata. Redact passwords and do not collect packet payloads or authentication tokens.

### Phase 4 — Execute the real SQL matrix
13. Run a smoke baseline with the stock JDBC jar under EP `Off` only to verify lab health; label it “no CBT capability baseline,” not a feature result.
14. For the reflection preview build, run direct CLIENT01 → SQL01 cases sequentially (*depends on Steps 5–12*):
    - EP Off + normal CBT: success, NTLM, encrypted, canary query succeeds.
    - EP Off + omitted/corrupt CBT: success is expected because SQL does not enforce CBT.
    - EP Allowed + normal CBT: success.
    - EP Allowed + omitted CBT: expected compatibility success; corrupt CBT outcome must be recorded and checked against SQL Server semantics rather than assumed.
    - EP Required + normal CBT: success; this is the primary proof of valid real `tls-unique` integration.
    - EP Required + omitted CBT: rejection.
    - EP Required + corrupt-one-byte CBT: rejection and correlated server evidence.
15. Repeat Step 14 for the new API-based JDK/JDBC build once artifact intake passes. Compare outcomes, negotiated TLS version, auth/encryption metadata, and failure classification against the reflection build; raw CBT values must never be compared or logged.
16. Run the existing Rust `mssql-tds/tests/test_extended_protection.rs` positive and corruption tests as an independent Schannel/SSPI control under EP Required. Require direct success with valid CBT and rejection with `MSSQL_TDS_TEST_CORRUPT_CBT=1`; keep this result separate from JDBC conformance.

### Phase 5 — Transport and two-channel educational controls
17. Enable the existing RELAY01 `netsh portproxy` path and run the normal CBT JDBC case under EP Required. Document and verify that this is opaque Layer-4 forwarding with one end-to-end CLIENT01 ↔ SQL01 TLS session; expected result is the same as direct connection. Capture two TCP legs on RELAY01 as topology evidence, but do not claim two TLS sessions or a CBT mismatch.
18. Extend `mssql-mock-tds` only with safe modes, in parallel with Steps 13–17 after design tests exist:
    - `transparent-relay`: byte-for-byte TCP forwarding with no TLS termination, packet inspection, or auth logging; use it as a second one-session transport control.
    - `synthetic-two-channel`: terminate two lab TLS sessions and exchange only synthetic challenge/binding identifiers using mock TDS messages or a dedicated test client. It must not accept, parse, forward, replay, or persist NTLM/SSPI tokens and must not claim compatibility with a real JDBC integrated-auth login.
19. Add Rust unit/integration tests for relay backpressure, half-close, size/time limits, cancellation, no payload logging, and exact byte preservation; add synthetic simulator tests proving binding A equals A and A differs from B. Test against local fixtures first, then run transparent mode in the isolated lab.

### Phase 6 — Analyze, clean up, and report
20. Classify every result as `PASS`, `FAIL`, `SKIP`, or `NOT RUN`, with expected versus actual outcome and one evidence pointer. A failure under EP Required is a passing security test only when the client was intentionally in omit/corrupt mode and server evidence correlates to that run.
21. In unconditional cleanup, disable temporary relays/firewall rules, stop only processes started by the orchestrator, remove transient configs/artifacts, restore temporary TLS policy, verify SQL health, and set SQL Extended Protection to `Required`. Preserve only redacted logs and artifact hashes.
22. Produce a comparison report for stock, reflection-preview, and API-based builds: reproducibility metadata, matrix results, SQL evidence, limitations, and follow-up for TLS 1.3 `tls-exporter`. Clearly distinguish real SQL enforcement, opaque transport controls, and synthetic two-channel education.

**Relevant files**
- `C:/Hyper-V/MITM-Lab/client-app/Run-Client.ps1` — deterministic JDK/jar selection, provenance, and test invocation.
- `C:/Hyper-V/MITM-Lab/client-app/src/MitmLabClient.java` — NTLM/encryption/session observability and assertions.
- `C:/Hyper-V/MITM-Lab/client-app/application.properties.example` — direct SQL template; add only non-secret test metadata/options.
- `C:/Hyper-V/MITM-Lab/client-app/application-relay.properties.example` — opaque relay transport-control template.
- `C:/Hyper-V/MITM-Lab/build/mssql-jdbc-channel-bindings/src/main/java/com/microsoft/sqlserver/jdbc/IOBuffer.java` — existing reflection-based TLS Finished extraction and future provider boundary.
- `C:/Hyper-V/MITM-Lab/build/mssql-jdbc-channel-bindings/src/main/java/com/microsoft/sqlserver/jdbc/NTLMAuthentication.java` — CBT hashing integration and guarded omit/corrupt test controls.
- `C:/Hyper-V/MITM-Lab/build/mssql-jdbc-channel-bindings/src/main/java/com/microsoft/sqlserver/jdbc/KerbAuthentication.java` — isolate current internal-API build blocker; Kerberos behavior remains out of Task 1.
- `C:/Hyper-V/MITM-Lab/build/mssql-jdbc-channel-bindings/pom.xml` — reproducible build/profile and test-only configuration.
- `C:/Hyper-V/MITM-Lab/sql-security/Set-SqlExtendedProtection.ps1` — existing EP mode transition and final Required state.
- `C:/Hyper-V/MITM-Lab/relay/Enable-SqlTcpRelay.ps1` — existing opaque Layer-4 control.
- `C:/Hyper-V/MITM-Lab/relay/Disable-SqlTcpRelay.ps1` — relay cleanup.
- `C:/Hyper-V/MITM-Lab/build/mssql-rs/mssql-tds/tests/test_extended_protection.rs` — independent real SQL valid/corrupt CBT control.
- `C:/Hyper-V/MITM-Lab/build/mssql-rs/mssql-mock-tds/src/main.rs` — safe simulator/transparent-relay CLI modes.
- `C:/Hyper-V/MITM-Lab/build/mssql-rs/mssql-mock-tds/src/server.rs` — keep mock-server behavior separate from relay/simulator state machines.
- `C:/Hyper-V/MITM-Lab/build/mssql-rs/mssql-mock-tds/src/tds_tls_wrapper.rs` — reuse only for mock TLS framing; never bridge auth between terminated channels.
- `C:/Hyper-V/MITM-Lab/cbt-demo/Invoke-SyntheticCbtDemo.ps1` — reference for synthetic same-channel/cross-channel assertions, noting it currently models `tls-server-end-point`, not real SQL `tls-unique`.
- `C:/Hyper-V/MITM-Lab/Secrets/Get-LabCredential.ps1` — DPAPI credential retrieval pattern.

**Verification**
1. Java unit tests cover binding provider modes and guarded fault injection with synthetic fixtures; Maven produces traceable jars for the selected JDK profiles.
2. Rust tests pass for `mssql-mock-tds`, including transparent byte preservation and synthetic two-channel mismatch; `cargo fmt` and `cargo clippy` pass for changed crates.
3. Every real JDBC success reports `NTLM`, `encrypt_option=TRUE`, the expected endpoint/run ID, and the canary row.
4. Under EP Required, normal direct CBT succeeds while omitted and one-byte-corrupt CBT fail; failures correlate with SQL01 events in the test time window.
5. The existing Rust real-SQL positive/corrupt tests independently reproduce accept/reject behavior.
6. Opaque RELAY01 and mock transparent-relay controls succeed under EP Required and are explicitly shown to preserve one end-to-end TLS session.
7. Synthetic two-channel tests show distinct bindings without handling NTLM; no logs or artifacts contain raw CBT, SSPI/NTLM tokens, or passwords.
8. Post-test checks confirm temporary listeners/rules/files are absent, SQL is reachable, and Extended Protection is `Required`.

**Decisions**
- Compare both the existing reflection preview and the future API-based build; the latter is gated as `NOT RUN` until artifacts and provenance are supplied.
- Task 1 targets NTLM with TLS 1.2 `tls-unique`; Kerberos and TLS 1.3 `tls-exporter` are excluded.
- Real SQL validation uses direct client-side normal/omit/corrupt controls, not an authentication relay.
- The existing `netsh portproxy` and any transparent mock relay are Layer-4 controls with one end-to-end TLS session.
- Any two-terminated-TLS demonstration is synthetic and must never forward real NTLM/SSPI messages.
- SQL01 is left with Extended Protection `Required` after cleanup.

**Further Considerations**
1. Before implementation, obtain the API-based JDK/JDBC artifacts, hashes, and source/build identifiers; otherwise only the reflection-preview leg can run.
2. Confirm SQL Server’s exact EP `Allowed` behavior for a present-but-invalid CBT from authoritative server documentation or measured evidence; do not encode an assumed result.
