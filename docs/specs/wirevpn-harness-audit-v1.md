# WireVPN Deterministic Harness and Bash Audit Specification

Status: Accepted
Version: 0.1
Implementation authorized: W1 only, after the specification-only commit
Owner acceptance: Accepted on 2026-10-27
Independent review: PASS after repair and re-review

The key words MUST, MUST NOT, SHOULD, and MAY are normative. A phase or specification does not authorize implementation, publication, deployment, live testing, or operational action by itself.

## 1. Purpose

Define a WireVPN-owned manifest and deterministic, nonprivileged test harness for characterizing the existing Bash implementation, auditing its complete executable surface, and establishing language-neutral behavior vectors for a later Go rewrite.

The first implementation is project test infrastructure and **validated external project configuration**. It is not a generic-kernel project pack, a generic check adapter, a production sandbox, or evidence that an agent runtime is governed by the general agent harness.

The campaign order is binding:

1. Accept and commit this specification.
2. Build and validate the manifest and deterministic harness.
3. Complete and independently review the Bash audit.
4. Write a separate Go rewrite specification informed by accepted audit dispositions.
5. Implement and test Go only under separate authorization.

A generic-kernel shadow binding is independent later work and MUST NOT delay or be fabricated into the project-owned harness.

## 2. Authority and phase gates

| Phase | Scope | Entry requirement | Exit does not authorize |
|---|---|---|---|
| W0 | This specification and its review record | Owner authorization for specification work | Implementation or publication |
| W1 | Manifest, runner, fakes, fixtures, initial vectors, and CI | Owner acceptance of W0 and separate W1 authorization | Complete audit, push, merge, or release |
| W2 | Complete Bash characterization and audit | W1 exit evidence and separate W2 authorization | Go implementation, Bash repair, or publication |
| W3 | Go specification, review, and owner acceptance | Accepted W2 audit and separate W3 specification authorization | Go implementation or live testing |
| W4 | Go implementation and synthetic testing | Accepted W3 specification and separate W4 implementation authorization | Live testing, deployment, migration, or cutover |
| W5 | Optional generic-kernel shadow binding | Separate generic prerequisites and W5 authorization | Runtime governance, production action, or publication |

Each phase requires exact-source verification and an explicit owner transition. A local commit, branch push, merge, release, deployment, and operational cutover are separate events. The existing public repository is the intended home for accepted sanitized artifacts, but no artifact is published without separate authorization.

## 3. Exact baselines

### 3.1 Product baseline

Repository: `linkvectorized/wirevpn`
Branch baseline: `main`
Commit: `01143e05ce105ab42fec5fd7b0bacaac49ad2405`

| Source | Bytes | SHA-256 |
|---|---:|---|
| `server_setup.sh` | 12031 | `0facd517571e53754992b62fb163698d690fe1fc3779813c258b33e670dfb3f5` |
| `adguard_setup.sh` | 12316 | `299b60a63525f7526267047f3b2035e991956349b1c95ecd6906203bf47f9cb5` |
| `client_setup.sh` | 31514 | `c7032118aa94a24b1115ca1c22afb7f119adca7c7627757bd6eea14258d2aad2` |
| `mobile_peer.sh` | 9518 | `a7b5d1b020fd06a3534fb1febf209d4904a538912cd70a48ed1d01e19a9e8b2d` |
| `wirevpn.sh` | 9819 | `89f0c84dc96bffb60bed68b743c231a109a07243a953a579a91a801ef5eb110e` |
| `wirevpn-connect.sh` | 5651 | `c8c0010279eddfe57628f73295a949383e0f1c852322be9433cb859694c85b84` |

The complete audit surface also includes `README.md`, relevant `.gitignore` rules, generated service/configuration content, remote heredocs, embedded Python, and historical fixes used as audit leads. Their exact source identities MUST be included in the W1 source manifest.

### 3.2 Generic references

- General Agent Harness Specification: frozen v1.3.1, SHA-256 `1f61a127e4a1ae5222adb62ffa8113b075172f5b1cfca138c874436b6b9a53b1`.
- Informational generic kernel commit: `4b619fddd7e3edaae19312d1dea48898b1397afa`.

These references do not establish a WireVPN kernel binding. The generic kernel currently provides only the `artifact_equals_input` deterministic check kind and no project-pack loader or general named host-command check adapter. Generic source MUST NOT be copied into WireVPN.

## 4. Goals and non-goals

### 4.1 Goals

- Bind every result to exact source, fixture, vector, runner, toolchain, and report identities.
- Exercise Bash behavior without real secrets, root execution, external network access, or host configuration mutation.
- Preserve evidence of safety behavior, including fail-closed DNS and IPv6 handling, key and peer preservation, and reruns.
- Detect defects and ambiguous behavior before defining Go parity.
- Reuse the same semantic vectors for Bash characterization and later Go tests.
- Make required missing, stale, malformed, or failed evidence visible.
- Keep public artifacts sanitized and traceable to private raw evidence without publishing that evidence.

### 4.2 Non-goals

- Reading, copying, hashing, or testing real client configurations, backups, private keys, VPS inventory, or AdGuard credentials.
- Real SSH, SCP, DNS, public-IP, AdGuard, package-download, or blocklist requests.
- Root execution, actual privilege escalation, package installation, firewall changes, service control, or host network changes.
- Production verification, deployment, migration, operational recovery, or cutover.
- Full IPv6 tunneling, Windows support, or unrelated platform expansion.
- Go implementation before W2 exits and a separate Go specification is accepted.
- Arbitrary shell execution through a manifest or agent tool.
- Claims of same-user isolation, a tamper-proof evidence store, a production sandbox, or automatic agent-session governance.
- Generic-kernel modification, publication, optional modules, or real publication adapters.

## 5. Terminology and evidence limits

**Validated external project configuration** means WireVPN-owned configuration validated by WireVPN tooling. It does not mean the generic kernel loads it as a pack.

**Instrumented characterization** means executing a transformed copy of verified source against synthetic state. It does not mean running the canonical script in its real environment.

**Static evidence** concerns source bytes and relationships without executing behavior.

**Synthetic behavior evidence** concerns instrumented source and fake dependencies. It is not live-platform proof.

**Public curated evidence** is a sanitized report suitable for the repository. **Raw evidence** includes transcripts, operation logs, temporary trees, and diagnostic output and remains owner-only.

**Baseline observation** is a non-authoritative prediction or record of what the current Bash does. **Required-contract assertion** is an independently reviewed statement of the behavior required for safety, compatibility, or an accepted intentional change. An observed defect MUST NOT be written into a required-contract assertion.

**Execution health** records whether a bounded case reached every required observation and assertion with valid instrumentation, fakes, containment, and evidence. **Contract verdict** records whether the observed behavior satisfies the required-contract assertions. These axes are never conflated.

A green synthetic result MUST NOT be described as production safety. A red Bash contract verdict MAY be the correct final characterization of a defect; it MUST NOT be converted into an expected pass or skipped. Changing a required-contract assertion to accommodate an observed defect invalidates dependent evidence and requires independent finding disposition.

## 6. Audit surface and behavior contract

### 6.1 `server_setup.sh`

Cover public-IP validation and retries, package failures, existing and missing keys, live/file key mismatch, live and file backups, peer preservation, configuration rendering, default-route detection, forwarding, service enable/start/restart/active checks, firewall changes, client rendering, file modes, and partial failures.

The existing server and client keys MUST survive reruns. Existing peer blocks MUST NOT be silently discarded. A live/file key mismatch MUST stop before destructive configuration mutation, apart from explicitly characterized backup/synchronization writes.

### 6.2 `adguard_setup.sh`

Cover supported and unsupported architectures, existing installations, configuration and credential preservation, port-53 conflicts, download/extract failures, archive layout and identity, service installation and restart, setup API readiness and responses, upstream DNS, blocklist failures, firewall restrictions, DNS verification, secret output, and cleanup.

A rerun MUST preserve existing configuration, password, and blocklists. A fresh run MUST NOT print success when required setup or service verification failed. Public exposure claims require evidence about the complete firewall/service configuration, not only individual `ufw allow` commands.

### 6.3 `client_setup.sh`

Cover configuration discovery, bounded fallback search, macOS and Linux package branches, sudo preflight, existing and self-registered devices, SSH registration, peer address allocation, config retrieval, backups and modes, Homebrew/`wg-quick` compatibility, launchd and systemd installation, immediate activation, verification, and failure recovery.

The embedded `wirevpn` and `wirevpn-connect.sh` payloads MUST be compared byte-for-byte with their standalone sources at the baseline. Any later drift MUST fail the static payload gate. Remote heredocs are executable audit source and MUST be captured and characterized, not ignored as opaque SSH input.

### 6.4 `mobile_peer.sh`

Cover argument cardinality, add/remove parsing, peer names containing empty input, traversal, whitespace, shell metacharacters, option-like text, and extreme lengths; configuration discovery and endpoint parsing; overwrite/removal confirmation; SSH preflight; allocation collisions and exhaustion; live/file/config update ordering; QR and package failures; partial add/remove state; and local/server divergence.

The embedded removal Python is in scope. Characterization MUST establish whether live peer removal, persistent config removal, key deletion, and local deletion remain reconciled after every failure boundary.

### 6.5 `wirevpn.sh`

Cover `up`, `down`, `status`, invalid and extra arguments, interface selection, already-active and stale state, macOS and Linux branches, DNS parsing, DNS health, public-IP reporting, signal/daemon interaction, concurrent invocation, IPv6 state, and all teardown/restore failures.

The managed CLI contract is `wirevpn up|down|status`. The audit MUST distinguish contractual exit/output semantics from incidental colors and prose.

### 6.6 `wirevpn-connect.sh`

Cover stale DNS cleanup, boot-time IPv6 healing, network wait and exhaustion, missing `wg-quick`, activation failure, DNS health retries and failure, resident shutdown, signals, and restoration failure. Tests MUST bound the resident loop and virtualize sleeps.

### 6.7 Documentation and history

Every README claim about re-entrancy, boot safety, fail-closed behavior, peer uniqueness, AdGuard exposure, restoration, and recovery MUST map to evidence or a documentation finding. Historical fixes are leads only. The following require fresh characterization:

- Public-IP validation, timeouts, backups, sudo and service failure handling.
- Existing key/peer/AdGuard preservation and live/file mismatch handling.
- macOS stale DNS after reboot and managed teardown blackout prevention.
- Non-AdGuard DNS health-target parsing.
- IPv4-only routing with IPv6 disable/restore leak protection.

Full IPv6 tunneling remains unimplemented and out of scope.

## 7. Data classification and denied surfaces

| Class | Examples | Rule |
|---|---|---|
| Public | Canonical repository source, synthetic vectors, sanitized reports | Eligible for accepted public commit |
| Internal | Runner configuration, synthetic operation logs, exact local evidence metadata | Private unless curated |
| Restricted | Real configs, keys, endpoints, credentials, host inventory, raw terminal/SSH material | Never accepted as harness input or public evidence |

The runner MUST deny real runtime configuration directories, real HOME fallback searches, live `/etc/wireguard`, `/opt/AdGuardHome`, system service paths, and any symlink or path resolution escaping its synthetic roots. It MUST NOT inspect the owner’s local WireVPN configuration directory to prove that denial.

Canonical private-evidence, repository, instrumentation, temporary, and public-report roots MUST be non-overlapping and MUST NOT alias one another through symlinks or other filesystem indirection. Raw CI evidence MUST NOT be uploaded as an artifact. Overlap, redirection, or an unvalidated evidence filesystem fails closed.

Tests use synthetic keys, addresses, credentials, and `.fixture` files. Secret canaries MUST be unique synthetic values and MUST cause failure if emitted outside an explicitly allowed synthetic output assertion. Real-looking secret material SHOULD NOT be copied from external examples.

The host-side runner and instrumented source are trusted test code; the harness is not a security boundary against a malicious operator or compromised kernel. OS-enforced per-case containment is nevertheless required to prevent accidental process-tree network access or host writes; trust and PATH shims are not containment.

## 8. Project configuration

### 8.1 `harness/project.json`

The project manifest MUST use schema `wirevpn.external-project-config/1.0` and a corresponding strict JSON Schema. It MUST contain:

- Manifest/schema versions and `kind: validated-external-project-configuration`.
- Product baseline commit and a complete exact source-file manifest with size, SHA-256, and origin.
- Entrypoint and embedded-payload identities.
- Allowed source, fixture, vector, and output roots.
- Denied private-path classes and prohibited input classes.
- Runner, vector bundle, check inventory, and toolchain version/digest bindings.
- Required check IDs and invalidation dependencies.
- Data-class and public-report rules.
- Empty optional capability list.

It MUST NOT contain an `enabled` field, generic lifecycle transitions, approval grants, kernel receipts, arbitrary command strings, or project-pack conformance claims.

Unknown fields, invalid hashes, duplicate paths, absolute source paths, traversal, symlinks, missing files, and private-path references MUST fail closed.

### 8.2 `harness/checks.json`

The check inventory selects named, installed suites and exact vector bundles. It MUST bind check ID, version, runner digest, vector digest, toolchain, required/advisory status, output schema, and invalidation dependencies.

It MUST NOT accept model-supplied argv, shell fragments, executable paths, environment overrides, or arbitrary host commands. Adding a check requires reviewed source and a new content binding.

## 9. Deterministic runner

### 9.1 Execution and containment boundary

The runner uses the Python standard library and is invoked directly by a developer or CI. It is not exposed as an agent tool.

Every case receives fresh synthetic client/server/state/HOME roots, a scrubbed environment, fixed locale and timezone, virtual time, fixed input, and scripted command outcomes. Execution, output, iterations, and retries MUST be bounded. Temporary evidence MUST be written only to the approved private evidence root.

Every behavior case MUST run inside an explicitly versioned, OS-enforced per-case containment profile that:

- Denies inbound and outbound network access to the entire process tree.
- Denies writes outside approved synthetic roots and the case’s private evidence directory.
- Denies reads of restricted host paths and prevents inherited-descriptor access to them.
- Prevents privilege escalation, new privileges, setuid execution, and sandbox-profile changes by the child.
- Is inherited by every child, including Bash, embedded Python, archive tools, SSH-captured payloads, and signal/schedule actors.
- Runs in a separately managed process group/session, closes unintended inherited descriptors, and terminates and reaps the complete process tree after completion, timeout, interruption, or resident-loop testing.

Each supported operating system MUST have a reviewed containment adapter and positive/negative conformance probes. Linux and macOS behavior lanes MUST use their named enforced profiles; an unavailable, unverifiable, or unsupported profile yields `NOT_RUN` and blocks behavior-dependent completion. Static checks MAY still run. Instrumentation and fake commands provide determinism and fidelity, not the security/containment boundary.

Containment self-tests MUST include direct shell writes, embedded-Python filesystem APIs, crafted archive entries, symlink/hardlink escapes, inherited descriptors, child-process escapes, socket attempts, and process-tree cleanup. They MUST prove denial without reading real private material.

The runner MUST refuse:

- Real root privileges or any actual `sudo` escalation.
- `/`, the canonical repository, the owner’s real HOME, or a private runtime directory as a sandbox or evidence root.
- Real network tools, absolute host executables not explicitly transformed, and unscripted commands.
- Symlink/path escapes and writes outside synthetic roots.
- Missing source bindings, unknown vectors, duplicate IDs, or unbounded loops/timeouts.

### 9.2 Instrumentation

PATH shims alone are insufficient because the scripts contain absolute paths and root checks. The instrumenter MUST:

1. Verify each original source file against the accepted source manifest.
2. Copy source into a fresh temporary instrumentation root.
3. Apply only enumerated substitutions for synthetic absolute roots, EUID observation, absolute executable paths, and timing.
4. Require exact replacement counts and reject unrecognized transformations.
5. Emit a transformation record and transformed-source digest.
6. Execute only the transformed copy with a fixed Bash binary and arguments.

Canonical source remains untouched and is separately checked statically. Captured SSH heredocs and generated scripts MUST undergo equivalent source accounting before any synthetic execution.

Instrumentation fidelity is itself an audit risk. Each transformation MUST have self-tests proving that only intended bytes changed and that unmapped privileged, network, or host paths fail closed.

### 9.3 Fake commands and state

For ordinary single-actor cases, fakes MUST match exact argv and call order. Broad regular expressions or “any command succeeds” behavior is prohibited. Unexpected, missing, extra, and duplicated calls MUST fail. Multi-actor cases use the bounded schedules and partial-order rules in §9.4 rather than weakening single-actor matching.

Fakes cover, as applicable:

- Network and remote operations: `curl`, `ssh`, `scp`, `ping`, `dig`.
- WireGuard and system state: `wg`, `wg-quick`, `systemctl`, `launchctl`, `sysctl`.
- macOS network state: `networksetup`, `dscacheutil`, `killall`.
- Packages, firewall, archives, and architecture: apt/dnf/pacman, `brew`, `ufw`, `ip`, `ss`, `tar`, `openssl`, `uname`.
- Privilege, QR, and timing: `sudo`, `qrencode`, `sleep`, `date`, `clear`.

Fake `sudo` never elevates. Fake network commands never open sockets. Fake SSH captures remote payloads and permits only separately instrumented synthetic execution. Fake SCP operates only between synthetic roots. State models cover files, peers, tunnel, DNS, IPv6, services, and command outcomes.

Vetted local text/file utilities MAY operate only inside the synthetic environment. Their versions and paths are toolchain inputs. No general host shell is exposed through check configuration.

### 9.4 Shared semantic vectors and implementation bindings

A **shared semantic vector** is language-neutral and MUST declare:

- Schema version, stable ID, platform, arguments, and applicability.
- Synthetic fixture and initial filesystem/service/network state identities.
- Independently reviewed required-contract assertions, with finding/requirement links.
- Externally meaningful effects and final file, peer, DNS, IPv6, service, and tunnel obligations.
- Expected exit class where contractual, plus backup, restoration, rollback, or reconciliation obligations.
- Named actors where needed, bounded deterministic schedules, explicit barriers, signal-injection points, allowed partial orders/linearizations, and final-state invariants.
- Semantic vector content digest.

A separate **Bash execution binding** references one semantic vector ID and digest and declares its entrypoint, instrumentation profile, exact fake-command scripts/outcomes, failure points, containment profile, and non-authoritative baseline observation where useful. A later Go binding references the same semantic vector but defines its own implementation-appropriate execution setup. Neither implementation is required to reproduce the other’s incidental utility calls.

A baseline observation MUST NOT satisfy or alter a required-contract assertion. Execution produces both:

1. Execution health, proving the bounded case and all assertions were reached with valid containment, instrumentation, fakes, schedules, and evidence.
2. Contract verdict, comparing observed semantic effects with the required-contract assertions.

A complete contract failure is a baseline defect requiring a linked `RED-BASH` finding; it is not a passing baseline observation or harness malfunction. Changing either semantic assertions or execution bindings invalidates dependent evidence. Contract changes additionally require independent disposition.

Schemas MUST reject unknown fields, duplicate IDs, missing expectations, ambiguous applicability, unbounded schedules/retries, and multi-actor cases without explicit ordering and signal rules. Every tested schedule MUST be bounded and every spawned process accounted for. Terminal colors and incidental prose are not parity requirements.

## 10. Evidence and invalidation

Every result MUST bind:

- Check ID, version, required status, execution health, contract verdict, and overall result state.
- Baseline commit plus exact tracked, permitted dirty, and permitted untracked input bytes.
- Source, transformed source, fixture, semantic vector, execution binding, runner, fake model, containment profile, schedule, and toolchain digests.
- Sanitized report digest and private raw-evidence identity.
- Creation time, retention class, expiry, and revalidation state.
- Invalidation dependencies and explicit evidence limits.

A commit ID alone is insufficient when workspace bytes differ. Any change to an input, generated source, fixture, vector, binding, runner, fake, containment profile, toolchain, or check definition invalidates dependent evidence. Unknown dependencies invalidate conservatively.

Execution health is `COMPLETE`, `PARTIAL`, or `NOT_RUN`. Contract verdict is `PASS`, `FAIL`, or `NOT_REACHED`. Overall results are:

- `PASS`: execution is `COMPLETE`, every required-contract assertion passes, and evidence is valid.
- `FAIL`: execution is `COMPLETE` and the contract verdict is `FAIL`.
- `HARNESS_FAIL`: execution is `PARTIAL`, timed out, malformed, unexpectedly interrupted, or encounters instrumentation, fake, containment, schedule, or evidence failure.
- `NOT_RUN`: execution did not begin or a required capability was unavailable. A skip is recorded as `NOT_RUN`, never as a distinct successful state.

A **complete result** requires bounded execution reaching all required assertions with valid evidence; its overall state is either `PASS` or `FAIL`. `PARTIAL`, `HARNESS_FAIL`, `NOT_RUN`, skipped, timed-out, malformed, stale, wrong-source, and hash-mismatched results block the applicable phase. At W2, a behavioral `FAIL` is acceptable only with an independently accepted `RED-BASH` finding and Go requirement; it never counts as infrastructure success.

`RED-BASH` is an audit disposition label for a confirmed baseline defect, not a passing test status. Every WVH infrastructure row MUST be `PASS` at W1 and revalidate as `PASS` at W2.

Raw evidence retention MUST be bounded and owner-only. Expired or deleted raw evidence blocks new phase reliance and makes retained curated reports historical and non-revalidatable; it cannot support a new completion or operation. Public reports MUST exclude real local paths, hostnames, endpoints, credentials, key material, raw remote payloads containing sensitive values, and unsanitized transcripts.

## 11. Audit findings and review

Each finding MUST contain:

- Stable ID, title, severity, status, and exact source references.
- Preconditions, failure mechanism, and affected safety/compatibility contract.
- Synthetic reproduction and exact evidence identity.
- Classification as preservation, regression repair, hardening, or documentation.
- Bash result and explicit Go requirement or intentional behavior change.
- Independent reviewer disposition.

Severity reflects confidentiality, integrity, availability, and likelihood. Hardening changes MUST NOT be presented as bug-for-bug parity. Bash repairs are outside W2 unless separately authorized; a repair requires failing evidence before the change, passing regression evidence afterward, and complete earlier-suite reruns.

Independent review MUST use fresh read-only examination of actual source and artifacts. Producer prose alone is insufficient. A reviewer cannot override deterministic failure, declare live safety from synthetic evidence, or authorize a later phase.

W2 MUST produce `docs/audit/source-coverage-ledger.json`. The ledger enumerates every script, function, remote heredoc, embedded program, generated executable/configuration, external-code execution boundary, and explicit failure exit. Each entry maps to static evidence, one or more complete executed semantic vectors, and applicable acceptance IDs, or to a reasoned non-applicability disposition accepted by independent review. Merely reading a file or executing its top-level path does not establish coverage. W2 completeness is defined by this ledger in addition to the acceptance matrix.

## 12. CI and supply-chain requirements

CI MUST provide separate lanes for:

- Manifest/schema/vector validation and runner self-tests.
- Bash syntax and embedded-payload equivalence.
- Sandboxed Bash characterization.
- Audit-map completeness and public-artifact sanitization.
- `git diff --check` and staged/public secret-canary checks.

Workflows MUST use full-commit action pins, explicit runner labels, and exact Python/Bash/ShellCheck/shfmt versions. Downloaded tools require reviewed content hashes or digest-pinned images. Mutable action tags, curl-pipe-shell installation, and unverified floating tools are prohibited.

CI uses read-only repository permissions, no repository secrets, no deployment environment, no `pull_request_target`, no `sudo`, no runtime SSH, and no production/network scan. Later Go lanes use locked dependencies, readonly module mode, and explicit Go versions.

A workflow is not proof of branch protection. Server-side enforcement requires separate verification. Confirmed baseline defects MUST remain visible; `|| true`, required skips, deleted assertions, and broadened fake expectations do not count as remediation.

## 13. Publication boundary

Accepted sanitized specifications, manifests, tests, vectors, CI, and curated audit artifacts MAY be committed to the existing WireVPN repository after review. Push and merge remain separately authorized.

The following MUST remain outside public repositories:

- Real WireVPN configurations, backups, keys, endpoints, credentials, and host inventory.
- Raw evidence, journals, run state, temporary trees, and unsanitized reports.
- Private operational runbooks and local distribution/binding credentials.
- Generic-kernel source copied for consumer use and any private generic run state.

No second WireVPN harness repository is required. The generic kernel is not published merely because WireVPN adopts project-owned harness practices.

## 14. Acceptance matrix

All rows applicable to a phase are required. A scenario added by an observed defect becomes required before the corresponding completion claim.

| ID | Scenario | W1 gate | W2 gate |
|---|---|---|---|
| WVH-01 | Exact source manifest detects tracked, dirty, untracked, generated, and runner changes | Pass | Pass revalidation |
| WVH-02 | Private paths, real HOME, live system roots, symlinks, path escapes, and root execution are denied | Pass negative controls | Pass revalidation |
| WVH-03 | Unexpected, missing, extra, duplicated, timed-out, and path-escaping commands fail | Pass negative controls | Pass revalidation |
| WVH-04 | Embedded CLI/connect payloads equal standalone sources; drift fails | Pass static gate | Pass revalidation |
| WVH-05 | Vector schemas reject unknown fields, missing expectations, duplicate IDs, and unbounded retries | Pass | Pass revalidation |
| WVH-06 | Instrumentation has exact replacement counts, source/output digests, and unmapped-path denial | Pass | Pass revalidation |
| WVH-07 | Tampered evidence, stale bindings, secret canaries, and malformed reports block completion | Pass | Pass revalidation |
| WVH-08 | Runner interruption and rerun preserve bounded, truthful evidence without false success | Pass | Pass revalidation |
| WVH-09 | OS containment denies direct shell/Python writes, network, archive/symlink/descriptor/child escapes and reaps process trees | Pass on each supported behavior lane | Pass revalidation |
| WVH-10 | Evidence roots are canonically non-overlapping; expiry/deletion blocks revalidation and raw CI upload is denied | Pass negative controls | Pass revalidation |
| WVA-01 | Public-IP valid, malformed, out-of-range, HTML, empty, timeout, and retry-exhaustion inputs | Initial characterization | Complete result |
| WVA-02 | Server key reuse, public derivation, and live/file mismatch behavior | Not required | Complete result |
| WVA-03 | Existing peers and matching configuration survive reruns; missing/stale material is characterized | Not required | Complete result |
| WVA-04 | Backup contents/modes, restart/start failure, and active-state verification | Not required | Complete result |
| WVA-05 | Peer names, traversal, metacharacters, empty/extreme input, and argument cardinality | Not required | Complete result |
| WVA-06 | Address allocation with holes, comments, boundaries, duplicates, exhaustion, and concurrency | Not required | Complete result |
| WVA-07 | Peer add/remove failures at every live, file, config, copy, QR, and deletion boundary | Not required | Complete result |
| WVA-08 | AdGuard fresh/rerun behavior preserves config, password, and blocklists; architectures are bounded | Not required | Complete result |
| WVA-09 | Resolved/AdGuard download, extraction, API, service, and DNS failures recover truthfully | Not required | Complete result |
| WVA-10 | AdGuard archive identity and API/firewall exposure claims receive security review | Not required | Disposition required |
| WVA-11 | Client discovery/install, backups, package, and autostart branches use only synthetic HOME/root | Not required | Complete result |
| WVA-12 | Client setup activation does not bypass managed DNS/IPv6 safety or double-activate | Initial characterization | Complete result |
| WVA-13 | DNS parsing covers AdGuard, public DNS, comma lists, comments, missing, and invalid values | Initial characterization | Complete result |
| WVA-14 | Stale DNS, changed DNS, sweep failure, and cache-flush failure are characterized | Initial characterization | Complete result |
| WVA-15 | DNS health success/failure/timeout drives fail-closed teardown and truthful restoration | Initial vectors executed | Complete result |
| WVA-16 | macOS IPv6 enumeration, partial disable, prior-off/manual state, and state/restore failures | Initial vectors executed | Complete result |
| WVA-17 | Linux `all`/`default` prior state, sysctl failure, reboot, and stop failure | Initial vectors executed | Complete result |
| WVA-18 | Managed CLI targets only the owned interface; daemon/concurrent operations do not race | Not required | Complete result |
| WVA-19 | File modes, logs, SSH/SCP argv, temporary files, QR output, and reports preserve secret boundaries | Negative canaries | Complete result |
| WVA-20 | Every historical fix and README claim maps to fresh evidence or a finding | Inventory established | Complete map |
| WVA-21 | Embedded SSH Bash and removal Python receive the same source/failure-boundary coverage | Static inventory | Complete result |
| WVA-22 | Every confirmed defect has severity, evidence, disposition, and an explicit Go requirement | Not required | Independent closure |
| WVA-23 | Server package failures, default-route detection, forwarding, firewall changes, and client rendering | Not required | Complete result |
| WVA-24 | Boot connector network-wait exhaustion, missing `wg-quick`, signals, resident shutdown, and cleanup exits | Not required | Complete result |
| WVA-25 | CLI invalid/extra arguments and contractual `up`, `down`, and `status` exit behavior | Not required | Complete result |
| WVA-26 | Homebrew installation and every downloaded/executed external-code boundary has identity and disposition | Static inventory | Disposition required |
| WVA-27 | Ignore rules and public-output checks cover every generated secret/config/backup/state filename | Static inventory | Complete result |
| WVA-28 | Concurrent actors and signals use bounded schedules, barriers, partial orders, and final-state invariants | Schedule negative controls | Complete result |

“Initial characterization” and “initial vectors executed” require `COMPLETE` execution health and valid evidence. A W1 contract failure is recorded as `FAIL` with a new finding and explicit W2 disposition requirement; it MUST NOT be weakened to obtain a green harness. `HARNESS_FAIL`, `PARTIAL`, `NOT_RUN`, skips, timeouts, and invalid evidence block W1. W1 infrastructure checks MUST still prove that the runner reports every outcome correctly.

## 15. Phase exit criteria

### 15.1 W0

- Independent review findings are repaired or explicitly dispositioned.
- Source hashes and generic references are verified.
- Acceptance IDs are unique and all required surfaces are mapped.
- Public-content and whitespace checks pass.
- Owner acceptance is recorded before the specification-only local commit.

### 15.2 W1

- Manifest, runner self-tests, static gates, OS-containment probes, negative controls, and required initial vectors execute with zero required skips.
- Every WVH row is `PASS`; initial behavioral rows have complete execution health and valid `PASS` or finding-linked `FAIL` results.
- No real private config, HOME, network, privilege, or host service is used; evidence/public roots are non-overlapping.
- Source/vector/binding/tool/runner/containment mutation invalidates evidence.
- Initial Bash outcomes, including defects, are reported truthfully.
- Independent review examines the exact final artifacts.
- A local commit is separately authorized; publication remains closed.

### 15.3 W2

- The source-coverage ledger accounts for every executable subsystem, function, embedded/remote path, generated artifact, external-code boundary, and explicit failure exit.
- Every acceptance row has a complete required result or accepted disposition; no required `HARNESS_FAIL`, `PARTIAL`, `NOT_RUN`, skip, timeout, or invalid evidence remains.
- Every WVH row revalidates as `PASS`. A behavioral `FAIL` remains only with an independently accepted `RED-BASH` finding and Go requirement.
- Every historical fix and README claim has evidence or an open finding.
- Every finding has an accepted disposition and Go requirement.
- Public artifacts are sanitized; raw evidence remains private and currently revalidatable for the completion claim.
- Independent review closes the audit at exact source identity.

W2 completion permits drafting a separately reviewed Go specification under W3. Go implementation requires W3 owner acceptance and new W4 authorization. W2 does not repair Bash, implement Go, deploy, or authorize operational testing.

## 16. Later generic binding

A future kernel-backed shadow run requires separately reviewed generic work for authenticated immutable distribution and named deterministic host-check support. Wrong artifact/version/signature, stale evidence, tampering, recovery, and independent receipt-verification tests MUST pass before adoption.

WireVPN MUST then pin the generic specification, kernel commit and artifact digest, distribution attestation, adapter and runner digests, contracts/policy/configuration, toolchain, and empty optional-module set. Run/control state remains outside model-writable workspaces. Shell and Go execution MUST NOT be exposed through the existing read/write-only runtime adapter.

Until those gates exist, WireVPN reports are deterministic project evidence only. No generic receipt, pack conformance, runtime governance, or general-reuse claim is permitted.

## 17. Review and acceptance record

This section records evidence, not authorization by implication.

- Independent review: PASS on 2026-10-27 after repair and re-review. The initial review identified five high and three medium findings covering baseline-versus-contract semantics, incomplete execution, OS containment, source coverage, Go phase separation, concurrency schedules, language-neutral vectors, and evidence retention. All were repaired; final re-review found no remaining blocking, high, or medium issue.
- Structural/source validation: PASS on 2026-10-27. Six source size/hash bindings verified, 38 unique acceptance IDs, separate Go specification/implementation gates, no trailing whitespace, and public-content checks passed.
- Owner acceptance: accepted on 2026-10-27.
- Specification-only commit: pending.
- W1 authorization: granted on 2026-10-27, effective after the specification-only commit.
- W2 authorization: not granted.
- Publication authorization: not granted.
