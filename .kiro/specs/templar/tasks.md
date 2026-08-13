# Implementation Plan: Templar — AI-Powered Cybersecurity Framework

## Overview

This plan implements the full Templar framework in Go, following the Knights Templar naming conventions established in the design. Tasks are sequenced so each step builds on the previous, wiring shared infrastructure first, then individual Knights in dependency order (Seneschal → Preceptor → Hospitaller → Marshal → Chaplain → Scribe → Grand Master → Pilgrim CLI). Property-based tests (using `pgregory.net/rapid`) are included as optional sub-tasks close to the code they validate.

---

## Tasks

- [x] 1. Scaffold project and shared infrastructure
  - Initialize Go module (`go.mod`) for `github.com/templar-framework/templar`
  - Create the full directory tree matching the design's project structure
  - Set up `go.sum`, `Makefile` with `build`, `test`, `lint` targets
  - Add `configs/default.yaml` with sensible scan depth defaults and rate limits
  - _Requirements: 1.1, 10.3_

  - [x] 1.1 Define all shared data types in `internal/shared/types.go`
    - Write Go structs for `CrusadeConfig`, `ScopeConfig`, `AIProviderConfig`, `AttackSurface`, `DiscoveredSubdomain`, `DiscoveredHost`, `DiscoveredEndpoint`, `DiscoveredParameter`, `TechStackEntry`, `CertificateInfo`, `Vulnerability`, `VulnEvidence`, `RawHTTPRequest`, `RawHTTPResponse`, `ProofOfConcept`, `AttackChain`, `ChainStep`, `ChainImpact`, `CampaignState`, `CampaignResult`, `CampaignExport`, `KBSearchResult`, `Report`, `ReportOptions`, `ModuleFlags`, `RateLimitConfig`
    - Define all enumerations: `ScanDepth`, `VulnType`, `AuthType`, `TechCategory`, `DataType`, `PoCType`
    - Define `IKnight`, `IReconSubAgent`, `IVulnScanner`, `IVulnAnalyst`, `IPoCGenerator`, `IChainBuilder` interfaces
    - _Requirements: 1.1, 2.2, 3.1, 4.1, 5.1, 6.1, 7.1_

  - [x] 1.2 Implement Scope Enforcer in `internal/shared/scope.go`
    - Write `isInScope(rawURL string, scope ScopeConfig) bool` with wildcard subdomain matching
    - Implement as HTTP client middleware (`ScopeEnforcingTransport`) intercepting at transport layer before DNS resolution
    - Emit `SCOPE_VIOLATION` and `URL_MALFORMED` audit events; never throw on malformed input — return false
    - Support `*.example.com` matching `api.example.com` and `sub.api.example.com` but NOT `example.com`
    - Write audit log entries with ISO-8601 timestamp, blocked URL, blocking rule type, and matching pattern
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7_

  - [ ]* 1.3 Write property tests for Scope Enforcer
    - **Property 1: Scope Invariant** — `∀ url, scope: isInScope(url, scope) = true → url.hostname ∈ allowedDomains ∧ url.path ∉ excludedPaths`
    - **Property 2: Scope Check Robustness** — `∀ input string: isInScope(input, scope)` never panics; returns false for all non-URL inputs
    - **Property 15: Endpoint Scope Invariant** — every endpoint that passes isInScope genuinely satisfies the scope predicate
    - **Validates: Requirements 9.1, 9.2, 9.3, 9.4**

  - [x] 1.4 Implement LLM Client in `internal/shared/llm/client.go` and `ratelimiter.go`
    - Implement `LLMClient` with provider routing for `openai`, `anthropic`, `google`, `ollama`, `openrouter`
    - Role-based provider selection: match `orchestration` / `analysis` / `exploit_gen`; fallback to `any`; error `NO_PROVIDER_AVAILABLE`
    - Reject unknown provider values with `UNSUPPORTED_PROVIDER` error at startup
    - Enforce `maxTokens` (default 4096) and `temperature` (default 0.7) per `AIProviderConfig`
    - Track cumulative token usage per Campaign; emit `TOKEN_BUDGET_WARNING` at 80% of cost threshold; emit immediately if threshold is 0 or omitted
    - Redact all API key values in every log line and error message before output (replace with `[REDACTED]`)
    - _Requirements: 8.1, 8.2, 8.5, 8.6, 8.7_

  - [x] 1.5 Implement LLM exponential backoff retry in `internal/shared/llm/client.go`
    - On HTTP 429 or HTTP 5xx: retry up to 5 times with initial delay 1s, multiplier 2×, max delay 60s, ±10% random jitter
    - After all 5 retries exhausted, return final error with HTTP status code and message to caller
    - _Requirements: 8.3, 8.4_

  - [ ]* 1.6 Write property test for LLM retry backoff
    - **Property 16: LLM Retry Backoff Bounds** — for any failure sequence, delay per attempt is ≥1s, ≤60s, and total attempts ≤5; sequence is non-decreasing (before jitter)
    - **Validates: Requirements 8.3**

  - [x] 1.7 Implement external tool executor in `internal/shared/tools/executor.go`
    - Write `Execute(toolName string, args []string, timeoutSecs int) (stdout, stderr string, exitCode int, err error)`
    - Log ISO-8601 timestamp, tool name, full args, exit code (or `TIMEOUT`), and first 4096 chars of combined stdout/stderr to audit log
    - On non-zero exit or timeout: retry once with `maxConcurrency` halved (minimum 1); record `TOOL_FAILURE` on second failure
    - _Requirements: 11.3, 11.4_

- [x] 2. Implement Seneschal — state, persistence, and Holy Grail RAG

  - [x] 2.1 Implement campaign state management in `internal/seneschal/state.go`
    - Write `CampaignState` lifecycle methods: `initializeCampaign`, `getStatus`, `setPhaseStatus`, `getPhasesStatus`
    - Implement phase status transitions: `pending → running → complete | degraded`
    - Emit structured progress events within 1 second of state change; each event includes campaign ID, phase name, phase status, subdomain/endpoint/vuln/PoC/chain counts
    - _Requirements: 2.1, 2.7, 11.2_

  - [x] 2.2 Implement SQLite persistence in `internal/seneschal/store.go`
    - Create SQLite schema for campaigns, attack surfaces, vulnerabilities, PoCs, attack chains, audit log, cache table
    - Implement `storeReconResults`, `storeVulnerabilities`, `storePOCs`, `storeChains`, `retrieve`, `exportCampaign`
    - On SQLite init failure: log error with SQLite error code, fall back to in-memory store, set `persistence_degraded` flag
    - Cache tech stack fingerprints, CVE results, and LLM similarity scores with configurable TTL (default 24h)
    - _Requirements: 2.1, 2.3, 2.6, 2.5_

  - [ ]* 2.3 Write property test for Seneschal artifact round-trip
    - **Property 11: Seneschal Artifact Round-Trip** — `∀ artifact: retrieve(store(campaignId, artifact)) ≡ artifact` for all four artifact types
    - Verify every scalar field, array length, element order, and nested object equality recursively
    - **Validates: Requirements 2.2, 2.3**

  - [x] 2.4 Implement API key redaction in Seneschal
    - Before any persist, emit, or export call, scan all string fields for patterns: `sk-[A-Za-z0-9]{20,}`, `Bearer [A-Za-z0-9\-._~+/]{20,}`, `AIzaSy[A-Za-z0-9\-_]{33}`, and 32+ alphanumeric chars in fields named key/token/secret/password
    - Replace matched values with `[REDACTED]`; apply at store boundary so raw keys never touch SQLite or events
    - _Requirements: 2.8_

  - [ ]* 2.5 Write property test for API key isolation
    - **Property 9: API Key Isolation** — generate arbitrary `AIProviderConfig` with random API keys; after store+retrieve+export, assert no original key value appears in the output
    - **Validates: Requirements 2.8, 8.7**

  - [x] 2.6 Implement Holy Grail RAG vector store in `internal/seneschal/holygrail/vectorstore.go` and `indexer.go`
    - Integrate ChromaDB or Qdrant client for vector storage
    - Implement CVE/NVD indexer that embeds CVE descriptions using Sentence Transformers (via `go-python3` or subprocess)
    - Implement `queryKnowledgeBase(query string) []KBSearchResult` with cosine similarity ranking, returning top 20 results sorted descending
    - _Requirements: 2.4_

- [x] 3. Checkpoint — Shared infrastructure complete
  - Ensure all tests pass; verify scope enforcer, LLM client, tool executor, and Seneschal compile cleanly; ask the user if questions arise.

- [x] 4. Implement Preceptor — reconnaissance and discovery

  - [x] 4.1 Implement Crusade Mapper in `internal/preceptor/crusademapper/mapper.go`
    - Wrap Subfinder, Amass, crt.sh (HTTP), and DNSx CLI tools using the shared tool executor
    - Merge and deduplicate results from all four tools into a single `[]DiscoveredSubdomain` list
    - Populate `source` field of each subdomain with contributing tool names
    - _Requirements: 3.1, 3.10_

  - [x] 4.2 Implement Cartographer in `internal/preceptor/cartographer/fingerprint.go`
    - Invoke Wappalyzer signature matching (minimum 7,200 signatures) and httpx probing against all hosts with reachable HTTP or open TCP ports
    - Populate `TechStackEntry.version` when non-null version signals are detected; compute confidence score 0.0–1.0 based on signal count and specificity
    - _Requirements: 3.2, 3.9_

  - [x] 4.3 Implement Vanguard in `internal/preceptor/vanguard/portscan.go`
    - Invoke masscan for initial host discovery, then Nmap NSE scripts against top 1000 TCP ports with service version detection
    - Return `[]DiscoveredHost` with all open ports and service versions
    - _Requirements: 3.3_

  - [x] 4.4 Implement Pilgrim Crawler in `internal/preceptor/pilgrimcrawler/crawler.go` and `fuzzer.go`
    - Invoke Katana and Gospider for JS-aware crawling, gau for historical URLs, ffuf and feroxbuster for directory fuzzing, x8 for hidden parameter discovery
    - Populate `DiscoveredEndpoint.source` with contributing tool names for each endpoint
    - Collect all discovered parameters (name, values, discovery source) into endpoint parameter lists
    - _Requirements: 3.4, 3.8, 3.10_

  - [x] 4.5 Implement Preceptor coordinator in `internal/preceptor/preceptor.go`
    - Launch Crusade Mapper, Cartographer, and Vanguard concurrently using goroutines; start Pilgrim Crawler within 5 seconds of all three completing
    - Apply `ScopeEnforcingTransport` to all outbound requests; discard and log `SCOPE_VIOLATION` for any out-of-scope endpoint
    - Deduplicate endpoints by `(url, method)` tuple, merging parameters and source lists
    - On any sub-agent failure or timeout: log `TOOL_FAILURE`, continue with remaining sub-agents, mark AttackSurface with `recon_partial` flag naming the failed sub-agent
    - Return `AttackSurface` where no two entries share the same `(url, method)` tuple
    - _Requirements: 3.5, 3.6, 3.7, 3.11_

  - [ ]* 4.6 Write property test for deduplication idempotency
    - **Property 8: Deduplication Idempotency** — `∀ findings: deduplicate(deduplicate(findings)).length = deduplicate(findings).length`
    - Test for both endpoint deduplication and vulnerability finding deduplication
    - **Validates: Requirements 4.5, 3.7**

- [x] 5. Implement Hospitaller — vulnerability analysis

  - [x] 5.1 Implement Inquisitor in `internal/hospitaller/inquisitor/nuclei.go` and `zap.go`
    - Wrap Nuclei CLI (community templates) and OWASP ZAP headless API active scan using the shared tool executor
    - Capture template ID match in `VulnEvidence.matchedTemplate`; enforce 300-second timeout; on failure log `TOOL_FAILURE`, mark sub-task `degraded`, continue
    - _Requirements: 4.1_

  - [x] 5.2 Implement Relic Hunter in `internal/hospitaller/relichunter/cve.go` and `exploitdb.go`
    - For each `TechStackEntry` with a non-null version: query NVD, OSV, and ExploitDB APIs with 30-second timeout per source
    - Optionally enrich hosts with Shodan/Censys when API keys are present (60-second timeout per host)
    - On any source failure or timeout: log the failure, skip that source, continue with remaining sources
    - _Requirements: 4.2, 4.7_

  - [x] 5.3 Implement Oracle AI analyst in `internal/hospitaller/oracle/analyst.go` and `prompt_builder.go`
    - Batch uncovered endpoints into groups of at most 10; build `AnalysisContext` fitting within 128,000 tokens (endpoint descriptions, tech stack, raw HTTP responses)
    - Call configured LLM with role `analysis`; discard any AI finding whose endpoint URL is absent from the AttackSurface, log `DATA_INTEGRITY_WARNING` with invalid URL and batch index
    - _Requirements: 4.3, 4.4_

  - [ ] 5.4 Implement Hospitaller coordinator in `internal/hospitaller/hospitaller.go`
    - Orchestrate Inquisitor → Relic Hunter → Oracle in sequence per the design's three-layer pipeline
    - Deduplicate findings by `(endpoint.url, type, payload)` — use `(endpoint.url, type)` when payload is null/empty; assign max CVSS and union of evidence on merge
    - Sort returned `[]Vulnerability` by severity tier (critical→high→medium→low→info) then descending CVSS (treat missing CVSS as 0.0)
    - Store all Vulnerability records in Vault via Seneschal before returning to Grand Master
    - _Requirements: 4.5, 4.6, 4.8_

  - [ ]* 5.5 Write property test for vulnerability endpoint referential integrity
    - **Property 3: Vulnerability Endpoint Referential Integrity** — `∀ v ∈ vulnerabilities: ∃ e ∈ surface.endpoints: v.endpoint.url = e.url`
    - **Validates: Requirements 4.4**

- [x] 6. Implement Marshal — exploit and PoC forge

  - [x] 6.1 Implement Holy Lance PoC generator in `internal/marshal/holylance/generator.go`
    - Skip any Vulnerability with severity `low` or `info`
    - First query ExploitDB and Holy Grail for CVE-matched exploits; if found, adapt best match to target endpoint context
    - If no existing exploit: call LLM with temperature 0.2, structured prompt containing vuln type, endpoint URL+method, raw evidence, tech stack, CVE IDs, and output format; reject empty or code-block-free responses
    - Set `poc.type` to one of the five valid values; default to `python_script` if adapted format doesn't map
    - Load PoC prompt templates from `internal/marshal/holylance/templates/` by vuln type
    - _Requirements: 5.1, 5.2, 5.3, 5.5_

  - [x] 6.2 Implement Siege Engine payload fuzzer/validator in `internal/marshal/siegeengine/fuzzer.go` and `validator.go`
    - For injection-class vulns: request smart wordlist from LLM (specify exact injection class + tech stack); use LLM-generated wordlist for ffuf/wfuzz invocation
    - For PoC validation: execute within 120-second timeout; record boolean success and first 2048 chars of output; on timeout set `validated=false` and `validationOutput='VALIDATION_TIMEOUT'`
    - For POST/PUT/PATCH/DELETE with `destructive_potential='HIGH'`: generate PoC but skip Siege Engine unless `allowDestructive=true`
    - _Requirements: 5.6, 5.7, 5.8_

  - [x] 6.3 Implement Marshal coordinator in `internal/marshal/marshal.go`
    - Filter vulnerabilities to severity medium/high/critical; iterate and call Holy Lance for each
    - Before storing a PoC: verify `vulnerabilityId` exists in Vault; discard and log `DATA_INTEGRITY_WARNING` if not found
    - Store all PoC records in Seneschal before returning results to Grand Master
    - _Requirements: 5.4, 5.9_

  - [ ]* 6.4 Write property tests for PoC correctness
    - **Property 4: PoC Vulnerability Referential Integrity** — `∀ poc: ∃ v ∈ vulnerabilities: poc.vulnerabilityId = v.id`
    - **Property 12: PoC Severity Filter** — `∀ poc ∈ forgeExploits(vulns): poc.vulnerability.severity ∈ {medium, high, critical}`
    - **Property 13: PoC Type Completeness** — `∀ poc: poc.type ∈ {curl_command, python_script, metasploit_module, burp_request, browser_steps}`
    - **Validates: Requirements 5.4, 5.1, 5.3**

- [~] 7. Checkpoint — Reconnaissance through Marshal complete
  - Ensure all tests pass for Preceptor, Hospitaller, and Marshal; run unit tests with mocked tool executor and LLM client; ask the user if questions arise.

- [ ] 8. Implement Chaplain — attack chain analysis

  - [x] 8.1 Implement attack graph construction in `internal/chaplain/crusadeplanner/graph.go`
    - Build `AttackGraph` where each node is a confirmed/poc_available Vulnerability; add directed edge A→B when `postconditionSatisfies(A, B.preconditions)` returns true
    - Implement semantic matching using exact string comparison first, then LLM similarity scoring for non-exact matches; cache LLM scores in SQLite keyed by `postcondition+precondition` concatenation
    - Only add nodes for Vulnerabilities with `status = 'confirmed' | 'poc_available'`
    - _Requirements: 6.1, 11.7_

  - [x] 8.2 Implement DAG path enumeration in `internal/chaplain/crusadeplanner/pathfinder.go`
    - Enumerate all DAG paths of length 2–10 nodes with minimum combined impact threshold `MEDIUM`
    - For each candidate path: call LLM to validate feasibility; if LLM says infeasible, exclude and log exclusion reason
    - On LLM call failure: retry once; if retry also fails, exclude chain and log `CHAIN_VALIDATION_FAILURE`
    - Generate `llmRationale` string of at least 50 characters explaining chaining mechanism and vulnerability types
    - _Requirements: 6.2, 6.5, 6.6_

  - [x] 8.3 Implement Heretic Judge CVSS scorer in `internal/chaplain/hereticjudge/scorer.go`
    - Compute `combinedCvss` for each chain applying CVSS temporal and environmental metrics
    - Result must be ≥ max individual CVSS score among all chain steps AND ≤ 10.0
    - _Requirements: 6.4_

  - [ ]* 8.4 Write property tests for chain correctness
    - **Property 5: Chain Coherence** — `∀ chain, ∀ i: postconditionSatisfies(chain.steps[i], chain.steps[i+1].preconditions)`; log `CHAIN_COHERENCE_VIOLATION` for any incoherent chain
    - **Property 6: Chain Severity Lower Bound** — `∀ chain: chain.combinedCvss ≥ max(steps[*].vuln.cvssScore) ∧ combinedCvss ≤ 10.0`
    - **Property 7: Chain Minimum Length** — `∀ chain: chain.steps.length ≥ 2`
    - **Validates: Requirements 6.3, 6.4, 6.2**

  - [x] 8.5 Implement Chaplain coordinator in `internal/chaplain/chaplain.go`
    - Orchestrate graph construction → path enumeration → scoring; sort result by descending `combinedCvss`, then descending chain length, then ascending `createdAt`
    - On empty input or no confirmed/poc_available vulns: return empty list and emit `CHAIN_ANALYSIS_SKIPPED` event
    - Store all AttackChain records in Seneschal before returning to Grand Master
    - _Requirements: 6.7, 6.8, 6.9_

- [x] 9. Implement Scribe and Chronicle — report generation

  - [x] 9.1 Implement Chronicle report data retrieval in `internal/scribe/chronicle/`
    - Write `retrieveAllArtifacts(campaignId) (CampaignExport, error)` that fetches all artifact types from Seneschal; return `REPORT_GENERATION_FAILED` identifying the artifact type on any retrieval error
    - _Requirements: 7.3_

  - [x] 9.2 Implement JSON and Markdown report renderers in `internal/scribe/chronicle/`
    - JSON: serialize `CampaignResult` such that `json.Unmarshal(data, &result)` succeeds and every Vulnerability, PoC, and AttackChain is accessible at expected schema path
    - Markdown: render all five required sections (executive summary, attack surface map, vulnerability list with evidence, PoC list, attack chain list with rationale)
    - Include "Operational Issues" section listing degraded components and "Excluded Targets" section listing scope-blocked URLs
    - _Requirements: 7.1, 7.2, 7.4, 7.7, 7.8_

  - [x] 9.3 Implement HTML and PDF report renderers in `internal/scribe/chronicle/`
    - HTML: full-featured report with all five required sections matching the design's content requirements
    - PDF: generate from HTML output using WeasyPrint or equivalent Go library
    - Write report files to `config.outputDir`; return `REPORT_WRITE_FAILED` with filesystem error if directory is missing or not writable
    - _Requirements: 7.1, 7.2, 7.6_

  - [x] 9.4 Implement SARIF 2.1.0 report renderer in `internal/scribe/chronicle/sarif.go`
    - Produce SARIF output conforming to schema version 2.1.0; zero schema validation errors when validated against official SARIF 2.1.0 JSON schema
    - Map Vulnerability records to SARIF `result` objects with appropriate rule references and severity levels
    - _Requirements: 7.5_

  - [x] 9.5 Implement Scribe coordinator in `internal/scribe/scribe.go`
    - Iterate over requested formats; log `UNSUPPORTED_FORMAT` and skip unknown formats without failing others
    - Invoke Chronicle per format; wire outputDir validation before rendering
    - _Requirements: 7.1, 7.3, 7.6_

  - [ ]* 9.6 Write property test for report section completeness
    - **Property 14: Report Section Completeness** — generate arbitrary campaign artifacts; for every format produced, assert all five required sections are present and non-empty
    - **Validates: Requirements 7.2**

- [ ] 10. Implement Grand Master — campaign orchestrator

  - [ ] 10.1 Implement campaign initialization and validation in `internal/grandmaster/orchestrator.go`
    - Validate `CrusadeConfig`: non-empty `targetUrl`, non-empty `allowedDomains`, at least one `AIProviderConfig` with non-empty `apiKey`, valid `scanDepth`, writable `outputDir`
    - Reject invalid config with descriptive error before creating any Campaign record
    - Check Seneschal for existing running/paused Campaign with same `targetUrl`; reject with `DUPLICATE_CAMPAIGN` error if found
    - Validate empty `allowedDomains` triggers `SCOPE_CONFIGURATION_ERROR` before any agent phase
    - _Requirements: 1.1, 1.2, 1.10, 9.7_

  - [~] 10.2 Implement campaign sequencing and phase management in `internal/grandmaster/orchestrator.go`
    - Sequence phases: Preceptor → Hospitaller → Marshal → Chaplain → Scribe; do not start a phase until all predecessors are `complete` or `degraded`
    - After each phase transitions to `complete`/`degraded`: persist status to Seneschal immediately
    - On all phases complete/degraded: set Campaign status to `complete` and return full `CampaignResult`
    - On phase failure after all retries: mark phase `degraded`, record failure reason, continue with subsequent phases using partial artifacts
    - _Requirements: 1.4, 1.8, 1.9, 11.2_

  - [~] 10.3 Implement pause, resume, and abort in `internal/grandmaster/orchestrator.go`
    - Pause: signal in-flight sub-agents to finish current atomic op and halt within 10 seconds; persist state; set status `paused`; return `CAMPAIGN_NOT_RUNNING` if status ≠ running
    - Resume: set status `running`; continue from last non-complete phase; return `CAMPAIGN_NOT_PAUSED` if status ≠ paused
    - Abort: terminate all in-flight ops without waiting; set status `aborted` within 5 seconds; return `CAMPAIGN_ALREADY_TERMINAL` if already aborted/complete
    - _Requirements: 1.5, 1.6, 1.7_

  - [~] 10.4 Implement concurrency scheduler and rate limiter in `internal/grandmaster/scheduler.go`
    - Enforce `maxConcurrency` as a hard upper bound on concurrent sub-agent goroutines; queue sub-agents when limit is reached
    - Apply per-host rate limiting matching `RateLimitConfig` (default 10 req/s per host)
    - _Requirements: 11.5, 11.6_

  - [~] 10.5 Implement LLM-driven scope refinement and `registerKnight` in `internal/grandmaster/orchestrator.go`
    - After Preceptor completes: call LLM with role `orchestration` to review AttackSurface and optionally expand/contract scope
    - Implement `registerKnight(knight IKnight)` for dynamic Knight registration
    - _Requirements: 1.4_

  - [ ]* 10.6 Write property test for resume safety
    - **Property 10: Resume Safety** — for a Campaign with one or more completed phases, resuming produces artifacts for uncompleted phases equivalent to a full run with the same persisted inputs; completed phases are never re-executed
    - **Validates: Requirements 11.1, 11.2, 1.6**

- [~] 11. Checkpoint — All Knights and Grand Master complete
  - Ensure all tests pass across all modules; run full unit test suite with mocked dependencies; ask the user if questions arise.

- [ ] 12. Implement Pilgrim CLI — command-line interface

  - [~] 12.1 Implement CLI entry point and command structure in `cmd/templar/main.go`
    - Register five commands using a Go CLI framework (cobra): `crusade start`, `crusade pause <campaignId>`, `crusade resume <campaignId>`, `crusade abort <campaignId>`, `crusade status <campaignId>`
    - Wire each command to the corresponding Grand Master method
    - _Requirements: 10.1_

  - [~] 12.2 Implement `crusade start` with authorization gate and config validation
    - Accept `--config <path>` flag; parse and validate YAML against `CrusadeConfig` schema; print each validation error and exit code 2 on any invalid field
    - Display legal authorization prompt naming `targetUrl`, `allowedDomains`, and `scanDepth`; require operator to type `yes` or `y` (case-insensitive) within 60 seconds; exit code 1 on any other response
    - Pass `allowDestructive=false` unless `--allow-destructive` flag is present
    - On `DUPLICATE_CAMPAIGN` error: print `'A campaign for this target is already active (ID: <campaignId>)'` and exit code 3
    - _Requirements: 10.2, 10.3, 10.5, 10.6, 1.3_

  - [~] 12.3 Implement progress streaming for running campaigns
    - Subscribe to Seneschal progress events; update terminal output at most every 2 seconds
    - Display: current phase name, active sub-agent name, elapsed time, subdomain/endpoint/vuln/PoC/chain counts
    - _Requirements: 10.4_

  - [~] 12.4 Implement campaign completion summary display
    - On Campaign status `complete` or `partial`: print output directory path, one line per generated report format, vuln counts by severity, total AttackChain count, total PoC count
    - _Requirements: 10.7_

  - [~] 12.5 Implement `crusade pause`, `resume`, `abort`, and `status` commands
    - Each command accepts campaign ID; forwards to Grand Master; prints status transitions and any error codes to stdout/stderr
    - _Requirements: 10.1, 1.5, 1.6, 1.7_

- [~] 13. Checkpoint — Pilgrim CLI complete
  - Run full unit and property-based test suite; verify all 5 CLI commands compile and exit codes are correct; ask the user if questions arise.

- [ ] 14. Integration tests against Pilgrim's Rest

  - [ ] 14.1 Create Pilgrim's Rest Docker Compose stack
    - Write `docker-compose.yml` in `tests/integration/pilgrims-rest/` launching DVWA, Juice Shop, WebGoat, and a custom injectable API container
    - Include a `wait-for-healthy.sh` script to block tests until all services pass health checks
    - _Requirements: Integration test suite_

  - [~] 14.2 Write shallow-depth integration test campaign
    - Write a Go integration test (build tag `//go:build integration`) that launches a `shallow` Crusade against the Pilgrim's Rest stack
    - Assert at least one confirmed Vulnerability per vulnerable service (DVWA, Juice Shop, WebGoat)
    - Assert at least one PoC validates successfully against the test stack
    - Assert at least one AttackChain is generated for a known multi-step path
    - _Requirements: Integration test suite, 4.1, 5.2, 6.1_

  - [~] 14.3 Write report format integration tests
    - After integration campaign completes, assert reports are generated for all five formats without error
    - Assert JSON report passes `json.Unmarshal` without error and required schema paths are populated
    - Assert SARIF report validates against SARIF 2.1.0 JSON schema with zero errors
    - _Requirements: 7.1, 7.4, 7.5_

  - [ ]* 14.4 Write scope enforcement integration test
    - Start a campaign against Pilgrim's Rest with a scope that excludes one service
    - Assert zero outbound requests reach the excluded service; assert all blocked URLs appear in the report's "Excluded Targets" section
    - **Validates: Requirements 9.1, 9.2, 7.8**

- [~] 15. Final checkpoint — All tests pass
  - Run `make test` (unit + property) and `make test-integration` (integration suite against Pilgrim's Rest); fix any failures; ask the user if questions arise.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP; core functionality is fully implemented without them
- All 16 correctness properties from the design are covered by property-based test sub-tasks distributed across the relevant implementation tasks
- Property tests use `pgregory.net/rapid` (Go native PBT library); unit tests use the standard `testing` package with `testify/assert`
- Integration tests carry the `integration` build tag and require Docker; run separately with `make test-integration`
- Every external tool call goes through the shared `tools/executor.go` for consistent audit logging and retry behavior
- The `ScopeEnforcingTransport` must be the only HTTP transport used across all Knights and sub-agents — never bypass it
- API keys are loaded from environment variables or `.env`; they must never appear in any output, log, or SQLite row

---

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.4", "1.7"] },
    { "id": 2, "tasks": ["1.3", "1.5", "2.1"] },
    { "id": 3, "tasks": ["1.6", "2.2", "2.4"] },
    { "id": 4, "tasks": ["2.3", "2.5", "2.6"] },
    { "id": 5, "tasks": ["4.1", "4.2", "4.3", "4.4"] },
    { "id": 6, "tasks": ["4.5"] },
    { "id": 7, "tasks": ["4.6", "5.1", "5.2"] },
    { "id": 8, "tasks": ["5.3"] },
    { "id": 9, "tasks": ["5.4"] },
    { "id": 10, "tasks": ["5.5", "6.1"] },
    { "id": 11, "tasks": ["6.2"] },
    { "id": 12, "tasks": ["6.3"] },
    { "id": 13, "tasks": ["6.4", "8.1"] },
    { "id": 14, "tasks": ["8.2", "8.3"] },
    { "id": 15, "tasks": ["8.4", "8.5"] },
    { "id": 16, "tasks": ["9.1"] },
    { "id": 17, "tasks": ["9.2", "9.3", "9.4"] },
    { "id": 18, "tasks": ["9.5"] },
    { "id": 19, "tasks": ["9.6", "10.1"] },
    { "id": 20, "tasks": ["10.2"] },
    { "id": 21, "tasks": ["10.3", "10.4", "10.5"] },
    { "id": 22, "tasks": ["10.6", "12.1"] },
    { "id": 23, "tasks": ["12.2", "12.3"] },
    { "id": 24, "tasks": ["12.4", "12.5"] },
    { "id": 25, "tasks": ["14.1"] },
    { "id": 26, "tasks": ["14.2"] },
    { "id": 27, "tasks": ["14.3", "14.4"] }
  ]
}
```
