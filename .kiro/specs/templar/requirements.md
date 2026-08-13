# Requirements Document

## Introduction

Templar is an autonomous, AI-powered cybersecurity framework that orchestrates a full offensive security lifecycle — discovery, fingerprinting, vulnerability analysis, exploit generation, vulnerability chaining, and reporting — beginning from a single target URL. It combines a curated set of open-source security tools (Nuclei, Subfinder, httpx, Nmap, OWASP ZAP, ffuf, and more) with LLM reasoning from multiple AI providers across a hierarchy of specialized agents organized under Knights Templar naming conventions.

The framework supports two operating modes: fully automated **Crusade** mode and interactive **Pilgrimage** mode. A legal authorization gate, hard scope enforcement, and a non-destructive validation pipeline ensure responsible use. Every campaign phase produces structured artifacts persisted by the Seneschal state manager, enabling pause, resume, and comprehensive multi-format reporting.

---

## Glossary

- **Grand_Master**: The central orchestrator component that drives the full campaign lifecycle, sequences agents, and makes LLM-driven decisions.
- **Seneschal**: The persistent state and memory component; single source of truth for all campaign artifacts.
- **Preceptor**: The reconnaissance and discovery module that coordinates four sub-agents across subdomain, tech stack, port, and endpoint discovery.
- **Hospitaller**: The vulnerability analysis module that combines deterministic template scanning with AI-driven analysis and CVE matching.
- **Marshal**: The exploit and proof-of-concept forge that generates and validates PoCs for confirmed vulnerabilities.
- **Chaplain**: The chain analysis module that identifies multi-step attack paths by combining individual vulnerabilities into high-impact chains.
- **Scribe**: The report generation module that produces structured reports in multiple output formats.
- **Crusade_Mapper**: Preceptor sub-agent responsible for subdomain enumeration using Subfinder, Amass, crt.sh, and DNSx.
- **Cartographer**: Preceptor sub-agent responsible for tech stack fingerprinting using Wappalyzer signatures and httpx probing.
- **Vanguard**: Preceptor sub-agent responsible for port and service scanning using Nmap and masscan.
- **Pilgrim_Crawler**: Preceptor sub-agent responsible for endpoint and path discovery using Katana, Gospider, gau, ffuf, feroxbuster, and x8.
- **Inquisitor**: Hospitaller sub-agent that runs Nuclei community templates and OWASP ZAP active scans.
- **Oracle**: Hospitaller sub-agent that uses LLM reasoning to analyze endpoints and tech stack for subtle and business-logic vulnerabilities.
- **Relic_Hunter**: Hospitaller sub-agent that queries NVD, OSV, ExploitDB, and optionally Shodan/Censys for CVE and exploit intelligence.
- **Holy_Lance**: Marshal sub-agent that generates PoC exploits using LLM-structured prompting and existing exploit templates.
- **Siege_Engine**: Marshal sub-agent that validates PoCs using payload fuzzing via ffuf and wfuzz.
- **Crusade_Planner**: Chaplain sub-agent that constructs the directed attack graph and enumerates multi-step attack paths.
- **Heretic_Judge**: Chaplain sub-agent that scores attack chains with CVSS metrics including temporal and environmental adjustments.
- **Chronicle**: Scribe sub-agent that renders reports in PDF, HTML, Markdown, JSON, and SARIF formats.
- **Holy_Grail**: The vector-indexed CVE and exploit knowledge base used by Seneschal for semantic RAG queries.
- **Vault**: Seneschal's structured vulnerability store for all discovered Vulnerability records.
- **Pilgrim_CLI**: The command-line interface used by operators to start, pause, resume, abort, and monitor campaigns.
- **LLM_Client**: The shared multi-provider LLM client with retry, rate limiting, and token budgeting capabilities.
- **Scope_Enforcer**: The HTTP client middleware layer that hard-enforces the configured scope on every outbound network request.
- **AttackSurface**: The data record collecting all discovered subdomains, hosts, endpoints, technologies, parameters, and certificates for a campaign.
- **Vulnerability**: A data record representing a detected security weakness with severity, CVSS score, evidence, and detection source.
- **ProofOfConcept**: A data record containing a generated or adapted exploit for a specific Vulnerability, with type, content, and validation status.
- **AttackChain**: A data record describing a multi-step attack path with ordered steps, combined severity, and LLM rationale.
- **CrusadeConfig**: The operator-supplied configuration record specifying target URL, scope, AI providers, scan depth, concurrency, rate limits, enabled modules, and output directory.
- **Campaign**: A single execution instance of the Templar framework against a target, identified by a unique campaign ID.
- **Knight**: Any top-level agent module (Preceptor, Hospitaller, Marshal, Chaplain, Scribe) coordinated by the Grand Master.

---

## Requirements

### Requirement 1: Campaign Lifecycle Management

**User Story:** As a security operator, I want to start, pause, resume, and abort campaigns, so that I can control the full offensive lifecycle and adapt to changing conditions without losing work.

#### Acceptance Criteria

1. WHEN an operator provides a CrusadeConfig with a non-empty targetUrl, a non-empty allowedDomains scope list, at least one AIProviderConfig with a non-empty apiKey, a valid scanDepth value, and a writable outputDir, THE Grand_Master SHALL initialize a Campaign via Seneschal and return a unique UUID campaign ID.
2. IF the CrusadeConfig contains zero AIProviderConfig entries or all entries have empty apiKey values, THEN THE Grand_Master SHALL reject the configuration and return an error message identifying the missing provider configuration before creating any Campaign record.
3. WHEN an operator submits a CrusadeConfig, THE Grand_Master SHALL display a legal authorization confirmation prompt via the Pilgrim_CLI that names the targetUrl and allowedDomains before executing any Campaign; IF the operator does not confirm authorization within 60 seconds, THEN THE Grand_Master SHALL return an AUTHORIZATION_DENIED error and not create a Campaign record.
4. WHEN a Campaign is started, THE Grand_Master SHALL sequence agent phases in the following dependency order: Preceptor → Hospitaller → Marshal → Chaplain → Scribe, and SHALL NOT start a phase until all preceding phases have a status of 'complete' or 'degraded' in Seneschal.
5. WHEN the operator issues a pause command for a Campaign with status 'running', THE Grand_Master SHALL signal all in-flight sub-agents to complete their current atomic operation and halt, persist the resulting Campaign state to Seneschal, and set Campaign status to 'paused' within 10 seconds of receiving the command; IF the Campaign status is not 'running', THEN THE Grand_Master SHALL return a CAMPAIGN_NOT_RUNNING error.
6. WHEN the operator issues a resume command for a Campaign with status 'paused', THE Grand_Master SHALL set Campaign status to 'running' and continue execution from the last phase with status other than 'complete'; IF the Campaign status is not 'paused', THEN THE Grand_Master SHALL return a CAMPAIGN_NOT_PAUSED error.
7. WHEN the operator issues an abort command for a Campaign with status 'running' or 'paused', THE Grand_Master SHALL terminate all in-flight operations without waiting for completion, record the Campaign status as 'aborted' in Seneschal, and return within 5 seconds; IF the Campaign status is already 'aborted' or 'complete', THEN THE Grand_Master SHALL return a CAMPAIGN_ALREADY_TERMINAL error.
8. WHEN all five phases complete with status 'complete' or 'degraded', THE Grand_Master SHALL set Campaign status to 'complete' and return a CampaignResult containing the AttackSurface, all Vulnerability records, all ProofOfConcept records, all AttackChain records, and the generated Report.
9. IF any agent phase fails after exhausting all retries, THEN THE Grand_Master SHALL mark that phase as 'degraded', record the failure reason in Seneschal, continue with subsequent phases using artifacts produced by non-failed sub-agents of the degraded phase, and include the degraded phase details in the final report's failure section.
10. IF a Campaign with status 'running' or 'paused' already exists for the exact same targetUrl in Seneschal, THEN THE Grand_Master SHALL reject the new CrusadeConfig and return a DUPLICATE_CAMPAIGN error containing the existing campaign ID.

---

### Requirement 2: State Management and Persistence (Seneschal)

**User Story:** As a security operator, I want all campaign artifacts persisted reliably, so that I can resume interrupted campaigns and review results at any time without data loss.

#### Acceptance Criteria

1. WHEN a Campaign is initialized, THE Seneschal SHALL attempt to create a Campaign state record persisted to SQLite and return a CampaignState object containing the campaign ID and state store reference; IF SQLite state creation fails, THE Seneschal SHALL log the error with the SQLite error code, allow Campaign initialization to proceed using an in-memory state store, and set a 'persistence_degraded' flag on the CampaignState.
2. WHEN Seneschal.storeReconResults is called with a campaignId and AttackSurface, THE Seneschal SHALL persist the artifact keyed by campaignId; WHEN Seneschal.retrieve is called with the same campaignId and DataType 'attack_surface', THE Seneschal SHALL return an AttackSurface where every field value equals the corresponding field value of the originally stored artifact, including all nested arrays and sub-objects.
3. THE Seneschal SHALL preserve the complete artifact structure for all stored types (AttackSurface, Vulnerability, ProofOfConcept, AttackChain) such that, for any stored artifact A, retrieve(store(campaignId, A), campaignId) returns an object where every scalar field equals A's corresponding field, every array field has the same length and element order as A's corresponding field, and every nested object satisfies the same equality definition recursively.
4. WHEN Seneschal.queryKnowledgeBase is called with a non-empty query string, THE Seneschal SHALL compute a cosine similarity score between the query embedding and each indexed CVE description embedding and return up to 20 KBSearchResult records sorted in descending order by cosine similarity score.
5. WHEN Seneschal.exportCampaign is called with a campaignId, THE Seneschal SHALL return a CampaignExport that is fully self-contained (contains all campaign artifacts without external references) and JSON-serializable such that JSON.parse(JSON.stringify(export)) produces an object structurally equivalent to the original CampaignExport.
6. THE Seneschal SHALL cache tech stack fingerprints, CVE lookup results, and LLM similarity scores using the campaign SQLite store with a configurable time-to-live per cache type; IF no TTL is configured for a cache type, THEN THE Seneschal SHALL use a default TTL of 24 hours for that type.
7. WHEN a phase transitions state or an artifact is stored, THE Seneschal SHALL emit a structured progress event within 1 second of the state change; each event SHALL contain the campaign ID, current phase name, phase status, and current artifact counts (subdomain count, endpoint count, vulnerability count, PoC count, chain count).
8. IF any data value matches the pattern of an API key — defined as any string matching `sk-[A-Za-z0-9]{20,}`, `Bearer [A-Za-z0-9\-._~+/]{20,}`, `AIzaSy[A-Za-z0-9\-_]{33}`, or any string of 32 or more alphanumeric characters appearing in a field named key, token, secret, or password — THEN THE Seneschal SHALL replace that value with the literal string `[REDACTED]` before persisting, emitting, or exporting it.

---

### Requirement 3: Reconnaissance and Discovery (Preceptor)

**User Story:** As a security operator, I want comprehensive attack surface discovery, so that no externally reachable assets, endpoints, or technologies are missed before vulnerability analysis begins.

#### Acceptance Criteria

1. THE Preceptor SHALL execute subdomain enumeration by invoking the Crusade_Mapper with Subfinder, Amass, crt.sh, and DNSx tools against the target domain and SHALL merge deduplicated results from all four tools into the AttackSurface.subdomains list.
2. WHEN the Crusade_Mapper has completed and returned a list of discovered subdomains, THE Preceptor SHALL invoke the Cartographer using Wappalyzer signature matching (minimum 7,200 signatures) and httpx probing against all hosts whose DNS resolves and returns HTTP status 100–599 or completes a TCP handshake on any open port.
3. THE Preceptor SHALL execute port and service scanning by invoking the Vanguard using Nmap NSE scripts against the top 1,000 TCP ports and masscan for initial host discovery against all discovered hosts, including service version detection for all open ports.
4. THE Preceptor SHALL execute endpoint, path, and hidden parameter discovery by invoking the Pilgrim_Crawler using Katana, Gospider, gau, ffuf, feroxbuster, and x8 against all hosts that return HTTP status 100–599 or complete a TCP handshake on any discovered open port.
5. THE Preceptor SHALL execute the Crusade_Mapper, Cartographer, and Vanguard sub-agents concurrently; WHEN all three complete, THE Preceptor SHALL start the Pilgrim_Crawler within 5 seconds of the last of the three completing.
6. THE Preceptor SHALL only add an endpoint to the AttackSurface if that endpoint passes the Scope_Enforcer isInScope check; IF an endpoint fails the scope check, THEN THE Preceptor SHALL log a SCOPE_VIOLATION warning to the campaign audit log and discard that endpoint.
7. THE Preceptor SHALL return an AttackSurface where no two endpoint entries share the same (url, method) tuple; IF duplicate (url, method) pairs are discovered, THE Preceptor SHALL merge them into a single endpoint entry, preserving the union of all parameters and sources.
8. WHEN the Pilgrim_Crawler discovers request parameters for an endpoint, THE Preceptor SHALL include all discovered parameters in the corresponding endpoint's parameter list within the AttackSurface, including parameter name, discovered values, and discovery source.
9. IF Wappalyzer signature matching or httpx response headers yield a non-null version value for a detected technology, THEN THE Preceptor SHALL populate the version field of the corresponding TechStackEntry and set the confidence score to a value between 0.0 and 1.0 based on the number and specificity of matching signals.
10. THE Preceptor SHALL record the source tool or tools that contributed to each discovered artifact (subdomain, endpoint, parameter) in the respective source field as a list of tool name strings.
11. IF any single sub-agent (Crusade_Mapper, Cartographer, Vanguard, or Pilgrim_Crawler) fails or times out, THEN THE Preceptor SHALL log a TOOL_FAILURE event for that sub-agent, continue execution with the remaining sub-agents, and mark the AttackSurface with a 'recon_partial' flag indicating which sub-agent failed.

---

### Requirement 4: Vulnerability Analysis (Hospitaller)

**User Story:** As a security operator, I want multi-layered vulnerability detection, so that both known CVEs and subtle business-logic vulnerabilities are identified with evidence and severity ratings.

#### Acceptance Criteria

1. WHEN the Hospitaller receives an AttackSurface, THE Hospitaller SHALL invoke the Inquisitor to scan all discovered endpoints using Nuclei community templates and OWASP ZAP active scan; IF the Inquisitor tool invocation fails or times out after 300 seconds, THEN THE Hospitaller SHALL log a TOOL_FAILURE event, mark the inquisitor sub-task as 'degraded', and continue with the CVE matching and Oracle analysis layers.
2. FOR EACH TechStackEntry in the AttackSurface that has a non-null version field, THE Relic_Hunter SHALL query NVD, OSV, and ExploitDB to retrieve matching CVE identifiers; IF a CVE data source query fails or times out after 30 seconds, THEN THE Relic_Hunter SHALL log the failure, skip that data source for the affected entry, and proceed with results from remaining sources.
3. WHEN the Hospitaller invokes the Oracle, THE Oracle SHALL analyze endpoints in batches of at most 10 at a time, constructing an AnalysisContext that fits within 128,000 tokens containing endpoint descriptions, tech stack information, and raw HTTP responses, and SHALL return AI-derived vulnerability findings for each batch within the configured LLM timeout.
4. IF a vulnerability finding returned by the Oracle references an endpoint URL that does not exist in the AttackSurface, THEN THE Hospitaller SHALL discard that finding, log a DATA_INTEGRITY_WARNING containing the invalid URL and the Oracle batch index, and continue processing remaining findings.
5. WHEN deduplicating findings, THE Hospitaller SHALL consider two findings as duplicates if they share the same endpoint.url, type, and payload values; IF the payload field is null or empty on both findings, THE Hospitaller SHALL consider endpoint.url and type alone as the deduplication key; WHEN merging duplicates, THE Hospitaller SHALL assign the maximum CVSS score across all merged findings and combine all distinct evidence records into a single array.
6. THE Hospitaller SHALL rank the returned Vulnerability list in descending order by severity tier (critical → high → medium → low → info) and then, within each severity tier, in descending order by CVSS score; IF a finding has no CVSS score, THE Hospitaller SHALL treat that finding's CVSS score as 0.0 for sorting purposes.
7. WHERE Shodan or Censys API keys are present in the Campaign configuration, THE Relic_Hunter SHALL enrich discovered hosts with internet-wide scan data within a 60-second timeout per host; IF enrichment times out or the API returns an error, THE Relic_Hunter SHALL log the failure and proceed without enrichment for that host.
8. WHEN the Hospitaller completes analysis, THE Hospitaller SHALL store all Vulnerability records in the Vault via Seneschal before returning results to the Grand_Master.

---

### Requirement 5: Exploit and Proof-of-Concept Generation (Marshal)

**User Story:** As a security operator, I want working proof-of-concept exploits for confirmed vulnerabilities, so that I can demonstrate exploitability to stakeholders and validate findings.

#### Acceptance Criteria

1. WHEN the Marshal receives a list of Vulnerability records, THE Marshal SHALL generate ProofOfConcept records only for vulnerabilities with severity 'medium', 'high', or 'critical'; THE Marshal SHALL skip and not process any Vulnerability with severity 'low' or 'info'.
2. WHEN generating a PoC for a Vulnerability, THE Holy_Lance SHALL first query ExploitDB and the Holy_Grail knowledge base for existing exploits matching the vulnerability's CVE identifiers; IF at least one existing exploit is found, THEN THE Holy_Lance SHALL adapt the best-matching exploit to the target endpoint context; IF no existing exploit is found, THEN THE Holy_Lance SHALL generate a novel PoC via the configured LLM.
3. EVERY ProofOfConcept generated or adapted by THE Holy_Lance SHALL have a type field set to exactly one of: 'curl_command', 'python_script', 'metasploit_module', 'burp_request', or 'browser_steps'; IF an adapted exploit's format does not map to one of these types, THEN THE Holy_Lance SHALL convert it to 'python_script' as the default.
4. WHEN THE Marshal attempts to store a ProofOfConcept, THE Marshal SHALL verify that a Vulnerability record with the matching vulnerabilityId exists in the campaign Vault; IF no matching Vulnerability exists, THEN THE Marshal SHALL discard the ProofOfConcept and log a DATA_INTEGRITY_WARNING.
5. WHEN THE Holy_Lance generates a novel PoC via LLM, THE Holy_Lance SHALL construct a structured prompt containing: vulnerability type, endpoint URL and method, raw evidence (request and response), tech stack context, all CVE identifiers, and the selected output format type; THE Holy_Lance SHALL call the configured LLM with temperature set to 0.2 and SHALL reject any response where the content field is empty or contains no code block.
6. WHEN PoC validation is enabled and the Siege_Engine is invoked for a ProofOfConcept, THE Siege_Engine SHALL attempt execution of the PoC against the target endpoint within a 120-second timeout, record the boolean success result and the first 2,048 characters of output in the ProofOfConcept record, and set the validated field accordingly; IF the Siege_Engine times out, THE Siege_Engine SHALL set validated to false and record 'VALIDATION_TIMEOUT' in validationOutput.
7. IF a Vulnerability's endpoint method is POST, PUT, PATCH, or DELETE AND the destructive_potential classification is 'HIGH', THEN THE Marshal SHALL generate the ProofOfConcept but set validated to false and SHALL NOT invoke the Siege_Engine for that PoC unless the CrusadeConfig contains the allowDestructive flag set to true.
8. WHEN THE Siege_Engine performs payload fuzzing for an injection-class vulnerability, THE Siege_Engine SHALL request a smart wordlist from the configured LLM specifying the exact injection class (e.g., SQL injection, XSS, SSTI) and target tech stack, and SHALL use that LLM-generated wordlist rather than a generic wordlist.
9. WHEN the Marshal completes exploit forging for all eligible vulnerabilities, THE Marshal SHALL store all ProofOfConcept records in Seneschal before returning results to the Grand_Master.

---

### Requirement 6: Attack Chain Analysis (Chaplain)

**User Story:** As a security operator, I want compound attack paths automatically identified and scored, so that I can present realistic worst-case scenarios that combine individually low-severity findings into critical-impact chains.

#### Acceptance Criteria

1. WHEN the Chaplain receives a list of Vulnerability records, THE Chaplain SHALL construct a directed attack graph where each Vulnerability with status 'confirmed' or 'poc_available' is a node, and a directed edge from node A to node B is added if and only if postconditionSatisfies(A, B.preconditions) returns true.
2. EVERY AttackChain returned by THE Chaplain SHALL contain at least 2 and at most 10 ChainStep records.
3. IF the postcondition of step i in an AttackChain does not satisfy the precondition of step i+1 as determined by postconditionSatisfies, THEN THE Chaplain SHALL not include that chain in the results and SHALL log a CHAIN_COHERENCE_VIOLATION event with the chain candidate details.
4. WHEN THE Heretic_Judge computes a combinedCvss score for an AttackChain, THE Heretic_Judge SHALL apply CVSS temporal and environmental metrics and the resulting combinedCvss value SHALL be greater than or equal to the maximum individual CVSS score among all steps in the chain and SHALL not exceed 10.0.
5. EVERY AttackChain SHALL include a non-empty llmRationale string of at least 50 characters generated by the Crusade_Planner explaining specifically why the chain is feasible, referencing the vulnerability types and chaining mechanism.
6. WHEN the Crusade_Planner validates a candidate chain path via LLM reasoning and the LLM determines a path is not feasible, THE Chaplain SHALL exclude that chain from the results and log the exclusion reason; IF the LLM call fails or times out, THE Chaplain SHALL retry once and, if the retry also fails, SHALL exclude the chain and log a CHAIN_VALIDATION_FAILURE event.
7. THE Chaplain SHALL return AttackChain records sorted in descending order by combinedCvss score; IF two chains have equal combinedCvss scores, THE Chaplain SHALL sort them by descending chain length (number of steps), then by ascending creation timestamp as a final tiebreaker.
8. WHEN the Chaplain completes chain analysis, THE Chaplain SHALL store all AttackChain records in Seneschal before returning results to the Grand_Master.
9. IF the Chaplain receives an empty Vulnerability list or a list containing no Vulnerability records with status 'confirmed' or 'poc_available', THEN THE Chaplain SHALL return an empty AttackChain list and emit a CHAIN_ANALYSIS_SKIPPED event with the reason 'no_eligible_vulnerabilities'.

---

### Requirement 7: Report Generation (Scribe)

**User Story:** As a security operator, I want comprehensive campaign reports in multiple formats, so that I can share findings with technical teams, management, and integrate results into CI/CD security workflows.

#### Acceptance Criteria

1. WHEN the operator requests report generation specifying one or more formats, THE Scribe SHALL produce a report file for each requested format from: PDF, HTML, Markdown, JSON, and SARIF; IF an unsupported format is requested, THE Scribe SHALL log an UNSUPPORTED_FORMAT warning and skip that format without failing the other formats.
2. EVERY generated report SHALL include all of the following sections: executive summary (campaign overview, risk rating, top findings), attack surface map (subdomain count, endpoint count, technology inventory), full list of all Vulnerability records with raw request/response evidence, full list of all ProofOfConcept records with content, and full list of all AttackChain records with step descriptions and llmRationale.
3. WHEN generating any report format, THE Chronicle SHALL retrieve all campaign artifacts from Seneschal by campaign ID before rendering, and SHALL not render a report if any required artifact type returns a retrieval error; IF retrieval fails, THE Chronicle SHALL return a REPORT_GENERATION_FAILED error identifying the failed artifact type.
4. WHEN THE Scribe generates the JSON format report, THE JSON document SHALL be well-formed such that JSON.parse(report_content) succeeds without error and produces an object where every Vulnerability, ProofOfConcept, and AttackChain from the campaign can be accessed at the expected path within the CampaignResult schema.
5. WHEN THE Scribe generates the SARIF format report, THE SARIF document SHALL conform to SARIF schema version 2.1.0 such that validating the output against the official SARIF 2.1.0 JSON schema produces zero errors.
6. WHEN a report is written to disk, THE Scribe SHALL store the report file in the directory specified by config.outputDir; IF the outputDir does not exist or is not writable, THEN THE Scribe SHALL return a REPORT_WRITE_FAILED error with the filesystem error details rather than silently failing.
7. WHEN tools or agent phases were marked as 'degraded' or 'TOOL_FAILURE' during a campaign, THE Scribe SHALL include a dedicated 'Operational Issues' section in the report listing each failed component name, failure reason, and timestamp.
8. WHEN any targets were logged as SCOPE_VIOLATION during a campaign, THE Scribe SHALL include an 'Excluded Targets' section in the report listing each blocked URL and the blocking reason.

---

### Requirement 8: AI Provider Configuration and LLM Client

**User Story:** As a security operator, I want to configure multiple AI providers with different roles, so that I can leverage the best available model for each task and fall back gracefully when a provider is unavailable.

#### Acceptance Criteria

1. THE LLM_Client SHALL accept AI provider configurations for each of the following providers: 'openai', 'anthropic', 'google', 'ollama', and 'openrouter'; IF a provider value outside this set is supplied, THE LLM_Client SHALL reject the configuration with an UNSUPPORTED_PROVIDER error at startup.
2. WHEN the Grand_Master or any Knight requires an LLM call for a task of type 'orchestration', 'analysis', or 'exploit_gen', THE LLM_Client SHALL select a provider whose role matches the task type; IF no provider with a matching role exists, THE LLM_Client SHALL select any provider whose role is 'any'; IF no 'any' provider exists either, THE LLM_Client SHALL return a NO_PROVIDER_AVAILABLE error for that task.
3. IF an AI provider returns an HTTP 429 rate limit response or an HTTP 500–599 server error, THEN THE LLM_Client SHALL retry the request using exponential backoff with an initial delay of 1 second, a multiplier of 2, a maximum delay of 60 seconds, and a maximum of 5 retry attempts with random jitter of ±10% on each delay.
4. IF all 5 retry attempts for an AI provider are exhausted for a given LLM task, THEN THE Grand_Master SHALL mark the dependent sub-task as 'degraded', record the final HTTP status code and error message in Seneschal, and continue campaign execution without that AI-dependent result.
5. THE LLM_Client SHALL track cumulative token usage per Campaign; WHEN cumulative token usage reaches 80% of the configured cost threshold, THE LLM_Client SHALL emit a TOKEN_BUDGET_WARNING event via Seneschal; IF the cost threshold is configured as zero or omitted, THEN THE LLM_Client SHALL emit a TOKEN_BUDGET_WARNING immediately upon the first token usage.
6. THE LLM_Client SHALL enforce the maxTokens and temperature values specified in each AIProviderConfig when constructing LLM requests; IF maxTokens is not specified, THE LLM_Client SHALL default to 4,096 tokens; IF temperature is not specified, THE LLM_Client SHALL default to 0.7.
7. IF an API key value appears in any AIProviderConfig, THEN THE LLM_Client SHALL ensure that value never appears verbatim in any log entry, error message, audit log entry, or Seneschal-persisted state record; THE LLM_Client SHALL replace any such value with `[REDACTED]` before output.

---

### Requirement 9: Scope Enforcement

**User Story:** As a security operator, I want strict scope enforcement throughout the entire framework, so that no accidental out-of-scope requests are made and legal and operational boundaries are respected.

#### Acceptance Criteria

1. WHEN any Knight or sub-agent attempts an outbound network request, THE Scope_Enforcer SHALL check if the target hostname matches at least one pattern in allowedDomains; IF the hostname does not match any pattern, THEN THE Scope_Enforcer SHALL block the request, log a SCOPE_VIOLATION event to the campaign audit log, and return a SCOPE_BLOCKED error to the caller without sending the request.
2. WHEN any Knight or sub-agent attempts an outbound network request, THE Scope_Enforcer SHALL check if the URL path matches any regex pattern in excludedPaths; IF the path matches any excluded pattern, THEN THE Scope_Enforcer SHALL block the request, log a SCOPE_VIOLATION event, and return a SCOPE_BLOCKED error to the caller.
3. IF the isInScope function receives an input string that cannot be parsed as a valid URL, THEN THE isInScope function SHALL return false and emit a URL_MALFORMED event without throwing an exception or causing the calling code to error.
4. THE Scope_Enforcer SHALL be implemented as HTTP client middleware that intercepts all outbound requests at the transport layer before any network connection is established, applying scope checks before DNS resolution for all Knights and sub-agents in the framework.
5. WHEN the Scope_Enforcer blocks a request, THE Scope_Enforcer SHALL write an audit log entry containing: ISO-8601 timestamp, the full blocked URL, the blocking rule type (DOMAIN_NOT_ALLOWED or PATH_EXCLUDED), and the matching rule pattern.
6. THE Scope_Enforcer SHALL support wildcard subdomain matching where the pattern `*.example.com` matches `api.example.com` and `sub.api.example.com` but does NOT match the apex domain `example.com`; IF the operator intends to include the apex domain, it must be listed separately in allowedDomains.
7. IF the allowedDomains list in CrusadeConfig is empty, THEN THE Scope_Enforcer SHALL block all outbound requests and return a SCOPE_CONFIGURATION_ERROR during campaign initialization, before any agent phase begins.

---

### Requirement 10: Command-Line Interface (Pilgrim CLI)

**User Story:** As a security operator, I want a full-featured command-line interface, so that I can configure, control, and monitor campaigns from the terminal with clear feedback and safety guardrails.

#### Acceptance Criteria

1. THE Pilgrim_CLI SHALL provide the following commands: `crusade start`, `crusade pause <campaignId>`, `crusade resume <campaignId>`, `crusade abort <campaignId>`, and `crusade status <campaignId>`, each accepting a campaign ID or target URL as the primary identifier.
2. WHEN the operator runs `crusade start`, THE Pilgrim_CLI SHALL display a legal authorization confirmation prompt that names the targetUrl, the allowedDomains list, and the scan depth before initiating the Campaign; IF the operator responds with anything other than 'yes' or 'y' (case-insensitive), THEN THE Pilgrim_CLI SHALL exit with code 1 without starting the Campaign.
3. WHEN the operator runs `crusade start`, THE Pilgrim_CLI SHALL accept a YAML configuration file via the `--config <path>` flag and SHALL validate the file against the CrusadeConfig schema before passing it to the Grand_Master; IF the file is missing required fields or contains invalid values, THE Pilgrim_CLI SHALL print each validation error and exit with code 2 before creating a Campaign.
4. WHEN a Campaign is running, THE Pilgrim_CLI SHALL stream progress output at most every 2 seconds sourced from Seneschal progress events, displaying: current phase name, active sub-agent name, elapsed time, and current counts of discovered subdomains, endpoints, vulnerabilities, PoCs, and chains.
5. IF the `--allow-destructive` flag is not present in the `crusade start` invocation, THEN THE Pilgrim_CLI SHALL pass allowDestructive=false in the CrusadeConfig, causing the Marshal to skip validation for any PoC classified as 'HIGH' destructive_potential.
6. IF a Campaign with status 'running' or 'paused' already exists for the same targetUrl, THE Pilgrim_CLI SHALL display the message 'A campaign for this target is already active (ID: <campaignId>)' and exit with code 3 without starting a new Campaign.
7. WHEN a Campaign completes with status 'complete' or 'partial', THE Pilgrim_CLI SHALL print a completion summary containing: the output directory path, one line per report format generated, total vulnerability count broken down by severity, total AttackChain count, and total ProofOfConcept count.

---

### Requirement 11: Campaign Resilience and Audit Logging

**User Story:** As a security operator, I want campaigns to be resilient to interruptions and all actions to be auditable, so that I can trust the results, resume work without data loss, and maintain legal defensibility.

#### Acceptance Criteria

1. THE framework SHALL support resuming a Campaign from the last successfully completed phase; WHEN the operator issues a resume command, THE Grand_Master SHALL query Seneschal for phase statuses and SHALL skip all phases with status 'complete', executing only phases with status other than 'complete'.
2. THE Grand_Master SHALL persist Campaign phase status to Seneschal immediately after each phase transitions to 'complete' or 'degraded', so that an interruption at any point after that transition does not require re-executing the completed phase.
3. WHEN any external tool (Nuclei, Nmap, ffuf, OWASP ZAP, or any other) is executed, THE framework SHALL write an audit log entry containing: ISO-8601 timestamp, tool name, full invocation command-line arguments, exit code (or 'TIMEOUT' if timed out), and the first 4,096 characters of combined stdout/stderr output.
4. IF an external tool exits with a non-zero exit code or exceeds its configured timeout (default 300 seconds if not specified in CrusadeConfig), THEN THE framework SHALL retry the tool invocation exactly once with the maxConcurrency reduced to half the configured value (minimum 1); IF the retry also fails or times out, THEN THE framework SHALL record the result as 'TOOL_FAILURE' and continue.
5. THE Grand_Master SHALL enforce the maxConcurrency value from CrusadeConfig as a hard upper bound on the number of concurrently executing sub-agent goroutines/threads at any point during Campaign execution; IF adding a new sub-agent would exceed maxConcurrency, THE Grand_Master SHALL queue that sub-agent until a slot becomes available.
6. THE framework SHALL apply per-host rate limiting as specified in RateLimitConfig, ensuring that the total number of outbound requests per second to any single hostname does not exceed the configured requests-per-second value; IF no RateLimitConfig is provided, THE framework SHALL default to 10 requests per second per host.
7. THE framework SHALL cache LLM similarity scores computed by postconditionSatisfies using the campaign-scoped SQLite store keyed by the exact concatenation of the postcondition string and precondition string; WHEN postconditionSatisfies is called with a pair of strings that match a cached key within the same Campaign, THE framework SHALL return the cached score without making an LLM call.
