package holygrail

import (
	"fmt"
	"sync"

	"github.com/templar-framework/templar/internal/shared"
)

const maxResults = 20

// KnowledgeBase is the Holy Grail RAG knowledge base. It wraps a VectorStore
// and exposes a high-level query interface over an indexed set of CVE/exploit
// descriptions. The index is built lazily on first query and is safe for
// concurrent use after initialisation.
type KnowledgeBase struct {
	mu    sync.RWMutex
	store *VectorStore
	ready bool
}

// NewKnowledgeBase creates and initialises a KnowledgeBase, seeding it with
// well-known vulnerability descriptions for common CVE classes.
func NewKnowledgeBase() *KnowledgeBase {
	kb := &KnowledgeBase{
		store: NewVectorStore(),
	}
	kb.seed()
	return kb
}

// QueryKnowledgeBase performs a semantic search over the knowledge base and
// returns up to 20 KBSearchResult records sorted by descending cosine
// similarity score, as required by Requirement 2.4.
func (kb *KnowledgeBase) QueryKnowledgeBase(query string) []shared.KBSearchResult {
	if query == "" {
		return nil
	}

	kb.mu.RLock()
	defer kb.mu.RUnlock()

	hits := kb.store.Search(query, maxResults)
	if len(hits) == 0 {
		return nil
	}

	results := make([]shared.KBSearchResult, len(hits))
	for i, h := range hits {
		results[i] = shared.KBSearchResult{
			ID:          h.ID,
			Content:     h.Content,
			Score:       h.Score,
			Description: h.Description,
		}
	}
	return results
}

// seed populates the knowledge base with a representative set of CVE
// descriptions covering the most common web and network vulnerability classes.
func (kb *KnowledgeBase) seed() {
	entries := []struct {
		id          string
		content     string
		description string
	}{
		// ── Cross-Site Scripting (XSS) ──────────────────────────────────────────
		{
			id: "CVE-XSS-REFLECTED",
			content: "Reflected cross-site scripting XSS vulnerability allows remote attackers to inject " +
				"arbitrary JavaScript HTML code into web pages viewed by other users. The attacker " +
				"crafts a malicious URL containing script tags or event handlers that are reflected " +
				"back in the server response without proper output encoding or sanitisation.",
			description: "Reflected XSS — injected script executes in victim's browser via crafted URL",
		},
		{
			id: "CVE-XSS-STORED",
			content: "Stored persistent cross-site scripting XSS vulnerability in user-supplied input " +
				"fields. Malicious script is saved in the application database and executed in every " +
				"victim's browser that renders the affected page. Affects comment sections, profile " +
				"fields, forum posts, and similar persistent storage points.",
			description: "Stored XSS — persisted malicious script executes on every page render",
		},
		{
			id: "CVE-XSS-DOM",
			content: "DOM-based cross-site scripting XSS vulnerability where client-side JavaScript " +
				"processes untrusted data from sources such as location.hash, document.referrer, or " +
				"postMessage and writes it to dangerous sinks including innerHTML, document.write, " +
				"eval, or setTimeout without sanitisation.",
			description: "DOM XSS — client-side script writes unsanitised data to dangerous DOM sinks",
		},

		// ── SQL Injection (SQLi) ─────────────────────────────────────────────────
		{
			id: "CVE-SQLI-CLASSIC",
			content: "SQL injection vulnerability allows remote attackers to execute arbitrary SQL " +
				"commands via unsanitised user input embedded in database queries. Exploitation can " +
				"result in authentication bypass, data exfiltration, data manipulation, and in some " +
				"configurations remote code execution via xp_cmdshell or file write operations.",
			description: "Classic SQLi — arbitrary SQL execution via unsanitised query parameters",
		},
		{
			id: "CVE-SQLI-BLIND",
			content: "Blind SQL injection vulnerability where the application does not directly return " +
				"query results but attackers can infer database contents through boolean-based or " +
				"time-based techniques. Boolean inference uses conditional expressions that alter " +
				"application responses; time-based uses SLEEP or WAITFOR DELAY statements to " +
				"extract data bit by bit.",
			description: "Blind SQLi — data extracted via boolean or time-based inference channels",
		},
		{
			id: "CVE-SQLI-OOB",
			content: "Out-of-band SQL injection vulnerability that exfiltrates data through DNS or HTTP " +
				"requests initiated by the database server using functions such as UTL_HTTP, LOAD_FILE, " +
				"xp_dirtree, or DNS lookup primitives. Useful when in-band channels are unavailable.",
			description: "OOB SQLi — data exfiltration via DNS/HTTP callbacks from the database engine",
		},

		// ── Server-Side Request Forgery (SSRF) ──────────────────────────────────
		{
			id: "CVE-SSRF-BASIC",
			content: "Server-side request forgery SSRF vulnerability allows an attacker to induce the " +
				"server-side application to make HTTP requests to an arbitrary domain or internal IP " +
				"address chosen by the attacker. This can expose internal services, cloud metadata " +
				"endpoints such as 169.254.169.254, and internal network resources behind firewalls.",
			description: "SSRF — server makes attacker-controlled outbound requests to internal resources",
		},
		{
			id: "CVE-SSRF-CLOUD-METADATA",
			content: "SSRF vulnerability targeting cloud instance metadata service IMDS. Attacker induces " +
				"the application to fetch http://169.254.169.254/latest/meta-data/ or similar endpoints, " +
				"potentially exposing IAM credentials, private keys, instance identity tokens, and " +
				"other sensitive cloud configuration data leading to privilege escalation.",
			description: "SSRF targeting cloud metadata — exposes IAM credentials and instance tokens",
		},

		// ── Remote Code Execution (RCE) ──────────────────────────────────────────
		{
			id: "CVE-RCE-DESERIALIZATION",
			content: "Remote code execution via insecure deserialization of untrusted Java, PHP, Python, " +
				"or .NET objects. Attackers craft malicious serialized payloads using gadget chains " +
				"such as CommonsCollections, Spring, or Groovy to achieve arbitrary command execution " +
				"on the server. Common entry points include HTTP request bodies, cookies, and session " +
				"storage.",
			description: "RCE via insecure deserialization — gadget chain execution on untrusted objects",
		},
		{
			id: "CVE-RCE-COMMAND-INJECTION",
			content: "Remote code execution via OS command injection. Unsanitised user input is passed " +
				"to shell functions such as system(), exec(), popen(), or subprocess without proper " +
				"escaping or argument array usage. Attackers inject shell metacharacters like semicolon, " +
				"pipe, backtick, or dollar sign to execute arbitrary OS commands with the web server " +
				"process privileges.",
			description: "RCE via OS command injection — shell metacharacter injection into exec calls",
		},
		{
			id: "CVE-RCE-FILE-UPLOAD",
			content: "Remote code execution via unrestricted file upload. The application allows uploading " +
				"files with executable extensions such as PHP, JSP, ASP, or ASPX to a web-accessible " +
				"directory without validation. Attackers upload web shells to gain arbitrary code " +
				"execution on the server.",
			description: "RCE via malicious file upload — executable web shell uploaded to accessible directory",
		},

		// ── Insecure Direct Object Reference (IDOR) ─────────────────────────────
		{
			id: "CVE-IDOR-BASIC",
			content: "Insecure direct object reference IDOR vulnerability allows attackers to access or " +
				"modify resources belonging to other users by manipulating predictable object identifiers " +
				"in API requests such as numeric user IDs, order numbers, or account references. " +
				"Insufficient authorisation checks enable horizontal privilege escalation.",
			description: "IDOR — horizontal privilege escalation by manipulating object reference parameters",
		},
		{
			id: "CVE-IDOR-MASS-ASSIGNMENT",
			content: "Mass assignment vulnerability combined with IDOR where the application automatically " +
				"binds request parameters to model attributes without an allowlist. Attackers supply " +
				"additional parameters such as isAdmin, role, or balance to elevate privileges or " +
				"modify protected fields on objects they should only partially control.",
			description: "Mass assignment / IDOR — attacker-controlled fields bypass authorisation checks",
		},

		// ── XML External Entity (XXE) ────────────────────────────────────────────
		{
			id: "CVE-XXE-BASIC",
			content: "XML external entity XXE injection vulnerability in XML parsing components. " +
				"Attackers craft malicious XML documents with DOCTYPE declarations referencing external " +
				"entities pointing to sensitive local files like /etc/passwd, /etc/shadow, " +
				"or internal network resources. Can lead to local file disclosure, SSRF, and " +
				"denial of service.",
			description: "XXE — external entity injection reads local files and internal network resources",
		},
		{
			id: "CVE-XXE-BLIND",
			content: "Blind XXE injection vulnerability where direct entity content is not returned in the " +
				"response. Exploitation relies on out-of-band DNS or HTTP callbacks using parameter " +
				"entities and external DTDs to exfiltrate file contents or confirm internal network " +
				"access without visible output.",
			description: "Blind XXE — out-of-band exfiltration via parameter entity DNS/HTTP callbacks",
		},

		// ── Server-Side Template Injection (SSTI) ───────────────────────────────
		{
			id: "CVE-SSTI-JINJA2",
			content: "Server-side template injection SSTI vulnerability in Jinja2 template engine. " +
				"Unsanitised user input is passed directly into template rendering contexts allowing " +
				"expression evaluation. Payload such as {{7*7}} confirms SSTI; exploitation via " +
				"__class__.__mro__ chains or config object access can achieve arbitrary Python code " +
				"execution and full RCE.",
			description: "SSTI in Jinja2 — template expression injection leads to Python RCE",
		},
		{
			id: "CVE-SSTI-TWIG",
			content: "Server-side template injection in Twig PHP template engine. Attacker-controlled " +
				"input rendered in Twig templates enables expression evaluation. Using _self.env " +
				"and getFilter or registerUndefinedFilterCallback with system function reference, " +
				"attackers can achieve arbitrary PHP code execution on the server.",
			description: "SSTI in Twig (PHP) — template injection enables arbitrary PHP code execution",
		},
		{
			id: "CVE-SSTI-FREEMARKER",
			content: "Server-side template injection in Apache FreeMarker template engine. Attacker " +
				"injects FreeMarker directives such as <#assign> with freemarker.template.utility.Execute " +
				"or Runtime.exec() to execute arbitrary Java code or OS commands on the server.",
			description: "SSTI in FreeMarker — directive injection executes arbitrary Java OS commands",
		},

		// ── Path Traversal / LFI ────────────────────────────────────────────────
		{
			id: "CVE-PATH-TRAVERSAL",
			content: "Path traversal directory traversal vulnerability allows attackers to read files " +
				"outside the intended web root directory. By supplying sequences such as ../, ..\\, " +
				"or URL-encoded variants %2e%2e%2f in file path parameters, attackers can access " +
				"sensitive files including /etc/passwd, SSH private keys, application configuration " +
				"files, and source code.",
			description: "Path traversal — ../ sequences bypass web root to read arbitrary server files",
		},
		{
			id: "CVE-LFI-PHP",
			content: "Local file inclusion LFI vulnerability in PHP applications using include, require, " +
				"include_once, or require_once with user-controlled path. Attackers include sensitive " +
				"local files, PHP session files to achieve code execution, or use php://filter wrappers " +
				"to read encoded source code. Combined with file upload leads to RCE.",
			description: "LFI in PHP — include/require with attacker-controlled path enables file disclosure and RCE",
		},

		// ── Cross-Site Request Forgery (CSRF) ────────────────────────────────────
		{
			id: "CVE-CSRF",
			content: "Cross-site request forgery CSRF vulnerability where state-changing operations lack " +
				"unpredictable anti-CSRF tokens. Attackers craft malicious web pages that trigger " +
				"authenticated requests to the target application using the victim's active session " +
				"cookies. Commonly exploits password changes, fund transfers, account settings, and " +
				"administrative actions.",
			description: "CSRF — forged authenticated state-changing requests via victim's active session",
		},

		// ── Authentication / Session Management ─────────────────────────────────
		{
			id: "CVE-AUTH-BROKEN",
			content: "Broken authentication vulnerability in session token generation or validation. " +
				"Predictable session IDs, weak token entropy, missing session expiry, session fixation, " +
				"or improper session invalidation on logout allow attackers to hijack authenticated " +
				"sessions, impersonate users, or maintain persistent access after credential changes.",
			description: "Broken authentication — weak or predictable session tokens enable session hijacking",
		},
		{
			id: "CVE-JWT-NONE-ALG",
			content: "JWT none algorithm vulnerability where the application accepts JSON Web Tokens " +
				"with algorithm set to none or alg header changed to HS256 using the public RSA key " +
				"as HMAC secret. Attackers forge arbitrary JWT payloads to bypass authentication, " +
				"escalate privileges, or impersonate any user account.",
			description: "JWT alg:none — forged tokens bypass authentication by disabling signature verification",
		},

		// ── Sensitive Data Exposure ──────────────────────────────────────────────
		{
			id: "CVE-SENSITIVE-EXPOSURE",
			content: "Sensitive data exposure vulnerability due to insufficient encryption, weak cipher " +
				"suites, cleartext transmission of credentials or PII over HTTP, hardcoded secrets " +
				"in source code or configuration files, or unprotected backup files and debug endpoints " +
				"accessible without authentication.",
			description: "Sensitive data exposure — cleartext transmission or unprotected storage of PII and credentials",
		},

		// ── Security Misconfiguration ────────────────────────────────────────────
		{
			id: "CVE-MISCONFIG-CORS",
			content: "CORS misconfiguration vulnerability where the Access-Control-Allow-Origin header " +
				"reflects the attacker's origin or is set to wildcard with Access-Control-Allow-Credentials " +
				"true. Allows malicious websites to make cross-origin requests with victim credentials " +
				"and read sensitive API responses, enabling account takeover and data exfiltration.",
			description: "CORS misconfiguration — reflected origin with credentials allows cross-origin data theft",
		},
		{
			id: "CVE-MISCONFIG-DEBUG",
			content: "Security misconfiguration exposing debug endpoints, stack traces, verbose error " +
				"messages, admin panels, or development frameworks in production environments. " +
				"Examples include Django DEBUG=True, PHP display_errors on, exposed /actuator endpoints, " +
				"phpinfo() pages, and .git directories serving source code.",
			description: "Debug/admin endpoint exposure — development artefacts expose source code and internals",
		},

		// ── Open Redirect ────────────────────────────────────────────────────────
		{
			id: "CVE-OPEN-REDIRECT",
			content: "Open redirect vulnerability where user-supplied URLs in redirect or returnUrl " +
				"parameters are not validated against an allowlist. Attackers craft phishing URLs " +
				"through the trusted domain that redirect victims to malicious sites. Can be chained " +
				"with OAuth flows to steal authorisation codes or tokens via the redirect_uri parameter.",
			description: "Open redirect — unvalidated redirect parameter enables phishing and OAuth token theft",
		},

		// ── Prototype Pollution / Node.js ─────────────────────────────────────────
		{
			id: "CVE-PROTOTYPE-POLLUTION",
			content: "Prototype pollution vulnerability in JavaScript or Node.js applications where " +
				"attacker-controlled keys such as __proto__ or constructor.prototype are used in " +
				"recursive object merge, deep clone, or path-set operations. Poisoning Object.prototype " +
				"can lead to property injection, authentication bypass, remote code execution via " +
				"template engines, and denial of service.",
			description: "Prototype pollution — __proto__ injection poisons Object.prototype enabling RCE or auth bypass",
		},

		// ── Log4Shell ────────────────────────────────────────────────────────────
		{
			id: "CVE-2021-44228",
			content: "Log4Shell CVE-2021-44228 critical remote code execution vulnerability in Apache " +
				"Log4j 2.x JNDI lookup feature. Attacker-controlled string containing ${jndi:ldap://} " +
				"expression logged by the application triggers outbound LDAP or RMI lookup to attacker " +
				"server, allowing delivery of malicious Java class and arbitrary RCE on the vulnerable " +
				"host. Affects all Log4j 2.x versions before 2.15.0.",
			description: "Log4Shell (CVE-2021-44228) — JNDI injection in Log4j 2.x enables unauthenticated RCE",
		},

		// ── Spring4Shell ─────────────────────────────────────────────────────────
		{
			id: "CVE-2022-22965",
			content: "Spring4Shell CVE-2022-22965 critical remote code execution vulnerability in Spring " +
				"MVC and Spring WebFlux running on JDK 9+. Exploits ClassLoader access via data binding " +
				"to write malicious JSP web shell to the Tomcat webroot, allowing unauthenticated " +
				"remote code execution. Affects Spring Framework 5.3.x before 5.3.18 and 5.2.x before " +
				"5.2.20.",
			description: "Spring4Shell (CVE-2022-22965) — ClassLoader manipulation writes web shell via data binding",
		},

		// ── Shellshock ───────────────────────────────────────────────────────────
		{
			id: "CVE-2014-6271",
			content: "Shellshock CVE-2014-6271 critical remote code execution vulnerability in GNU Bash " +
				"through 4.3. Attacker injects malicious function definitions via environment variables " +
				"such as HTTP_COOKIE, HTTP_USER_AGENT, or QUERY_STRING in CGI scripts, causing Bash " +
				"to execute arbitrary commands. Affects web servers using CGI with Bash as the shell " +
				"interpreter.",
			description: "Shellshock (CVE-2014-6271) — Bash function injection via CGI environment variables",
		},

		// ── Heartbleed ───────────────────────────────────────────────────────────
		{
			id: "CVE-2014-0160",
			content: "Heartbleed CVE-2014-0160 critical memory disclosure vulnerability in OpenSSL 1.0.1 " +
				"through 1.0.1f TLS heartbeat extension. Attacker sends malformed heartbeat request " +
				"with mismatched payload length, causing the server to return up to 64KB of process " +
				"memory potentially containing private keys, session tokens, passwords, and plaintext " +
				"communications.",
			description: "Heartbleed (CVE-2014-0160) — OpenSSL heartbeat reads up to 64KB server memory including keys",
		},

		// ── EternalBlue / MS17-010 ──────────────────────────────────────────────
		{
			id: "CVE-2017-0144",
			content: "MS17-010 EternalBlue CVE-2017-0144 critical remote code execution vulnerability in " +
				"Microsoft SMBv1 protocol implementation. Exploits buffer overflow in transaction response " +
				"handling allowing unauthenticated attackers to execute arbitrary code with SYSTEM " +
				"privileges. Used by WannaCry and NotPetya ransomware for lateral movement across " +
				"Windows networks.",
			description: "EternalBlue (MS17-010) — SMBv1 buffer overflow enables SYSTEM-level RCE without authentication",
		},

		// ── Insecure Deserialization (PHP) ─────────────────────────────────────
		{
			id: "CVE-PHP-DESERIALIZATION",
			content: "PHP object injection via unserialize() vulnerability where attacker-controlled " +
				"serialized PHP data is passed to unserialize() function. Magic methods __wakeup, " +
				"__destruct, and __toString in existing classes form gadget chains enabling file deletion, " +
				"arbitrary file write, SQL injection, or remote code execution depending on available " +
				"classes in the application.",
			description: "PHP unserialize injection — magic method gadget chains enable RCE via object injection",
		},

		// ── HTTP Request Smuggling ──────────────────────────────────────────────
		{
			id: "CVE-HTTP-SMUGGLING",
			content: "HTTP request smuggling vulnerability caused by discrepancy in how front-end and " +
				"back-end servers parse Transfer-Encoding and Content-Length headers. Attackers craft " +
				"ambiguous requests to poison the back-end TCP socket, enabling bypassing of WAFs " +
				"and security controls, cache poisoning, session hijacking, and privilege escalation.",
			description: "HTTP request smuggling — TE/CL header ambiguity bypasses front-end security controls",
		},

		// ── Subdomain Takeover ──────────────────────────────────────────────────
		{
			id: "CVE-SUBDOMAIN-TAKEOVER",
			content: "Subdomain takeover vulnerability where a dangling DNS CNAME record points to an " +
				"unclaimed third-party service such as GitHub Pages, Heroku, AWS S3, Azure, or Fastly. " +
				"Attackers register the referenced service under their account, serving malicious " +
				"content on the victim's subdomain to perform phishing, cookie theft, and CSP bypass.",
			description: "Subdomain takeover — dangling CNAME to unclaimed service enables content injection on trusted domain",
		},

		// ── Race Condition / TOCTOU ─────────────────────────────────────────────
		{
			id: "CVE-RACE-CONDITION",
			content: "Race condition time-of-check to time-of-use TOCTOU vulnerability in concurrent " +
				"request handling. Attackers send simultaneous requests to trigger business logic flaws " +
				"such as double spending gift card balances, bypassing one-time token validation, " +
				"duplicating coupon usage, or exceeding rate limits through parallel execution before " +
				"server-side locks are acquired.",
			description: "Race condition / TOCTOU — concurrent requests exploit business logic before locks are acquired",
		},

		// ── GraphQL specific ────────────────────────────────────────────────────
		{
			id: "CVE-GRAPHQL-INTROSPECTION",
			content: "GraphQL introspection and batching abuse vulnerability. Unrestricted introspection " +
				"exposes full schema including internal types and mutations. Batching allows sending " +
				"hundreds of operations in a single request to bypass rate limiting. Query depth and " +
				"complexity limits absent, enabling denial of service via deeply nested queries. " +
				"Missing authorisation on resolvers leads to IDOR and data leakage.",
			description: "GraphQL introspection/batching — schema disclosure and DoS via unrestricted query depth",
		},
	}

	docs := make([]*Document, len(entries))
	for i, e := range entries {
		docs[i] = &Document{
			ID:          e.id,
			Content:     e.content,
			Description: e.description,
		}
	}
	kb.store.AddDocuments(docs)
	kb.ready = true
}

// Size returns the number of indexed documents.
func (kb *KnowledgeBase) Size() int {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	return len(kb.store.docs)
}

// IndexDocument adds a single document to the knowledge base at runtime and
// rebuilds the TF-IDF index. Thread-safe.
func (kb *KnowledgeBase) IndexDocument(id, content, description string) {
	kb.mu.Lock()
	defer kb.mu.Unlock()

	doc := &Document{
		ID:          id,
		Content:     content,
		Description: description,
	}
	kb.store.AddDocuments([]*Document{doc})
}

// FormatID returns a consistently formatted knowledge base entry ID given a
// numeric index, useful for dynamic ingestion of CVE data from NVD.
func FormatID(prefix string, idx int) string {
	return fmt.Sprintf("%s-%04d", prefix, idx)
}
