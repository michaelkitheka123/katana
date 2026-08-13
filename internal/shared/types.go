package shared

import (
	"time"
)

// Enumerations
type ScanDepth string

const (
	ScanDepthShallow  ScanDepth = "shallow"
	ScanDepthStandard ScanDepth = "standard"
	ScanDepthDeep     ScanDepth = "deep"
)

type VulnType string

const (
	VulnTypeInjection VulnType = "injection"
	VulnTypeXSS       VulnType = "xss"
	VulnTypeCSRF      VulnType = "csrf"
	VulnTypeIDOR      VulnType = "idor"
	VulnTypeSSRF      VulnType = "ssrf"
	VulnTypeRCE       VulnType = "rce"
	VulnTypeLFI       VulnType = "lfi"
	VulnTypeSQLi      VulnType = "sqli"
	VulnTypeMisc      VulnType = "misc"
)

type AuthType string

const (
	AuthTypeNone   AuthType = "none"
	AuthTypeBasic  AuthType = "basic"
	AuthTypeBearer AuthType = "bearer"
	AuthTypeOAuth  AuthType = "oauth"
	AuthTypeCustom AuthType = "custom"
)

type TechCategory string

const (
	TechCategoryOS       TechCategory = "os"
	TechCategoryWeb      TechCategory = "web_server"
	TechCategoryDB       TechCategory = "database"
	TechCategoryLang     TechCategory = "language"
	TechCategoryFramework TechCategory = "framework"
	TechCategoryMisc     TechCategory = "misc"
)

type DataType string

const (
	DataTypeString  DataType = "string"
	DataTypeInteger DataType = "integer"
	DataTypeBoolean DataType = "boolean"
	DataTypeJSON    DataType = "json"
	DataTypeXML     DataType = "xml"
)

type PoCType string

const (
	PoCTypeCurl       PoCType = "curl_command"
	PoCTypePython     PoCType = "python_script"
	PoCTypeMetasploit PoCType = "metasploit_module"
	PoCTypeBurp       PoCType = "burp_request"
	PoCTypeBrowser    PoCType = "browser_steps"
)

// Structs

type CrusadeConfig struct {
	TargetURL      string
	AllowedDomains []string
	AIProviders    []AIProviderConfig
	MCPServers     []MCPServerConfig // optional MCP tool servers
	ScanDepth      ScanDepth
	OutputDir      string
	Scope          ScopeConfig
	RateLimit      RateLimitConfig
	CVESources     []CVESourceConfig `yaml:"cveSources,omitempty"` // CVE source configuration
}

type ScopeConfig struct {
	AllowedDomains []string
	ExcludedPaths  []string
}

type AIProviderConfig struct {
	Name        string
	APIKey      string
	MaxTokens   int
	Temperature float64
	Role        string
}

type RateLimitConfig struct {
	RequestsPerSecond int
	TimeoutSeconds    int
}

// CVE Source Configuration Types

// CVESourceType represents the type of CVE source
type CVESourceType string

const (
	CVESourceTypeNVD        CVESourceType = "nvd"
	CVESourceTypeOSV        CVESourceType = "osv"
	CVESourceTypeHackerOne  CVESourceType = "hackerone"
	CVESourceTypeGitHub     CVESourceType = "github"
	CVESourceTypeExploitDB  CVESourceType = "exploitdb"
	CVESourceTypeCustomFeed CVESourceType = "custom_feed"
)

// CVESourceConfig represents configuration for a single CVE source
type CVESourceConfig struct {
	Name    CVESourceType `yaml:"name"`
	Enabled bool          `yaml:"enabled"`
	
	// Source-specific configuration fields
	HackerOneAPIKey      string `yaml:"hackeroneApiKey,omitempty"`
	HackerOneProgramHandle string `yaml:"hackeroneProgramHandle,omitempty"`
	GitHubToken          string `yaml:"githubToken,omitempty"`
	FeedURL              string `yaml:"feedUrl,omitempty"`
	FeedFormat           string `yaml:"feedFormat,omitempty"` // rss, json, atom
	FeedAuth             *FeedAuthConfig `yaml:"feedAuth,omitempty"`
	
	// Common configuration fields
	TimeoutSeconds  int `yaml:"timeoutSeconds,omitempty"`
	Priority        int `yaml:"priority,omitempty"`
	FreshnessThresholdDays int `yaml:"freshnessThresholdDays,omitempty"`
}

// FeedAuthConfig represents authentication for custom vulnerability feeds
type FeedAuthConfig struct {
	Type     string `yaml:"type"` // basic, bearer, api_key
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	Token    string `yaml:"token,omitempty"`
	APIKey   string `yaml:"apiKey,omitempty"`
	APIKeyHeader string `yaml:"apiKeyHeader,omitempty"` // e.g., "X-API-Key"
}

// CVESourceMetrics tracks performance metrics for CVE sources
type CVESourceMetrics struct {
	SourceName          string
	QueryCount          int64
	SuccessCount        int64
	FailureCount        int64
	AverageResponseTime float64 // in seconds
	LastQueryTime       time.Time
	LastSuccessTime     time.Time
	LastFailureTime     time.Time
	ConsecutiveFailures int
	TotalVulnerabilitiesFound int64
}

type AttackSurface struct {
	Subdomains []DiscoveredSubdomain
	Hosts      []DiscoveredHost
	Endpoints  []DiscoveredEndpoint
}

type DiscoveredSubdomain struct {
	Domain string
	IP     string
	Source []string
}

type DiscoveredHost struct {
	IP        string
	OpenPorts []int
	Services  []string
}

type DiscoveredEndpoint struct {
	URL        string
	Method     string
	Parameters []DiscoveredParameter
	Source     []string
}

type DiscoveredParameter struct {
	Name   string
	Values []string
	Source []string
}

type TechStackEntry struct {
	Name       string
	Category   TechCategory
	Version    *string
	Confidence float64
}

type CertificateInfo struct {
	Issuer      string
	Subject     string
	ValidFrom   time.Time
	ValidTo     time.Time
	Fingerprint string
}

type Vulnerability struct {
	ID               string
	Title            string
	Description      string
	Severity         string
	CVSSScore        float64
	Endpoint         DiscoveredEndpoint
	Type             VulnType
	Status           string
	Evidence         []VulnEvidence
	DisclosureDate   time.Time
	Tags             []string
	ExploitAvailable bool
	Remediation      string
}

type VulnEvidence struct {
	Type            string
	MatchedTemplate string
	Details         string
}

type RawHTTPRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

type RawHTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}

type ProofOfConcept struct {
	ID              string
	VulnerabilityID string
	Type            PoCType
	Content         string
	Validated       bool
	ValidationOutput string
}

type AttackChain struct {
	ID           string
	Steps        []ChainStep
	CombinedCVSS float64
	Impact       ChainImpact
	CreatedAt    time.Time
}

type ChainStep struct {
	Vulnerability Vulnerability
	Preconditions []string
	Postconditions []string
}

type ChainImpact struct {
	Level       string
	Description string
}

const (
	CampaignStatusRunning   = "running"
	CampaignStatusFailed    = "failed"
	CampaignStatusCompleted = "completed"
)

type CampaignState struct {
	ID     string
	Status string
	Phases map[string]string
}

type CampaignResult struct {
	CampaignID    string
	AttackSurface AttackSurface
	Vulnerabilities []Vulnerability
	PoCs          []ProofOfConcept
	AttackChains  []AttackChain
}

type CampaignExport struct {
	Result CampaignResult
}

type KBSearchResult struct {
	ID          string
	Content     string
	Score       float64
	Description string
}

type Report struct {
	Format string
	Data   string
}

type ReportOptions struct {
	IncludePoCs    bool
	IncludeChains  bool
	Formats        []string
}

type ModuleFlags struct {
	AllowDestructive bool
}

// MCPServerConfig describes an MCP server that Templar can connect to in order
// to invoke security tools without requiring local binary installations.
type MCPServerConfig struct {
	// Name is a short identifier used to match this server to a Knight sub-agent.
	// Known names: "pd-tools-mcp", "nuclei-mcp", "mcp-for-security", "fetch-mcp"
	Name    string
	Command string   // e.g. "npx", "uvx", "python"
	Args    []string // e.g. ["-y", "@intelligent-ears/pd-tools-mcp"]
	Env     []string // additional env vars (e.g. API keys for tools)
}

// Interfaces

type IKnight interface {
	Name() string
	Run(ctx map[string]interface{}) error
}

type IReconSubAgent interface {
	Discover(target string) ([]DiscoveredEndpoint, error)
}

type IVulnScanner interface {
	Scan(endpoints []DiscoveredEndpoint) ([]Vulnerability, error)
}

type IVulnAnalyst interface {
	Analyze(vulns []Vulnerability) ([]Vulnerability, error)
}

type IPoCGenerator interface {
	Generate(vuln Vulnerability) (ProofOfConcept, error)
}

type IChainBuilder interface {
	BuildChains(vulns []Vulnerability) ([]AttackChain, error)
}
