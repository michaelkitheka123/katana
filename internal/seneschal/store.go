package seneschal

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"

	"github.com/templar-framework/templar/internal/seneschal/holygrail"
	"github.com/templar-framework/templar/internal/shared"
	_ "modernc.org/sqlite"
)

type Store struct {
	db       *sql.DB
	degraded bool
	kb       *holygrail.KnowledgeBase
}

// NewStore initializes SQLite database and schema
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Printf("SQLite init failure: %v", err)
		return &Store{degraded: true}, nil // Fallback
	}

	store := &Store{
		db:       db,
		degraded: false,
		kb:       holygrail.NewKnowledgeBase(),
	}

	if err := store.createSchema(); err != nil {
		log.Printf("SQLite schema failure: %v", err)
		store.degraded = true
	}

	return store, nil
}

func (s *Store) createSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS campaigns (id TEXT PRIMARY KEY, data TEXT);`,
		`CREATE TABLE IF NOT EXISTS attack_surfaces (campaign_id TEXT PRIMARY KEY, data TEXT);`,
		`CREATE TABLE IF NOT EXISTS vulnerabilities (campaign_id TEXT PRIMARY KEY, data TEXT);`,
		`CREATE TABLE IF NOT EXISTS pocs (campaign_id TEXT PRIMARY KEY, data TEXT);`,
		`CREATE TABLE IF NOT EXISTS attack_chains (campaign_id TEXT PRIMARY KEY, data TEXT);`,
		`CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, event_type TEXT, url TEXT, rule_type TEXT, pattern TEXT, message TEXT);`,
		`CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, data TEXT, expires_at DATETIME);`,
	}
	
	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// storeAsJSON marshals input to JSON, redacts it, and stores it in the table
func (s *Store) storeAsJSON(table, campaignID string, data interface{}) error {
	if s.degraded {
		return nil // In-memory fallback (no-op for MVP)
	}
	
	redactedData := RedactKeys(data)
	b, err := json.Marshal(redactedData)
	if err != nil {
		return err
	}
	
	query := `INSERT INTO ` + table + ` (campaign_id, data) VALUES (?, ?) ON CONFLICT(campaign_id) DO UPDATE SET data=excluded.data;`
	_, err = s.db.Exec(query, campaignID, string(b))
	return err
}

func (s *Store) retrieveAsJSON(table, campaignID string, target interface{}) error {
	if s.degraded {
		return errors.New("store is degraded")
	}

	var data string
	query := `SELECT data FROM ` + table + ` WHERE campaign_id = ?;`
	err := s.db.QueryRow(query, campaignID).Scan(&data)
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(data), target)
}

func (s *Store) StoreReconResults(campaignID string, surface shared.AttackSurface) error {
	return s.storeAsJSON("attack_surfaces", campaignID, surface)
}

func (s *Store) StoreVulnerabilities(campaignID string, vulns []shared.Vulnerability) error {
	return s.storeAsJSON("vulnerabilities", campaignID, vulns)
}

func (s *Store) StorePOCs(campaignID string, pocs []shared.ProofOfConcept) error {
	return s.storeAsJSON("pocs", campaignID, pocs)
}

func (s *Store) StoreChains(campaignID string, chains []shared.AttackChain) error {
	return s.storeAsJSON("attack_chains", campaignID, chains)
}

func (s *Store) ExportCampaign(campaignID string) (shared.CampaignExport, error) {
	var export shared.CampaignExport
	export.Result.CampaignID = campaignID
	
	s.retrieveAsJSON("attack_surfaces", campaignID, &export.Result.AttackSurface)
	s.retrieveAsJSON("vulnerabilities", campaignID, &export.Result.Vulnerabilities)
	s.retrieveAsJSON("pocs", campaignID, &export.Result.PoCs)
	s.retrieveAsJSON("attack_chains", campaignID, &export.Result.AttackChains)
	
	return export, nil
}

