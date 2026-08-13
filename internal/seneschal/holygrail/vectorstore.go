// Package holygrail implements the Holy Grail RAG (Retrieval-Augmented Generation)
// knowledge base for CVE and exploit intelligence. It uses a TF-IDF based embedding
// approach with cosine similarity search, backed by in-memory storage.
package holygrail

import (
	"math"
	"sort"
	"strings"
	"unicode"
)

// Vector is a sparse TF-IDF vector represented as a map from term to weight.
type Vector map[string]float64

// Document holds the indexed content along with its pre-computed TF-IDF vector.
type Document struct {
	ID          string
	Content     string
	Description string
	vector      Vector
}

// VectorStore is an in-memory store of documents with cosine similarity search.
type VectorStore struct {
	docs []*Document
	idf  map[string]float64 // inverse document frequency per term
}

// NewVectorStore creates an empty VectorStore.
func NewVectorStore() *VectorStore {
	return &VectorStore{
		idf: make(map[string]float64),
	}
}

// AddDocuments adds a batch of documents and recomputes IDF weights across the corpus.
// This should be called once after all seed documents have been prepared.
func (vs *VectorStore) AddDocuments(docs []*Document) {
	vs.docs = append(vs.docs, docs...)
	vs.recomputeIDF()
	for _, d := range vs.docs {
		d.vector = vs.tfidfVector(d.Content)
	}
}

// Search performs a cosine similarity query against all indexed documents and returns
// up to topN results sorted in descending order by score. Only results with score > 0
// are returned.
func (vs *VectorStore) Search(query string, topN int) []SearchResult {
	if len(vs.docs) == 0 || query == "" {
		return nil
	}

	qVec := vs.tfidfVector(query)
	qNorm := norm(qVec)
	if qNorm == 0 {
		return nil
	}

	type scored struct {
		doc   *Document
		score float64
	}
	results := make([]scored, 0, len(vs.docs))

	for _, d := range vs.docs {
		s := cosine(qVec, qNorm, d.vector)
		if s > 0 {
			results = append(results, scored{doc: d, score: s})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	if topN > len(results) {
		topN = len(results)
	}

	out := make([]SearchResult, topN)
	for i := 0; i < topN; i++ {
		out[i] = SearchResult{
			ID:          results[i].doc.ID,
			Content:     results[i].doc.Content,
			Description: results[i].doc.Description,
			Score:       results[i].score,
		}
	}
	return out
}

// SearchResult is a single result from a vector similarity search.
type SearchResult struct {
	ID          string
	Content     string
	Description string
	Score       float64
}

// --- TF-IDF internals ---

// tokenize lowercases, strips punctuation, and splits text into word tokens,
// filtering stop words to improve signal quality.
func tokenize(text string) []string {
	var tokens []string
	// Replace punctuation with spaces and lowercase
	f := func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return ' '
	}
	cleaned := strings.Map(f, text)

	for _, tok := range strings.Fields(cleaned) {
		if len(tok) > 1 && !isStopWord(tok) {
			tokens = append(tokens, tok)
		}
	}
	return tokens
}

// isStopWord returns true for very common English words that carry little signal.
var stopWords = map[string]bool{
	"a": true, "an": true, "the": true, "and": true, "or": true,
	"of": true, "in": true, "to": true, "for": true, "is": true,
	"it": true, "its": true, "be": true, "by": true, "on": true,
	"at": true, "as": true, "are": true, "was": true, "with": true,
	"this": true, "that": true, "can": true, "may": true, "not": true,
	"has": true, "have": true, "been": true, "from": true, "via": true,
	"which": true, "when": true, "if": true, "any": true,
	"no": true, "do": true, "so": true, "will": true, "also": true,
}

func isStopWord(w string) bool {
	return stopWords[w]
}

// tf computes term frequency (normalised by document length).
func tf(tokens []string) map[string]float64 {
	counts := make(map[string]int, len(tokens))
	for _, t := range tokens {
		counts[t]++
	}
	out := make(map[string]float64, len(counts))
	total := float64(len(tokens))
	if total == 0 {
		return out
	}
	for t, c := range counts {
		out[t] = float64(c) / total
	}
	return out
}

// recomputeIDF rebuilds the IDF table from the current document corpus.
func (vs *VectorStore) recomputeIDF() {
	df := make(map[string]int)
	N := float64(len(vs.docs))
	for _, d := range vs.docs {
		seen := make(map[string]bool)
		for _, tok := range tokenize(d.Content) {
			if !seen[tok] {
				df[tok]++
				seen[tok] = true
			}
		}
	}
	vs.idf = make(map[string]float64, len(df))
	for term, count := range df {
		// Smoothed IDF: log((N+1)/(df+1)) + 1
		vs.idf[term] = math.Log((N+1)/float64(count+1)) + 1
	}
}

// tfidfVector builds a TF-IDF vector for the given text using the store's IDF table.
func (vs *VectorStore) tfidfVector(text string) Vector {
	tokens := tokenize(text)
	tfMap := tf(tokens)
	vec := make(Vector, len(tfMap))
	for term, tfVal := range tfMap {
		if idfVal, ok := vs.idf[term]; ok {
			vec[term] = tfVal * idfVal
		} else {
			// unseen term during query — assign IDF as if df=0
			idfVal := math.Log(float64(len(vs.docs)+1)/1) + 1
			vec[term] = tfVal * idfVal
		}
	}
	return vec
}

// norm computes the L2 (Euclidean) norm of a vector.
func norm(v Vector) float64 {
	var sum float64
	for _, val := range v {
		sum += val * val
	}
	return math.Sqrt(sum)
}

// cosine computes the cosine similarity between query vector q (with pre-computed norm qNorm)
// and document vector d.
func cosine(q Vector, qNorm float64, d Vector) float64 {
	if qNorm == 0 {
		return 0
	}
	dNorm := norm(d)
	if dNorm == 0 {
		return 0
	}

	var dot float64
	// Iterate over the smaller vector for efficiency
	if len(q) <= len(d) {
		for term, qVal := range q {
			dot += qVal * d[term]
		}
	} else {
		for term, dVal := range d {
			dot += dVal * q[term]
		}
	}
	return dot / (qNorm * dNorm)
}
