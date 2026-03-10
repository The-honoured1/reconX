package enumeration

import (
	"log"
	"reconx/models"
	"sync"
)

// Enumerator is the interface for subdomain discovery sources.
type Enumerator interface {
	Enumerate(domain string) ([]models.Subdomain, error)
	Name() string
}

// SubdomainScanner manages multiple enumeration sources.
type SubdomainScanner struct {
	Sources []Enumerator
}

// NewSubdomainScanner creates a new scanner with default sources.
func NewSubdomainScanner() *SubdomainScanner {
	return &SubdomainScanner{
		Sources: []Enumerator{
			&CrtShEnumerator{},
			&BruteForceEnumerator{
				Wordlist: []string{"www", "api", "dev", "test", "stage", "admin", "db", "mail", "blog"},
			},
		},
	}
}

// Scan runs all enumeration sources.
func (s *SubdomainScanner) Scan(domain string) []models.Subdomain {
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(map[string]models.Subdomain)

	for _, source := range s.Sources {
		wg.Add(1)
		go func(src Enumerator) {
			defer wg.Done()
			subs, err := src.Enumerate(domain)
			if err != nil {
				log.Printf("Error from %s: %v", src.Name(), err)
				return
			}
			mu.Lock()
			for _, sub := range subs {
				results[sub.Name] = sub
			}
			mu.Unlock()
		}(source)
	}

	wg.Wait()

	var finalResults []models.Subdomain
	for _, sub := range results {
		finalResults = append(finalResults, sub)
	}
	return finalResults
}

// CrtShEnumerator implements crt.sh certificate transparency log searching.
type CrtShEnumerator struct{}

func (c *CrtShEnumerator) Name() string { return "crt.sh" }
func (c *CrtShEnumerator) Enumerate(domain string) ([]models.Subdomain, error) {
	// For now, returning a mock result to demonstrate the flow.
	// In a real implementation, this would query https://crt.sh/?q=%.domain&output=json
	return []models.Subdomain{
		{Name: "api." + domain, Source: "crt.sh"},
		{Name: "dev." + domain, Source: "crt.sh"},
	}, nil
}

// BruteForceEnumerator implements DNS brute-forcing.
type BruteForceEnumerator struct {
	Wordlist []string
}

func (b *BruteForceEnumerator) Name() string { return "BruteForce" }
func (b *BruteForceEnumerator) Enumerate(domain string) ([]models.Subdomain, error) {
	var subs []models.Subdomain
	for _, word := range b.Wordlist {
		// In a real implementation, this would perform a DNS lookup.
		subs = append(subs, models.Subdomain{Name: word + "." + domain, Source: "BruteForce"})
	}
	return subs, nil
}
