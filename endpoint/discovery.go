package endpoint

import (
	"io"
	"net/http"
	"reconx/models"
	"regexp"
	"sync"
	"time"
)

// Scanner handles endpoint discovery.
type Scanner struct {
	Client *http.Client
}

// NewScanner creates a new endpoint scanner.
func NewScanner() *Scanner {
	return &Scanner{
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Discover finds endpoints and JS files for a given host.
func (s *Scanner) Discover(host *models.Host) {
	if host.HTTPInfo == nil {
		return
	}
	
	resp, err := s.Client.Get(host.HTTPInfo.URL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	// Extract JS files
	jsRegex := regexp.MustCompile(`src=["'](.*?\.js)["']`)
	jsMatches := jsRegex.FindAllStringSubmatch(content, -1)
	for _, match := range jsMatches {
		host.HTTPInfo.JSFiles = append(host.HTTPInfo.JSFiles, match[1])
	}

	// Extract links/endpoints
	linkRegex := regexp.MustCompile(`href=["'](.*? )["']`)
	linkMatches := linkRegex.FindAllStringSubmatch(content, -1)
	for _, match := range linkMatches {
		host.HTTPInfo.Endpoints = append(host.HTTPInfo.Endpoints, models.Endpoint{
			Path:   match[1],
			Source: "HTML",
		})
	}
}

// MultiDiscover runs discovery on multiple hosts.
func (s *Scanner) MultiDiscover(hosts []models.Host) {
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Add(1)
		go func(h *models.Host) {
			defer wg.Done()
			s.Discover(h)
		}(&hosts[i])
	}
	wg.Wait()
}
