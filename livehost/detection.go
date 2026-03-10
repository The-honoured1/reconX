package livehost

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"reconx/models"
	"sync"
	"time"
)

// Detector handles live host discovery.
type Detector struct {
	Client *http.Client
}

// NewDetector creates a new live host detector.
func NewDetector() *Detector {
	return &Detector{
		Client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// Detect checks which subdomains are live.
func (d *Detector) Detect(subdomains []models.Subdomain) []models.Host {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var liveHosts []models.Host

	for _, sub := range subdomains {
		wg.Add(1)
		go func(s models.Subdomain) {
			defer wg.Done()
			
			// Try HTTPS first, then HTTP
			protocols := []string{"https", "http"}
			for _, proto := range protocols {
				url := fmt.Sprintf("%s://%s", proto, s.Name)
				resp, err := d.Client.Get(url)
				if err == nil {
					defer resp.Body.Close()
					
					host := models.Host{
						Hostname: s.Name,
						HTTPInfo: &models.HTTPInfo{
							URL:        url,
							StatusCode: resp.StatusCode,
							Title:      d.extractTitle(resp),
						},
					}
					
					mu.Lock()
					liveHosts = append(liveHosts, host)
					mu.Unlock()
					break // If one protocol works, we stop for this subdomain
				}
			}
		}(sub)
	}

	wg.Wait()
	return liveHosts
}

// extractTitle is a placeholder for HTML title extraction.
func (d *Detector) extractTitle(resp *http.Response) string {
	// In a real implementation, use an HTML parser to find <title>
	return "Placeholder Title"
}
