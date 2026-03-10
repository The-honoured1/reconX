package jsanalysis

import (
	"io"
	"net/http"
	"reconx/models"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Analyzer handles JavaScript file parsing for sensitive info and endpoints.
type Analyzer struct {
	Client *http.Client
}

// NewAnalyzer creates a new JS analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Analyze parses JS files found for a host.
func (a *Analyzer) Analyze(host *models.Host) {
	if host.HTTPInfo == nil || len(host.HTTPInfo.JSFiles) == 0 {
		return
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, jsPath := range host.HTTPInfo.JSFiles {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()

			fullURL := path
			if !strings.HasPrefix(path, "http") {
				baseURL := host.HTTPInfo.URL
				if strings.HasSuffix(baseURL, "/") {
					baseURL = baseURL[:len(baseURL)-1]
				}
				if strings.HasPrefix(path, "/") {
					fullURL = baseURL + path
				} else {
					fullURL = baseURL + "/" + path
				}
			}

			resp, err := a.Client.Get(fullURL)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			content := string(body)

			// Simple regex for endpoints within JS
			endpointRegex := regexp.MustCompile(`(?i)(?:/api/v[0-9]/|/v[0-9]/|/admin/|/user/|/debug/)[a-zA-Z0-9_\-/]+`)
			matches := endpointRegex.FindAllString(content, -1)

			mu.Lock()
			for _, match := range matches {
				host.HTTPInfo.Endpoints = append(host.HTTPInfo.Endpoints, models.Endpoint{
					Path:   match,
					Method: "UNKNOWN",
					Source: "JS:" + path,
				})
			}
			mu.Unlock()
		}(jsPath)
	}

	wg.Wait()
}

// MultiAnalyze runs analysis on multiple hosts.
func (a *Analyzer) MultiAnalyze(hosts []models.Host) {
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Add(1)
		go func(h *models.Host) {
			defer wg.Done()
			a.Analyze(h)
		}(&hosts[i])
	}
	wg.Wait()
}
