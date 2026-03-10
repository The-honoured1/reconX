package models

import "time"

// Target represents the initial domain or target provided by the user.
type Target struct {
	Domain    string
	CreatedAt time.Time
}

// Subdomain represents a discovered subdomain.
type Subdomain struct {
	Name   string
	Source string
	IPs    []string
}

// Host represents a live host detected during the reconnaissance.
type Host struct {
	Hostname   string
	IP         string
	Ports      []Port
	HTTPInfo   *HTTPInfo
	Screenshot string // Path to screenshots
}

// Port represents an open port on a host.
type Port struct {
	Number   int
	Protocol string
	Service  string
	State    string
}

// HTTPInfo contains information about a web service.
type HTTPInfo struct {
	URL        string
	StatusCode int
	Title      string
	WebServer  string
	Endpoints  []Endpoint
	JSFiles    []string
}

// Endpoint represents a discovered URL path or API endpoint.
type Endpoint struct {
	Path   string
	Method string
	Source string
}

// Vulnerability represents a potential security weakness.
type Vulnerability struct {
	Name        string
	Description string
	Severity    string
	URL         string
	Evidence    string
}

// Report represents the final reconnaissance results.
type Report struct {
	Target          Target
	Subdomains      []Subdomain
	Hosts           []Host
	Vulnerabilities []Vulnerability
	ScanDuration    time.Duration
}
