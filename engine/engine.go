package engine

import (
	"fmt"
	"log"
	"reconx/endpoint"
	"reconx/enumeration"
	"reconx/jsanalysis"
	"reconx/livehost"
	"reconx/models"
	"time"
)

// Engine orchestrates the reconnaissance pipeline.
type Engine struct {
	Target string
	Report *models.Report
}

// NewEngine creates a new reconnaissance engine.
func NewEngine(target string) *Engine {
	return &Engine{
		Target: target,
		Report: &models.Report{
			Target: models.Target{
				Domain:    target,
				CreatedAt: time.Now(),
			},
		},
	}
}

// Run starts the reconnaissance pipeline.
func (e *Engine) Run() {
	start := time.Now()
	fmt.Printf("[*] Starting reconnaissance for %s\n", e.Target)

	// 1. Subdomain Enumeration
	fmt.Println("[+] Stage 1: Subdomain Enumeration")
	e.enumerateSubdomains()

	// 2. Live Host Detection
	fmt.Println("[+] Stage 2: Live Host Detection")
	e.detectLiveHosts()

	// 3. Endpoint Discovery & JS Analysis
	fmt.Println("[+] Stage 3: Endpoint Discovery & JS Analysis")
	e.discoverEndpoints()

	// 4. Infrastructure & Port Analysis
	fmt.Println("[+] Stage 4: Infrastructure & Port Analysis")
	e.scanInfrastructure()

	// 5. Web Interface Analysis
	fmt.Println("[+] Stage 5: Web Interface Analysis")
	e.analyzeWebInterfaces()

	// 6. Vulnerability Detection
	fmt.Println("[+] Stage 6: Vulnerability Detection")
	e.detectVulnerabilities()

	// 7. Report Generation
	fmt.Println("[+] Stage 7: Report Generation")
	e.generateReport()

	e.Report.ScanDuration = time.Since(start)
	fmt.Printf("[*] Reconnaissance complete. Duration: %s\n", e.Report.ScanDuration)
}

func (e *Engine) enumerateSubdomains() {
	scanner := enumeration.NewSubdomainScanner()
	e.Report.Subdomains = scanner.Scan(e.Target)
	fmt.Printf("  [!] Discovered %d subdomains\n", len(e.Report.Subdomains))
}

func (e *Engine) detectLiveHosts() {
	detector := livehost.NewDetector()
	e.Report.Hosts = detector.Detect(e.Report.Subdomains)
	fmt.Printf("  [!] Detected %d live hosts\n", len(e.Report.Hosts))
}

func (e *Engine) discoverEndpoints() {
	scanner := endpoint.NewScanner()
	scanner.MultiDiscover(e.Report.Hosts)

	analyzer := jsanalysis.NewAnalyzer()
	analyzer.MultiAnalyze(e.Report.Hosts)

	totalEndpoints := 0
	for _, host := range e.Report.Hosts {
		if host.HTTPInfo != nil {
			totalEndpoints += len(host.HTTPInfo.Endpoints)
		}
	}
	fmt.Printf("  [!] Discovered %d endpoints across all hosts\n", totalEndpoints)
}

func (e *Engine) scanInfrastructure() {
	// TODO: Implement infrastructure and port analysis
	log.Println("Scan infrastructure... (stub)")
}

func (e *Engine) analyzeWebInterfaces() {
	// TODO: Implement web interface analysis (screenshots)
	log.Println("Analyze web interfaces... (stub)")
}

func (e *Engine) detectVulnerabilities() {
	// TODO: Implement vulnerability detection
	log.Println("Detect vulnerabilities... (stub)")
}

func (e *Engine) generateReport() {
	// TODO: Implement report generation
	log.Println("Generate report... (stub)")
}
