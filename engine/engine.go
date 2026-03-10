package engine

import (
	"fmt"
	"reconx/endpoint"
	"reconx/enumeration"
	"reconx/infrastructure"
	"reconx/jsanalysis"
	"reconx/livehost"
	"reconx/models"
	"reconx/report"
	"reconx/vulnerability"
	"reconx/webinterface"
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
	scanner := infrastructure.NewScanner()
	scanner.MultiScan(e.Report.Hosts)

	totalPorts := 0
	for _, host := range e.Report.Hosts {
		totalPorts += len(host.Ports)
	}
	fmt.Printf("  [!] Identified %d open ports across all hosts\n", totalPorts)
}

func (e *Engine) analyzeWebInterfaces() {
	analyzer := webinterface.NewAnalyzer("./screenshots")
	analyzer.CaptureScreenshots(e.Report.Hosts)
	fmt.Printf("  [!] Captured screenshots for %d hosts\n", len(e.Report.Hosts))
}

func (e *Engine) detectVulnerabilities() {
	scanner := vulnerability.NewScanner()
	e.Report.Vulnerabilities = scanner.MultiScan(e.Report.Hosts)
	fmt.Printf("  [!] Detected %d potential vulnerabilities\n", len(e.Report.Vulnerabilities))
}

func (e *Engine) generateReport() {
	generator := report.NewGenerator(e.Report)
	generator.ExportText()
	err := generator.ExportJSON("report.json")
	if err != nil {
		fmt.Printf(" [!] Error exporting JSON: %v\n", err)
	} else {
		fmt.Println(" [!] Report saved to report.json")
	}
}
