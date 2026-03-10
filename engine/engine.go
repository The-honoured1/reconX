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
	Target  string
	Report  *models.Report
	Updates chan models.ProgressUpdate
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
		Updates: make(chan models.ProgressUpdate, 100),
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
	e.sendUpdate("Reporting", "Generating final report", 0.9, nil)
	e.generateReport()

	e.Report.ScanDuration = time.Since(start)
	e.sendUpdate("Finished", fmt.Sprintf("Reconnaissance complete. Duration: %s", e.Report.ScanDuration), 1.0, nil)
	close(e.Updates)
}

func (e *Engine) sendUpdate(stage, msg string, prog float64, data interface{}) {
	e.Updates <- models.ProgressUpdate{
		Stage:    stage,
		Message:  msg,
		Progress: prog,
		Data:     data,
	}
}

func (e *Engine) enumerateSubdomains() {
	e.sendUpdate("Enumeration", "Starting subdomain enumeration", 0.1, nil)
	scanner := enumeration.NewSubdomainScanner()
	e.Report.Subdomains = scanner.Scan(e.Target)
	e.sendUpdate("Enumeration", fmt.Sprintf("Discovered %d subdomains", len(e.Report.Subdomains)), 0.2, e.Report.Subdomains)
}

func (e *Engine) detectLiveHosts() {
	e.sendUpdate("Live Detection", "Probing subdomains for live services", 0.3, nil)
	detector := livehost.NewDetector()
	e.Report.Hosts = detector.Detect(e.Report.Subdomains)
	e.sendUpdate("Live Detection", fmt.Sprintf("Detected %d live hosts", len(e.Report.Hosts)), 0.4, e.Report.Hosts)
}

func (e *Engine) discoverEndpoints() {
	e.sendUpdate("Endpoint Discovery", "Analyzing web services for endpoints", 0.5, nil)
	scanner := endpoint.NewScanner()
	scanner.MultiDiscover(e.Report.Hosts)

	e.sendUpdate("JS Analysis", "Parsing JavaScript files for hidden resources", 0.6, nil)
	analyzer := jsanalysis.NewAnalyzer()
	analyzer.MultiAnalyze(e.Report.Hosts)

	totalEndpoints := 0
	for _, host := range e.Report.Hosts {
		if host.HTTPInfo != nil {
			totalEndpoints += len(host.HTTPInfo.Endpoints)
		}
	}
	e.sendUpdate("Analysis", fmt.Sprintf("Discovered %d endpoints across all hosts", totalEndpoints), 0.7, nil)
}

func (e *Engine) scanInfrastructure() {
	e.sendUpdate("Infrastructure", "Scanning ports and identifying services", 0.8, nil)
	scanner := infrastructure.NewScanner()
	scanner.MultiScan(e.Report.Hosts)

	totalPorts := 0
	for _, host := range e.Report.Hosts {
		totalPorts += len(host.Ports)
	}
	e.sendUpdate("Infrastructure", fmt.Sprintf("Identified %d open ports", totalPorts), 0.85, nil)
}

func (e *Engine) analyzeWebInterfaces() {
	// e.sendUpdate("Web Analysis", "Capturing screenshots", 0.88, nil)
	analyzer := webinterface.NewAnalyzer("./screenshots")
	analyzer.CaptureScreenshots(e.Report.Hosts)
}

func (e *Engine) detectVulnerabilities() {
	e.sendUpdate("Vulnerabilities", "Scanning for common security weaknesses", 0.9, nil)
	scanner := vulnerability.NewScanner()
	e.Report.Vulnerabilities = scanner.MultiScan(e.Report.Hosts)
	e.sendUpdate("Vulnerabilities", fmt.Sprintf("Detected %d potential vulnerabilities", len(e.Report.Vulnerabilities)), 0.95, e.Report.Vulnerabilities)
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
