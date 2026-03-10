package report

import (
	"encoding/json"
	"fmt"
	"os"
	"reconx/models"
)

// Generator handles report creation in various formats.
type Generator struct {
	Report *models.Report
}

// NewGenerator creates a new report generator.
func NewGenerator(report *models.Report) *Generator {
	return &Generator{
		Report: report,
	}
}

// ExportJSON exports the report to a JSON file.
func (g *Generator) ExportJSON(filename string) error {
	data, err := json.MarshalIndent(g.Report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// ExportText prints a summary to the console or a text file.
func (g *Generator) ExportText() {
	fmt.Printf("\n--- ReconX Attack Surface Report ---\n")
	fmt.Printf("Target: %s\n", g.Report.Target.Domain)
	fmt.Printf("Duration: %s\n", g.Report.ScanDuration)
	fmt.Printf("Subdomains discovered: %d\n", len(g.Report.Subdomains))
	fmt.Printf("Live hosts detected: %d\n", len(g.Report.Hosts))
	
	totalEndpoints := 0
	for _, h := range g.Report.Hosts {
		if h.HTTPInfo != nil {
			totalEndpoints += len(h.HTTPInfo.Endpoints)
		}
	}
	fmt.Printf("Endpoints discovered: %d\n", totalEndpoints)
	fmt.Printf("Potential vulnerabilities: %d\n", len(g.Report.Vulnerabilities))
	fmt.Printf("------------------------------------\n")
}

// In a real implementation, add HTML and CSV exporters...
