package report

import (
	"encoding/json"
	"fmt"
	"os"
	"reconx/models"
	"text/template"
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

// ExportHTML exports the report to a premium HTML file.
func (g *Generator) ExportHTML(filename string) error {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, g.Report)
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

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconX Report - {{.Target.Domain}}</title>
    <style>
        :root {
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #f8fafc;
            --primary: #7d56f4;
            --secondary: #04b575;
            --danger: #ef4444;
            --subtle: #94a3b8;
        }
        body {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.5;
            margin: 0;
            padding: 2rem;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        header {
            margin-bottom: 3rem;
            border-bottom: 2px solid var(--primary);
            padding-bottom: 1rem;
        }
        h1 { margin: 0; color: var(--primary); }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }
        .stat-card {
            background: var(--card-bg);
            padding: 1.5rem;
            border-radius: 0.75rem;
            border: 1px solid #334155;
            text-align: center;
        }
        .stat-value { font-size: 2rem; font-weight: bold; color: var(--secondary); }
        .stat-label { color: var(--subtle); font-size: 0.875rem; text-transform: uppercase; }
        
        section { margin-bottom: 3rem; }
        h2 { border-left: 4px solid var(--primary); padding-left: 1rem; margin-bottom: 1.5rem; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border-radius: 0.5rem;
            overflow: hidden;
        }
        th, td { padding: 1rem; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #334155; color: var(--subtle); text-transform: uppercase; font-size: 0.75rem; }
        
        .severity { padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-weight: bold; font-size: 0.75rem; }
        .severity.HIGH { background: var(--danger); }
        .severity.CRITICAL { background: #7f1d1d; border: 1px solid var(--danger); }
        .severity.MEDIUM { background: #b45309; }
        .severity.LOW { background: #1e40af; }
        
        .badge { background: var(--primary); padding: 0.2rem 0.5rem; border-radius: 1rem; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>RECON-X — {{.Target.Domain}}</h1>
            <p style="color: var(--subtle)">Scan completed on {{.Target.CreatedAt.Format "Jan 02, 2006 15:04:05 UTC"}} • Duration: {{.ScanDuration}}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{len .Subdomains}}</div>
                <div class="stat-label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{len .Hosts}}</div>
                <div class="stat-label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{len .Vulnerabilities}}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
        </div>

        {{if .Vulnerabilities}}
        <section>
            <h2>Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Name</th>
                        <th>URL</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Vulnerabilities}}
                    <tr>
                        <td><span class="severity {{.Severity}}">{{.Severity}}</span></td>
                        <td>{{.Name}}</td>
                        <td><a href="{{.URL}}" style="color: var(--primary)">{{.URL}}</a></td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </section>
        {{end}}

        <section>
            <h2>Live Hosts</h2>
            <table>
                <thead>
                    <tr>
                        <th>Hostname</th>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Title</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Hosts}}
                    <tr>
                        <td>{{.Hostname}}</td>
                        <td><a href="{{.HTTPInfo.URL}}" style="color: var(--primary)">{{.HTTPInfo.URL}}</a></td>
                        <td><span class="badge">{{.HTTPInfo.StatusCode}}</span></td>
                        <td>{{.HTTPInfo.Title}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </section>

        <section>
            <h2>All Subdomains</h2>
            <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                {{range .Subdomains}}
                <span class="stat-card" style="padding: 0.5rem 1rem; font-size: 0.875rem;">{{.Name}}</span>
                {{end}}
            </div>
        </section>
    </div>
</body>
</html>
`
