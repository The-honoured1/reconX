# reconX

reconX is an automated reconnaissance and vulnerability scanning engine built in Go. It provides a complete pipeline for discovering assets, analyzing infrastructure, and identifying potential security weaknesses across a target domain. Driven by a beautiful Terminal User Interface (TUI) powered by [Charmbracelet](https://github.com/charmbracelet), reconX makes it easy to monitor the progress of complex scanning tasks.

## Features

reconX orchestrates a comprehensive 6-stage reconnaissance pipeline:

1. **Subdomain Enumeration**: Discovers subdomains associated with the target domain.
2. **Live Host Detection**: Probes subdomains to identify live, responsive hosts and services.
3. **Endpoint Discovery & JS Analysis**: Analyzes web services to find API endpoints and parses JavaScript files for hidden resources and routes.
4. **Infrastructure & Port Analysis**: Scans for open ports and identifies underlying infrastructure and running services.
5. **Web Interface Analysis**: Captures screenshots of discovered web interfaces for visual inspection.
6. **Vulnerability Detection**: Scans the target's infrastructure for common security weaknesses.
7. **Report Generation**: Automatically generates detailed scan reports in JSON and HTML formats.

## Installation

Ensure you have Go installed (version 1.21 or later is recommended).

Clone the repository and build the project:

```bash
git clone https://github.com/yourusername/reconX.git
cd reconX
go mod download
go build -o reconx main.go
```

## Usage

You can run reconX by providing the target domain as an argument:

```bash
./reconx example.com
```

Alternatively, you can use the `-t` flag:

```bash
./reconx -t example.com
```

### Output

As reconX runs, you'll see a real-time progress update in your terminal via the integrated TUI. Once the scan is complete, it generates the following files in the current working directory:

- `report.json`: A machine-readable JSON file containing the full scan payload.
- `report.html`: An easy-to-read, structured HTML report.
- `screenshots/`: A directory populated with screenshots of the active web surfaces (if applicable).

## Acknowledgements

- Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea), [Bubbles](https://github.com/charmbracelet/bubbles), and [Lip Gloss](https://github.com/charmbracelet/lipgloss).

## License

This project is licensed under the MIT License - see the LICENSE file for details.
