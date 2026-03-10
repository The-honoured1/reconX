package ui

import (
	"fmt"
	"reconx/engine"
	"reconx/models"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575")).
			Bold(true)

	subtleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262"))

	statsStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7D56F4")).
			Width(20)
)

type model struct {
	engine   *engine.Engine
	progress progress.Model
	spinner  spinner.Model
	quitting bool
	err      error

	currentStage   string
	currentMessage string
	subdomains     []models.Subdomain
	hosts          []models.Host
	vulns          []models.Vulnerability
}

func NewModel(eng *engine.Engine) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))

	return model{
		engine:   eng,
		spinner:  s,
		progress: progress.New(progress.WithDefaultGradient()),
	}
}

type progressMsg models.ProgressUpdate

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.listenForUpdates(),
	)
}

func (m model) listenForUpdates() tea.Cmd {
	return func() tea.Msg {
		update, ok := <-m.engine.Updates
		if !ok {
			return nil
		}
		return progressMsg(update)
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case progressMsg:
		m.currentStage = msg.Stage
		m.currentMessage = msg.Message
		
		// Handle data updates
		if msg.Data != nil {
			switch d := msg.Data.(type) {
			case []models.Subdomain:
				m.subdomains = d
			case []models.Host:
				m.hosts = d
			case []models.Vulnerability:
				m.vulns = d
			}
		}

		if msg.Progress >= 1.0 {
			m.quitting = true
			return m, nil
		}

		cmd := m.progress.SetPercent(msg.Progress)
		return m, tea.Batch(cmd, m.listenForUpdates())
	case progress.FrameMsg:
		newProgressModel, cmd := m.progress.Update(msg)
		m.progress = newProgressModel.(progress.Model)
		return m, cmd
	}
	return m, nil
}

func (m model) View() string {
	if m.err != nil {
		return "Error: " + m.err.Error() + "\n"
	}

	header := titleStyle.Render("RECON-X — Automated Attack Surface Reconnaissance")
	
	prog := m.progress.View()
	
	status := fmt.Sprintf("%s %s: %s", m.spinner.View(), headerStyle.Render(m.currentStage), subtleStyle.Render(m.currentMessage))
	
	stats := statsStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			fmt.Sprintf("%s %d", labelStyle.Render("Subdomains:"), len(m.subdomains)),
			fmt.Sprintf("%s %d", labelStyle.Render("Live Hosts:"), len(m.hosts)),
			fmt.Sprintf("%s %d", labelStyle.Render("Vulnerabilities:"), len(m.vulns)),
		),
	)

	view := lipgloss.JoinVertical(lipgloss.Left,
		header,
		"",
		status,
		"",
		prog,
		"",
		stats,
		"",
		subtleStyle.Render("press q to quit"),
	)

	if m.quitting {
		return view + "\n" + headerStyle.Render("Scan complete!") + "\n"
	}

	return "\n" + view + "\n"
}

func Run(eng *engine.Engine) error {
	p := tea.NewProgram(NewModel(eng))
	
	// Start engine in background
	go eng.Run()
	
	_, err := p.Run()
	return err
}
