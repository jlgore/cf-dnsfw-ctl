package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cloudflare/cloudflare-go"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Config struct {
	APIToken  string
	AccountID string
}

type OutputFormat string

const (
	OutputFormatText      OutputFormat = "text"
	OutputFormatJSON      OutputFormat = "json"
	OutputFormatMarkdown  OutputFormat = "markdown"
	OutputFormatBubbleTea OutputFormat = "bubbletea"
)

type inputField int

const (
	nameInput inputField = iota
	upstreamIPInput
	minTTLInput
	maxTTLInput
)

type model struct {
	clusters        []*cloudflare.DNSFirewallCluster
	cursor          int
	selected        *cloudflare.DNSFirewallCluster
	api             *cloudflare.API
	config          *Config
	err             error
	loading         bool
	clusterDetails  string
	spinner         spinner.Model
	fetchingDetails bool
	creatingCluster bool
	inputs          []textinput.Model
	focusIndex      int
}

type errMsg error
type clustersMsg []*cloudflare.DNSFirewallCluster
type clusterDetailsMsg string
type clusterCreatedMsg *cloudflare.DNSFirewallCluster

func initialModel(api *cloudflare.API, config *Config) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	m := model{
		api:     api,
		config:  config,
		loading: true,
		spinner: s,
		inputs:  make([]textinput.Model, 4),
	}

	var t textinput.Model
	for i := range m.inputs {
		t = textinput.New()
		t.CursorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
		t.CharLimit = 50

		switch i {
		case int(nameInput):
			t.Placeholder = "Cluster Name"
			t.Focus()
		case int(upstreamIPInput):
			t.Placeholder = "Upstream IP (comma separated)"
		case int(minTTLInput):
			t.Placeholder = "Minimum Cache TTL"
		case int(maxTTLInput):
			t.Placeholder = "Maximum Cache TTL"
		}

		m.inputs[i] = t
	}

	return m
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.fetchClusters, m.spinner.Tick)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.creatingCluster {
			switch msg.String() {
			case "ctrl+c", "esc":
				m.creatingCluster = false
				return m, nil
			case "tab", "shift+tab", "enter", "up", "down":
				s := msg.String()

				if s == "enter" && m.focusIndex == len(m.inputs)-1 {
					return m, m.createCluster
				}

				if s == "up" || s == "shift+tab" {
					m.focusIndex--
				} else {
					m.focusIndex++
				}

				if m.focusIndex > len(m.inputs)-1 {
					m.focusIndex = 0
				} else if m.focusIndex < 0 {
					m.focusIndex = len(m.inputs) - 1
				}

				cmds := make([]tea.Cmd, len(m.inputs))
				for i := 0; i <= len(m.inputs)-1; i++ {
					if i == m.focusIndex {
						cmds[i] = m.inputs[i].Focus()
						continue
					}
					m.inputs[i].Blur()
				}

				return m, tea.Batch(cmds...)
			}
		} else {
			switch msg.String() {
			case "ctrl+c", "q":
				return m, tea.Quit
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.clusters) {
					m.cursor++
				}
			case "enter":
				if m.cursor == len(m.clusters) {
					m.creatingCluster = true
					return m, nil
				}
				if len(m.clusters) > 0 && !m.fetchingDetails {
					m.selected = m.clusters[m.cursor]
					m.fetchingDetails = true
					return m, tea.Batch(m.fetchClusterDetails, m.spinner.Tick)
				}
			case "esc":
				if !m.fetchingDetails {
					m.selected = nil
					m.clusterDetails = ""
				}
			}
		}

	case clustersMsg:
		m.clusters = msg
		m.loading = false
		m.err = nil
	case clusterDetailsMsg:
		m.clusterDetails = string(msg)
		m.fetchingDetails = false
	case clusterCreatedMsg:
		m.creatingCluster = false
		m.clusters = append(m.clusters, msg)
		m.err = nil
	case errMsg:
		m.err = msg
		m.loading = false
		m.fetchingDetails = false
		m.creatingCluster = false
	case spinner.TickMsg:
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	if m.creatingCluster {
		for i := range m.inputs {
			m.inputs[i], cmd = m.inputs[i].Update(msg)
		}
	}

	return m, cmd
}

func (m model) View() string {
	if m.loading {
		return fmt.Sprintf("%s Loading DNS Firewall clusters...\n", m.spinner.View())
	}

	if m.err != nil {
		errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("red")).Bold(true)
		return errorStyle.Render(fmt.Sprintf("Error: %v\n", m.err)) + "\nPress any key to continue."
	}

	if m.fetchingDetails {
		return fmt.Sprintf("%s Fetching cluster details...\n", m.spinner.View())
	}

	if m.creatingCluster {
		return m.createClusterView()
	}

	if m.selected != nil {
		return fmt.Sprintf("Cluster Details for %s:\n%s\n\nPress ESC to go back", m.selected.Name, m.clusterDetails)
	}

	s := "Cloudflare DNS Firewall Clusters:\n\n"

	for i, cluster := range m.clusters {
		cursor := " "
		if m.cursor == i {
			cursor = ">"
		}
		s += fmt.Sprintf("%s %s (ID: %s)\n", cursor, cluster.Name, cluster.ID)
	}

	cursor := " "
	if m.cursor == len(m.clusters) {
		cursor = ">"
	}
	s += fmt.Sprintf("%s Create New Cluster\n", cursor)

	s += "\nPress q to quit.\n"
	return s
}

func (m model) createClusterView() string {
	s := "Create New DNS Firewall Cluster\n\n"

	for i := range m.inputs {
		s += m.inputs[i].View() + "\n"
	}

	s += "\nPress Enter to create the cluster or ESC to cancel.\n"

	if m.err != nil {
		errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("red")).Bold(true)
		s += "\n" + errorStyle.Render(fmt.Sprintf("Error: %v", m.err))
	}

	return s
}

func (m model) fetchClusters() tea.Msg {
	ctx := context.Background()
	rc := cloudflare.AccountIdentifier(m.config.AccountID)
	params := cloudflare.ListDNSFirewallClustersParams{}

	clusters, err := m.api.ListDNSFirewallClusters(ctx, rc, params)
	if err != nil {
		return errMsg(err)
	}

	return clustersMsg(clusters)
}

func (m model) fetchClusterDetails() tea.Msg {
	if m.selected == nil {
		return nil
	}

	ctx := context.Background()
	rc := cloudflare.AccountIdentifier(m.config.AccountID)
	params := cloudflare.GetDNSFirewallClusterParams{
		ClusterID: m.selected.ID,
	}

	detailedCluster, err := m.api.GetDNSFirewallCluster(ctx, rc, params)
	if err != nil {
		return errMsg(err)
	}

	details := fmt.Sprintf("Name: %s\n", detailedCluster.Name)
	details += fmt.Sprintf("ID: %s\n", detailedCluster.ID)
	details += fmt.Sprintf("Upstream IPs: %v\n", detailedCluster.UpstreamIPs)
	details += fmt.Sprintf("DNS Firewall IPs: %v\n", detailedCluster.DNSFirewallIPs)
	details += fmt.Sprintf("Min Cache TTL: %d\n", detailedCluster.MinimumCacheTTL)
	details += fmt.Sprintf("Max Cache TTL: %d\n", detailedCluster.MaximumCacheTTL)
	details += fmt.Sprintf("Deprecate ANY Requests: %v\n", detailedCluster.DeprecateAnyRequests)
	details += fmt.Sprintf("Modified On: %s\n", detailedCluster.ModifiedOn)

	analyticsParams := cloudflare.GetDNSFirewallUserAnalyticsParams{
		ClusterID: m.selected.ID,
		DNSFirewallUserAnalyticsOptions: cloudflare.DNSFirewallUserAnalyticsOptions{
			Metrics: []string{"queryCount", "uncachedCount", "staleCount", "responseTimeAvg"},
			Since:   timePtr(time.Now().Add(-24 * time.Hour)),
			Until:   timePtr(time.Now()),
		},
	}

	analytics, err := m.api.GetDNSFirewallUserAnalytics(ctx, rc, analyticsParams)
	if err != nil {
		return errMsg(err)
	}

	details += "\nAnalytics (Last 24 hours):\n"
	details += fmt.Sprintf("Query Count: %d\n", *analytics.Totals.QueryCount)
	details += fmt.Sprintf("Uncached Count: %d\n", *analytics.Totals.UncachedCount)
	details += fmt.Sprintf("Stale Count: %d\n", *analytics.Totals.StaleCount)
	details += fmt.Sprintf("Avg Response Time: %.2f\n", *analytics.Totals.ResponseTimeAvg)

	return clusterDetailsMsg(details)
}

func (m model) createCluster() tea.Msg {
	ctx := context.Background()
	rc := cloudflare.AccountIdentifier(m.config.AccountID)

	name := strings.TrimSpace(m.inputs[nameInput].Value())
	if name == "" {
		return errMsg(fmt.Errorf("cluster name cannot be empty"))
	}

	upstreamIPsRaw := strings.TrimSpace(m.inputs[upstreamIPInput].Value())
	upstreamIPs := strings.Split(upstreamIPsRaw, ",")
	for i, ip := range upstreamIPs {
		upstreamIPs[i] = strings.TrimSpace(ip)
		if net.ParseIP(upstreamIPs[i]) == nil {
			return errMsg(fmt.Errorf("invalid IP address: %s", upstreamIPs[i]))
		}
	}

	if len(upstreamIPs) == 0 {
		return errMsg(fmt.Errorf("at least one upstream IP is required"))
	}

	var minTTL, maxTTL uint
	if _, err := fmt.Sscanf(m.inputs[minTTLInput].Value(), "%d", &minTTL); err != nil {
		return errMsg(fmt.Errorf("invalid minimum TTL: %s", m.inputs[minTTLInput].Value()))
	}
	if _, err := fmt.Sscanf(m.inputs[maxTTLInput].Value(), "%d", &maxTTL); err != nil {
		return errMsg(fmt.Errorf("invalid maximum TTL: %s", m.inputs[maxTTLInput].Value()))
	}

	if maxTTL < minTTL {
		return errMsg(fmt.Errorf("maximum TTL must be greater than or equal to minimum TTL"))
	}

	params := cloudflare.CreateDNSFirewallClusterParams{
		Name:                 name,
		UpstreamIPs:          upstreamIPs,
		MinimumCacheTTL:      minTTL,
		MaximumCacheTTL:      maxTTL,
		DeprecateAnyRequests: false,
	}

	cluster, err := m.api.CreateDNSFirewallCluster(ctx, rc, params)
	if err != nil {
		return errMsg(fmt.Errorf("failed to create cluster: %w", err))
	}

	return clusterCreatedMsg(cluster)
}

func main() {
	var cfgFile string
	var config Config
	var outputFormat OutputFormat

	rootCmd := &cobra.Command{
		Use:   "cf-dns-firewall",
		Short: "A CLI tool for Cloudflare DNS Firewall",
		Run: func(cmd *cobra.Command, args []string) {
			api, err := cloudflare.NewWithAPIToken(config.APIToken)
			if err != nil {
				log.Fatal(err)
			}

			switch outputFormat {
			case OutputFormatText:
				err = runTextOutput(api, &config)
			case OutputFormatJSON:
				err = runJSONOutput(api, &config)
			case OutputFormatMarkdown:
				err = runMarkdownOutput(api, &config)
			case OutputFormatBubbleTea:
				p := tea.NewProgram(initialModel(api, &config))
				_, err = p.Run()
			default:
				log.Fatalf("Invalid output format: %s", outputFormat)
			}

			if err != nil {
				log.Fatal(err)
			}
		},
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cf-dns-firewall.yaml)")
	rootCmd.PersistentFlags().StringVar((*string)(&outputFormat), "output", string(OutputFormatBubbleTea), "Output format: text, json, markdown, or bubbletea")

	cobra.OnInitialize(func() {
		if cfgFile != "" {
			viper.SetConfigFile(cfgFile)
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatal(err)
			}
			viper.AddConfigPath(home)
			viper.SetConfigName(".cf-dns-firewall")
		}

		viper.AutomaticEnv()

		if err := viper.ReadInConfig(); err == nil {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		}

		if err := viper.Unmarshal(&config); err != nil {
			log.Fatal(err)
		}

		if config.APIToken == "" {
			log.Fatal("APIToken is not set in the configuration")
		}
		if config.AccountID == "" {
			log.Fatal("AccountID is not set in the configuration")
		}
	})

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runTextOutput(api *cloudflare.API, config *Config) error {
	ctx := context.Background()
	rc := cloudflare.AccountIdentifier(config.AccountID)
	params := cloudflare.ListDNSFirewallClustersParams{}

	clusters, err := api.ListDNSFirewallClusters(ctx, rc, params)
	if err != nil {
		return err
	}

	fmt.Println("Cloudflare DNS Firewall Clusters:")
	for _, cluster := range clusters {
		detailedCluster, err := getDetailedCluster(api, config, cluster.ID)
		if err != nil {
			return err
		}

		fmt.Printf("- Name: %s\n", detailedCluster.Name)
		fmt.Printf("  ID: %s\n", detailedCluster.ID)
		fmt.Printf("  Upstream IPs: %v\n", detailedCluster.UpstreamIPs)
		fmt.Printf("  DNS Firewall IPs: %v\n", detailedCluster.DNSFirewallIPs)
		fmt.Printf("  Min Cache TTL: %d\n", detailedCluster.MinimumCacheTTL)
		fmt.Printf("  Max Cache TTL: %d\n", detailedCluster.MaximumCacheTTL)
		fmt.Printf("  Deprecate ANY Requests: %v\n", detailedCluster.DeprecateAnyRequests)
		fmt.Printf("  Modified On: %s\n", detailedCluster.ModifiedOn)

		analytics, err := getClusterAnalytics(api, config, cluster.ID)
		if err != nil {
			return err
		}

		fmt.Println("  Analytics (Last 24 hours):")
		fmt.Printf("    Query Count: %d\n", *analytics.Totals.QueryCount)
		fmt.Printf("    Uncached Count: %d\n", *analytics.Totals.UncachedCount)
		fmt.Printf("    Stale Count: %d\n", *analytics.Totals.StaleCount)
		fmt.Printf("    Avg Response Time: %.2f\n", *analytics.Totals.ResponseTimeAvg)
		fmt.Println()
	}

	return nil
}

func runJSONOutput(api *cloudflare.API, config *Config) error {
	ctx := context.Background()
	rc := cloudflare.AccountIdentifier(config.AccountID)
	params := cloudflare.ListDNSFirewallClustersParams{}

	clusters, err := api.ListDNSFirewallClusters(ctx, rc, params)
	if err != nil {
		return err
	}

	type ClusterWithAnalytics struct {
		cloudflare.DNSFirewallCluster
		Analytics *cloudflare.DNSFirewallAnalytics `json:"analytics"`
	}

	detailedClusters := make([]ClusterWithAnalytics, len(clusters))
	for i, cluster := range clusters {
		detailedCluster, err := getDetailedCluster(api, config, cluster.ID)
		if err != nil {
			return err
		}

		analytics, err := getClusterAnalytics(api, config, cluster.ID)
		if err != nil {
			return err
		}

		detailedClusters[i] = ClusterWithAnalytics{
			DNSFirewallCluster: *detailedCluster,
			Analytics:          &analytics,
		}
	}

	jsonData, err := json.MarshalIndent(detailedClusters, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonData))
	return nil
}

func runMarkdownOutput(api *cloudflare.API, config *Config) error {
	ctx := context.Background()
	rc := cloudflare.AccountIdentifier(config.AccountID)
	params := cloudflare.ListDNSFirewallClustersParams{}

	clusters, err := api.ListDNSFirewallClusters(ctx, rc, params)
	if err != nil {
		return err
	}

	fmt.Println("# Cloudflare DNS Firewall Clusters")
	fmt.Println()

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "ID", "Upstream IPs", "DNS Firewall IPs", "Min TTL", "Max TTL", "Deprecate ANY", "Modified On"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")

	for _, cluster := range clusters {
		detailedCluster, err := api.GetDNSFirewallCluster(ctx, rc, cloudflare.GetDNSFirewallClusterParams{ClusterID: cluster.ID})
		if err != nil {
			return err
		}

		table.Append([]string{
			detailedCluster.Name,
			detailedCluster.ID,
			strings.Join(detailedCluster.UpstreamIPs, ", "),
			strings.Join(detailedCluster.DNSFirewallIPs, ", "),
			strconv.Itoa(int(detailedCluster.MinimumCacheTTL)),
			strconv.Itoa(int(detailedCluster.MaximumCacheTTL)),
			strconv.FormatBool(detailedCluster.DeprecateAnyRequests),
			detailedCluster.ModifiedOn,
		})
	}

	table.Render()

	fmt.Println("\n## Analytics (Last 24 hours)")
	fmt.Println()

	analyticsTable := tablewriter.NewWriter(os.Stdout)
	analyticsTable.SetHeader([]string{"Cluster", "Query Count", "Uncached Count", "Stale Count", "Avg Response Time"})
	analyticsTable.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	analyticsTable.SetCenterSeparator("|")

	for _, cluster := range clusters {
		analytics, err := api.GetDNSFirewallUserAnalytics(ctx, rc, cloudflare.GetDNSFirewallUserAnalyticsParams{
			ClusterID: cluster.ID,
			DNSFirewallUserAnalyticsOptions: cloudflare.DNSFirewallUserAnalyticsOptions{
				Metrics: []string{"queryCount", "uncachedCount", "staleCount", "responseTimeAvg"},
				Since:   timePtr(time.Now().Add(-24 * time.Hour)),
				Until:   timePtr(time.Now()),
			},
		})
		if err != nil {
			return err
		}

		analyticsTable.Append([]string{
			cluster.Name,
			strconv.FormatInt(*analytics.Totals.QueryCount, 10),
			strconv.FormatInt(*analytics.Totals.UncachedCount, 10),
			strconv.FormatInt(*analytics.Totals.StaleCount, 10),
			fmt.Sprintf("%.2f", *analytics.Totals.ResponseTimeAvg),
		})
	}

	analyticsTable.Render()

	return nil
}

func getDetailedCluster(api *cloudflare.API, config *Config, clusterID string) (*cloudflare.DNSFirewallCluster, error) {
	ctx := context.Background()
	rc := cloudflare.AccountIdentifier(config.AccountID)
	params := cloudflare.GetDNSFirewallClusterParams{
		ClusterID: clusterID,
	}

	return api.GetDNSFirewallCluster(ctx, rc, params)
}

func getClusterAnalytics(api *cloudflare.API, config *Config, clusterID string) (cloudflare.DNSFirewallAnalytics, error) {
	ctx := context.Background()
	rc := cloudflare.AccountIdentifier(config.AccountID)
	params := cloudflare.GetDNSFirewallUserAnalyticsParams{
		ClusterID: clusterID,
		DNSFirewallUserAnalyticsOptions: cloudflare.DNSFirewallUserAnalyticsOptions{
			Metrics: []string{"queryCount", "uncachedCount", "staleCount", "responseTimeAvg"},
			Since:   timePtr(time.Now().Add(-24 * time.Hour)),
			Until:   timePtr(time.Now()),
		},
	}

	analytics, err := api.GetDNSFirewallUserAnalytics(ctx, rc, params)
	if err != nil {
		fmt.Println(err)
	}
	return analytics, nil
}

func timePtr(t time.Time) *time.Time {
	return &t
}
