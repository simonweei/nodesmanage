package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	version           = "0.2.0"
	defaultConfigPath = "/etc/nodemanage/agent.json"
	maxResponseBytes  = 3 << 20
)

type config struct {
	ServerURL   string `json:"server_url"`
	AgentID     string `json:"agent_id"`
	AgentToken  string `json:"agent_token"`
	PollSeconds int    `json:"poll_seconds"`
	SingBoxPath string `json:"sing_box_path"`
	ServiceName string `json:"service_name"`
	RuntimePath string `json:"runtime_config_path"`
	BackupPath  string `json:"backup_config_path"`
}

type permissions struct {
	User              string `json:"user"`
	UID               int    `json:"uid"`
	EUID              int    `json:"euid"`
	GID               int    `json:"gid"`
	IsRoot            bool   `json:"is_root"`
	EffectiveCapsHex  string `json:"effective_capabilities_hex"`
	ConfigReadable    bool   `json:"config_readable"`
	ConfigWritable    bool   `json:"config_writable"`
	SingBoxExecutable bool   `json:"sing_box_executable"`
	ServiceControl    bool   `json:"service_control"`
}

type syncRequest struct {
	AgentVersion     string      `json:"agent_version"`
	SingBoxVersion   string      `json:"singbox_version"`
	CurrentRevision  *int64      `json:"current_revision"`
	SingBoxRunning   bool        `json:"singbox_running"`
	CPUUsagePercent  float64     `json:"cpu_usage_percent"`
	UptimeSeconds    int64       `json:"uptime_seconds"`
	MemoryTotalBytes int64       `json:"memory_total_bytes"`
	MemoryUsedBytes  int64       `json:"memory_used_bytes"`
	DiskTotalBytes   int64       `json:"disk_total_bytes"`
	DiskUsedBytes    int64       `json:"disk_used_bytes"`
	Permissions      permissions `json:"permissions"`
}

type syncResponse struct {
	DesiredRevision *int64 `json:"desired_revision"`
	ConfigJSON      string `json:"config_json"`
	SHA256          string `json:"sha256"`
	PollSeconds     int    `json:"poll_seconds"`
}

type agent struct {
	configPath  string
	config      config
	client      *http.Client
	previousCPU cpuSample
}

type cpuSample struct {
	total uint64
	idle  uint64
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: nodemanage-agent <register|run|once|version>")
	}
	switch os.Args[1] {
	case "register":
		register(os.Args[2:])
	case "run":
		run(false)
	case "once":
		run(true)
	case "version":
		fmt.Println(version)
	default:
		fatal("unknown command: " + os.Args[1])
	}
}

func register(args []string) {
	flags := flag.NewFlagSet("register", flag.ExitOnError)
	server := flags.String("server", "", "management server URL")
	code := flags.String("code", "", "enrollment code")
	name := flags.String("name", "", "agent display name")
	configPath := flags.String("config", defaultConfigPath, "agent configuration path")
	_ = flags.Parse(args)
	if *server == "" || *code == "" || *name == "" {
		fatal("--server, --code and --name are required")
	}
	hostname, err := os.Hostname()
	must(err)
	body := map[string]string{"code": *code, "name": *name, "hostname": hostname, "architecture": runtime.GOARCH, "os": runtime.GOOS}
	var response struct {
		AgentID     string `json:"agent_id"`
		AgentToken  string `json:"agent_token"`
		PollSeconds int    `json:"poll_seconds"`
	}
	registrationClient := &http.Client{Timeout: 20 * time.Second}
	must(postJSON(registrationClient, strings.TrimRight(*server, "/")+"/api/agent/register", "", body, &response))
	if response.AgentID == "" || response.AgentToken == "" {
		fatal("registration returned empty credentials")
	}
	cfg := config{
		ServerURL: strings.TrimRight(*server, "/"), AgentID: response.AgentID, AgentToken: response.AgentToken,
		PollSeconds: response.PollSeconds, SingBoxPath: "/usr/local/bin/sing-box", ServiceName: "sing-box.service",
		RuntimePath: "/etc/sing-box/config.json", BackupPath: "/etc/sing-box/config.json.bak",
	}
	if cfg.PollSeconds < 15 {
		cfg.PollSeconds = 60
	}
	must(writeJSONAtomic(*configPath, cfg, 0600))
	fmt.Printf("registered agent %s\n", response.AgentID)
}

func run(once bool) {
	a := &agent{configPath: defaultConfigPath, client: &http.Client{Timeout: 20 * time.Second}}
	must(a.loadConfig())
	for {
		if err := a.sync(); err != nil {
			fmt.Fprintf(os.Stderr, "sync failed: %v\n", err)
			if once {
				os.Exit(1)
			}
		}
		if once {
			return
		}
		time.Sleep(time.Duration(a.config.PollSeconds) * time.Second)
	}
}

func (a *agent) loadConfig() error {
	data, err := os.ReadFile(a.configPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &a.config); err != nil {
		return err
	}
	if a.config.ServerURL == "" || a.config.AgentToken == "" {
		return errors.New("agent configuration is incomplete")
	}
	return nil
}

func (a *agent) sync() error {
	currentRevision := readRevision(a.config.RuntimePath + ".revision")
	memoryTotal, memoryUsed := memoryStats()
	diskTotal, diskUsed := diskStats(filepath.Dir(a.config.RuntimePath))
	cpuUsage := a.cpuUsage()
	request := syncRequest{
		AgentVersion: version, SingBoxVersion: commandOutput(a.config.SingBoxPath, "version"), CurrentRevision: currentRevision,
		SingBoxRunning: commandOK("systemctl", "is-active", "--quiet", a.config.ServiceName), UptimeSeconds: uptimeSeconds(),
		CPUUsagePercent:  cpuUsage,
		MemoryTotalBytes: memoryTotal, MemoryUsedBytes: memoryUsed, DiskTotalBytes: diskTotal, DiskUsedBytes: diskUsed,
		Permissions: collectPermissions(a.config),
	}
	var response syncResponse
	if err := postJSON(a.client, a.config.ServerURL+"/api/agent/sync", a.config.AgentToken, request, &response); err != nil {
		return err
	}
	if response.PollSeconds >= 15 && response.PollSeconds != a.config.PollSeconds {
		a.config.PollSeconds = response.PollSeconds
		if err := writeJSONAtomic(a.configPath, a.config, 0600); err != nil {
			return fmt.Errorf("save poll interval: %w", err)
		}
	}
	if response.DesiredRevision == nil || response.ConfigJSON == "" || (currentRevision != nil && *response.DesiredRevision == *currentRevision) {
		return nil
	}
	err := a.apply(*response.DesiredRevision, response.ConfigJSON, response.SHA256)
	result := map[string]any{"revision": *response.DesiredRevision, "success": err == nil}
	if err != nil {
		result["error"] = err.Error()
	}
	if reportErr := postJSON(a.client, a.config.ServerURL+"/api/agent/result", a.config.AgentToken, result, nil); reportErr != nil {
		return fmt.Errorf("apply result: %v; report result: %w", err, reportErr)
	}
	return err
}

func (a *agent) cpuUsage() float64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}
	var sample cpuSample
	for index, field := range fields[1:] {
		value, parseErr := strconv.ParseUint(field, 10, 64)
		if parseErr != nil {
			return 0
		}
		sample.total += value
		if index == 3 || index == 4 {
			sample.idle += value
		}
	}
	previous := a.previousCPU
	a.previousCPU = sample
	if previous.total == 0 || sample.total <= previous.total {
		return 0
	}
	totalDelta := sample.total - previous.total
	idleDelta := sample.idle - previous.idle
	usage := 100 * float64(totalDelta-idleDelta) / float64(totalDelta)
	return float64(int(usage*10+0.5)) / 10
}

func (a *agent) apply(revision int64, configJSON, expectedHash string) error {
	digest := sha256.Sum256([]byte(configJSON))
	if !strings.EqualFold(hex.EncodeToString(digest[:]), expectedHash) {
		return errors.New("configuration checksum mismatch")
	}
	temporary := a.config.RuntimePath + ".new"
	if err := os.WriteFile(temporary, []byte(configJSON), 0600); err != nil {
		return fmt.Errorf("write temporary config: %w", err)
	}
	defer os.Remove(temporary)
	if output, err := exec.Command(a.config.SingBoxPath, "check", "-c", temporary).CombinedOutput(); err != nil {
		return fmt.Errorf("sing-box check: %s", strings.TrimSpace(string(output)))
	}
	oldConfig, readErr := os.ReadFile(a.config.RuntimePath)
	if readErr == nil {
		if err := os.WriteFile(a.config.BackupPath, oldConfig, 0600); err != nil {
			return fmt.Errorf("backup current config: %w", err)
		}
	}
	if err := os.Rename(temporary, a.config.RuntimePath); err != nil {
		return fmt.Errorf("activate config: %w", err)
	}
	if output, err := exec.Command("systemctl", "restart", a.config.ServiceName).CombinedOutput(); err != nil {
		return a.rollback(fmt.Errorf("restart sing-box: %s", strings.TrimSpace(string(output))))
	}
	time.Sleep(800 * time.Millisecond)
	if !commandOK("systemctl", "is-active", "--quiet", a.config.ServiceName) {
		return a.rollback(errors.New("sing-box is not active after restart"))
	}
	return os.WriteFile(a.config.RuntimePath+".revision", []byte(strconv.FormatInt(revision, 10)+"\n"), 0600)
}

func (a *agent) rollback(reason error) error {
	backup, err := os.ReadFile(a.config.BackupPath)
	if err != nil {
		return fmt.Errorf("%v; rollback unavailable: %w", reason, err)
	}
	if err := os.WriteFile(a.config.RuntimePath, backup, 0600); err != nil {
		return fmt.Errorf("%v; rollback write failed: %w", reason, err)
	}
	output, restartErr := exec.Command("systemctl", "restart", a.config.ServiceName).CombinedOutput()
	if restartErr != nil {
		return fmt.Errorf("%v; rollback restart failed: %s", reason, strings.TrimSpace(string(output)))
	}
	return fmt.Errorf("%v; previous configuration restored", reason)
}

func collectPermissions(cfg config) permissions {
	current, _ := user.Current()
	username := ""
	if current != nil {
		username = current.Username
	}
	return permissions{
		User: username, UID: os.Getuid(), EUID: os.Geteuid(), GID: os.Getgid(), IsRoot: os.Geteuid() == 0,
		EffectiveCapsHex: effectiveCapabilities(), ConfigReadable: canOpen(cfg.RuntimePath, os.O_RDONLY),
		ConfigWritable: canOpen(cfg.RuntimePath, os.O_WRONLY), SingBoxExecutable: commandOK(cfg.SingBoxPath, "version"),
		ServiceControl: os.Geteuid() == 0 && commandOK("systemctl", "show", "--property=LoadState", "--value", cfg.ServiceName),
	}
}

func effectiveCapabilities() string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		}
	}
	return ""
}

func canOpen(path string, flag int) bool {
	file, err := os.OpenFile(path, flag, 0)
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

func uptimeSeconds() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	value, _ := strconv.ParseFloat(fields[0], 64)
	return int64(value)
}

func memoryStats() (int64, int64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	values := map[string]int64{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			value, _ := strconv.ParseInt(fields[1], 10, 64)
			values[strings.TrimSuffix(fields[0], ":")] = value * 1024
		}
	}
	return values["MemTotal"], values["MemTotal"] - values["MemAvailable"]
}

func readRevision(path string) *int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || value < 1 {
		return nil
	}
	return &value
}

func commandOK(name string, args ...string) bool {
	return exec.Command(name, args...).Run() == nil
}

func commandOutput(name string, args ...string) string {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return ""
	}
	value := strings.TrimSpace(string(output))
	if len(value) > 120 {
		value = value[:120]
	}
	return value
}

func postJSON(client *http.Client, url, token string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "nodemanage-agent/"+version)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("server response too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("server returned %s: %s", response.Status, strings.TrimSpace(string(data)))
	}
	if output != nil && len(data) > 0 {
		return json.Unmarshal(data, output)
	}
	return nil
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary := path + ".new"
	if err := os.WriteFile(temporary, append(data, '\n'), mode); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func must(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
