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
	"strconv"
	"strings"
	"time"
)

const (
	version          = "0.5.0"
	maxResponseBytes = 3 << 20
)

type config struct {
	ServerURL   string `json:"server_url"`
	AgentID     string `json:"agent_id"`
	AgentToken  string `json:"agent_token"`
	PollSeconds int    `json:"poll_seconds"`
	SingBoxPath string `json:"sing_box_path"`
	ServiceName string `json:"service_name"`
	RuntimePath string `json:"runtime_config_path"`
	StatePath   string `json:"state_path"`
	InitSystem  string `json:"init_system"`
	InstallMode string `json:"install_mode"`
}

type permissions struct {
	User                string `json:"user"`
	UID                 int    `json:"uid"`
	EUID                int    `json:"euid"`
	GID                 int    `json:"gid"`
	IsRoot              bool   `json:"is_root"`
	EffectiveCapsHex    string `json:"effective_capabilities_hex"`
	ConfigReadable      bool   `json:"config_readable"`
	ConfigWritable      bool   `json:"config_writable"`
	SingBoxExecutable   bool   `json:"sing_box_executable"`
	ServiceControl      bool   `json:"service_control"`
	Distribution        string `json:"distribution"`
	DistributionVersion string `json:"distribution_version"`
	Libc                string `json:"libc"`
	InitSystem          string `json:"init_system"`
	InstallMode         string `json:"install_mode"`
	BindLowPort         bool   `json:"bind_low_port"`
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
		fatal("usage: nodemanage-agent <install|repair|upgrade|diagnose|uninstall|run|once|version>")
	}
	switch os.Args[1] {
	case "install":
		installCommand(os.Args[2:])
	case "repair":
		repairCommand(os.Args[2:])
	case "upgrade":
		upgradeCommand(os.Args[2:])
	case "diagnose":
		diagnoseCommand()
	case "uninstall":
		uninstallCommand(os.Args[2:])
	case "run":
		run(os.Args[2:], false)
	case "once":
		run(os.Args[2:], true)
	case "version":
		fmt.Println(version)
	default:
		fatal("unknown command: " + os.Args[1])
	}
}

func run(args []string, once bool) {
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := flags.String("config", defaultLayout().AgentConfig, "agent configuration path")
	_ = flags.Parse(args)
	a := &agent{configPath: *configPath, client: &http.Client{Timeout: 20 * time.Second}}
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
	if a.config.ServerURL == "" || a.config.AgentID == "" || a.config.AgentToken == "" || a.config.SingBoxPath == "" || a.config.RuntimePath == "" || a.config.StatePath == "" || a.config.InitSystem == "" {
		return errors.New("agent configuration is incomplete")
	}
	if a.config.InstallMode != "system" && a.config.InstallMode != "user" {
		return errors.New("agent configuration has an invalid install_mode")
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
		SingBoxRunning: serviceActive(a.config.InitSystem, a.config.InstallMode, strings.TrimSuffix(a.config.ServiceName, ".service")), UptimeSeconds: uptimeSeconds(),
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
	layout, err := layoutFromConfig(a.config)
	if err != nil {
		return err
	}
	if err := ensureReleaseLayout(a.config.RuntimePath, layout.ReleasesRoot); err != nil {
		return fmt.Errorf("prepare A/B releases: %w", err)
	}
	releasesRoot := layout.ReleasesRoot
	temporaryDir := filepath.Join(releasesRoot, fmt.Sprintf("r%d.tmp", revision))
	releaseDir := filepath.Join(releasesRoot, fmt.Sprintf("r%d", revision))
	if err := os.RemoveAll(temporaryDir); err != nil {
		return fmt.Errorf("clean temporary release: %w", err)
	}
	if err := os.MkdirAll(temporaryDir, 0700); err != nil {
		return fmt.Errorf("create temporary release: %w", err)
	}
	defer os.RemoveAll(temporaryDir)
	temporaryConfig := filepath.Join(temporaryDir, "config.json")
	if err := os.WriteFile(temporaryConfig, []byte(configJSON), 0600); err != nil {
		return fmt.Errorf("write temporary config: %w", err)
	}
	if a.config.InstallMode == "user" {
		if err := validateUserPorts([]byte(configJSON)); err != nil {
			return err
		}
	}
	if output, err := exec.Command(a.config.SingBoxPath, "check", "-c", temporaryConfig).CombinedOutput(); err != nil {
		return fmt.Errorf("sing-box check: %s", strings.TrimSpace(string(output)))
	}
	_ = os.RemoveAll(releaseDir)
	if err := os.Rename(temporaryDir, releaseDir); err != nil {
		return fmt.Errorf("finalize release: %w", err)
	}
	currentLink := filepath.Join(layout.StateRoot, "current")
	previousLink := filepath.Join(layout.StateRoot, "previous")
	oldTarget, _ := os.Readlink(currentLink)
	if oldTarget != "" {
		if err := atomicSymlink(oldTarget, previousLink); err != nil {
			return fmt.Errorf("record previous release: %w", err)
		}
	}
	if err := atomicSymlink(releaseDir, currentLink); err != nil {
		return fmt.Errorf("activate release: %w", err)
	}
	if err := restartService(a.config.InitSystem, a.config.InstallMode, strings.TrimSuffix(a.config.ServiceName, ".service")); err != nil {
		return a.rollback(fmt.Errorf("restart sing-box: %w", err))
	}
	time.Sleep(800 * time.Millisecond)
	if !serviceActive(a.config.InitSystem, a.config.InstallMode, strings.TrimSuffix(a.config.ServiceName, ".service")) {
		return a.rollback(errors.New("sing-box is not active after restart"))
	}
	return os.WriteFile(a.config.RuntimePath+".revision", []byte(strconv.FormatInt(revision, 10)+"\n"), 0600)
}

func validateUserPorts(data []byte) error {
	var document struct {
		Inbounds []struct {
			ListenPort int `json:"listen_port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("parse runtime configuration: %w", err)
	}
	for _, inbound := range document.Inbounds {
		if inbound.ListenPort > 0 && inbound.ListenPort <= 1024 {
			return fmt.Errorf("user installation cannot bind privileged port %d; use a port above 1024", inbound.ListenPort)
		}
	}
	return nil
}

func (a *agent) rollback(reason error) error {
	layout, layoutErr := layoutFromConfig(a.config)
	if layoutErr != nil {
		return fmt.Errorf("%v; rollback layout unavailable: %w", reason, layoutErr)
	}
	previous, err := os.Readlink(filepath.Join(layout.StateRoot, "previous"))
	if err != nil {
		return fmt.Errorf("%v; rollback unavailable: %w", reason, err)
	}
	if err := atomicSymlink(previous, filepath.Join(layout.StateRoot, "current")); err != nil {
		return fmt.Errorf("%v; rollback switch failed: %w", reason, err)
	}
	restartErr := restartService(a.config.InitSystem, a.config.InstallMode, strings.TrimSuffix(a.config.ServiceName, ".service"))
	if restartErr != nil {
		return fmt.Errorf("%v; rollback restart failed: %w", reason, restartErr)
	}
	return fmt.Errorf("%v; previous configuration restored", reason)
}

func ensureReleaseLayout(runtimePath, releasesRoot string) error {
	root := filepath.Dir(releasesRoot)
	currentLink := filepath.Join(root, "current")
	if err := os.MkdirAll(releasesRoot, 0700); err != nil {
		return err
	}
	if _, err := os.Stat(currentLink); errors.Is(err, os.ErrNotExist) {
		if err := os.Remove(currentLink); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		bootstrapDir := filepath.Join(releasesRoot, "bootstrap")
		if err := os.MkdirAll(bootstrapDir, 0700); err != nil {
			return err
		}
		if data, readErr := os.ReadFile(runtimePath); readErr == nil {
			if err := os.WriteFile(filepath.Join(bootstrapDir, "config.json"), data, 0600); err != nil {
				return err
			}
		} else {
			return readErr
		}
		if err := atomicSymlink(bootstrapDir, currentLink); err != nil {
			return err
		}
	}
	info, err := os.Lstat(runtimePath)
	if err == nil && info.Mode()&os.ModeSymlink == 0 {
		if err := os.Remove(runtimePath); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(runtimePath); errors.Is(err, os.ErrNotExist) {
		if err := os.Symlink(filepath.Join(currentLink, "config.json"), runtimePath); err != nil {
			return err
		}
	}
	return nil
}

func atomicSymlink(target, link string) error {
	temporary := link + ".new"
	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	return os.Rename(temporary, link)
}

func collectPermissions(cfg config) permissions {
	current, _ := user.Current()
	username := ""
	if current != nil {
		username = current.Username
	}
	platform := detectPlatform()
	return permissions{
		User: username, UID: os.Getuid(), EUID: os.Geteuid(), GID: os.Getgid(), IsRoot: os.Geteuid() == 0,
		EffectiveCapsHex: effectiveCapabilities(), ConfigReadable: canOpen(cfg.RuntimePath, os.O_RDONLY),
		ConfigWritable: canOpen(cfg.RuntimePath, os.O_WRONLY), SingBoxExecutable: commandOK(cfg.SingBoxPath, "version"),
		ServiceControl: serviceControlAvailable(cfg.InitSystem, cfg.InstallMode),
		Distribution:   platform.Distribution, DistributionVersion: platform.DistributionVersion, Libc: platform.Libc,
		InitSystem: platform.InitSystem, InstallMode: cfg.InstallMode, BindLowPort: os.Geteuid() == 0 || hasBindLowPortCapability(),
	}
}

func hasBindLowPortCapability() bool {
	value, err := strconv.ParseUint(effectiveCapabilities(), 16, 64)
	return err == nil && value&(1<<10) != 0
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
