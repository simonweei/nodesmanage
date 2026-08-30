package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
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
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	maxDownloadBytes     = 128 << 20
	minimalRuntimeConfig = "{\n  \"inbounds\": [],\n  \"outbounds\": [{\"type\": \"direct\"}]\n}\n"
)

type releaseFile struct {
	Version     string   `json:"version"`
	URLs        []string `json:"urls"`
	SHA256      string   `json:"sha256"`
	ArchiveRoot string   `json:"archive_root"`
}

type releaseManifest struct {
	SchemaVersion int         `json:"schema_version"`
	Agent         releaseFile `json:"agent"`
	SingBox       releaseFile `json:"sing_box"`
}

type platformInfo struct {
	OS                  string `json:"os"`
	Architecture        string `json:"architecture"`
	Distribution        string `json:"distribution"`
	DistributionVersion string `json:"distribution_version"`
	Libc                string `json:"libc"`
	InitSystem          string `json:"init_system"`
	InstallMode         string `json:"install_mode"`
}

type installReporter struct {
	client  *http.Client
	server  string
	ticket  string
	token   string
	logPath string
}

func (reporter installReporter) report(stage, errorCode, message, source string) {
	if reporter.ticket != "" {
		message = strings.ReplaceAll(message, reporter.ticket, "[redacted]")
	}
	if reporter.token != "" {
		message = strings.ReplaceAll(message, reporter.token, "[redacted]")
	}
	line := fmt.Sprintf("%s stage=%s code=%s source=%s message=%s\n", time.Now().UTC().Format(time.RFC3339), stage, errorCode, source, message)
	if reporter.logPath != "" {
		_ = os.MkdirAll(filepath.Dir(reporter.logPath), 0700)
		if file, err := os.OpenFile(reporter.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
			_, _ = file.WriteString(line)
			_ = file.Close()
		}
	}
	fmt.Print(line)
	if reporter.server == "" || (reporter.ticket == "" && reporter.token == "") {
		return
	}
	body := map[string]string{"stage": stage, "error_code": errorCode, "message": message, "source": source}
	if reporter.ticket != "" {
		body["ticket"] = reporter.ticket
	}
	_ = postJSON(reporter.client, reporter.server+"/api/install/event", reporter.token, body, nil)
}

func installCommand(args []string) {
	flags := flag.NewFlagSet("install", flag.ExitOnError)
	server := flags.String("server", "", "management server URL")
	ticket := flags.String("ticket", "", "one-time install ticket")
	name := flags.String("name", "", "agent display name")
	modeFlag := flags.String("mode", "auto", "install mode: auto, system or user")
	manifestURL := flags.String("manifest", "", "release manifest URL")
	_ = flags.Parse(args)
	client := &http.Client{Timeout: 90 * time.Second}
	mode, modeErr := resolveInstallMode(*modeFlag)
	if modeErr != nil {
		fatal("[NM-E201] " + modeErr.Error())
	}
	layout, layoutErr := layoutForMode(mode)
	if layoutErr != nil {
		fatal("[NM-E201] " + layoutErr.Error())
	}
	reporter := installReporter{client: &http.Client{Timeout: 5 * time.Second}, server: strings.TrimRight(*server, "/"), ticket: *ticket, logPath: layout.LogPath}
	if runtime.GOOS != "linux" {
		reporter.report("failed", "NM-E201", "install requires Linux", "local")
		fatal("[NM-E201] install requires Linux")
	}
	if *server == "" || *ticket == "" || *name == "" {
		fatal("[NM-E202] --server, --ticket and --name are required")
	}
	if *manifestURL == "" {
		*manifestURL = strings.TrimRight(*server, "/") + "/api/install/manifest?os=linux&arch=" + runtime.GOARCH
	}
	platform := detectPlatform()
	platform.InstallMode = mode
	if mode == "user" && (platform.InitSystem != "systemd" || !userSystemdAvailable()) {
		reporter.report("failed", "NM-E203", "user mode requires an active systemd user manager", "local")
		fatal("[NM-E203] user mode requires systemctl --user; ask the administrator to enable lingering or keep a user session active")
	}
	if mode == "system" && platform.InitSystem != "systemd" && platform.InitSystem != "openrc" {
		reporter.report("failed", "NM-E203", "supported init system not found", "local")
		fatal("[NM-E203] supported init system not found (systemd or OpenRC required)")
	}
	reporter.report("bootstrap_started", "", "Agent bootstrap started", "worker-assets")
	var manifest releaseManifest
	if err := getJSON(client, *manifestURL, &manifest); err != nil {
		reporter.report("failed", "NM-E204", err.Error(), sourceHost(*manifestURL))
		fatal("[NM-E204] fetch release manifest: " + err.Error())
	}
	if manifest.SchemaVersion != 1 || len(manifest.Agent.URLs) == 0 || len(manifest.SingBox.URLs) == 0 {
		reporter.report("failed", "NM-E204", "invalid release manifest", sourceHost(*manifestURL))
		fatal("[NM-E204] invalid release manifest")
	}
	temporary, err := os.MkdirTemp("", "nodemanage-install-")
	if err != nil {
		reporter.report("failed", "NM-E210", err.Error(), "local")
		fatal("[NM-E210] create temporary directory: " + err.Error())
	}
	defer os.RemoveAll(temporary)

	agentFile := filepath.Join(temporary, "nodemanage-agent")
	singBoxArchive := filepath.Join(temporary, "sing-box.tar.gz")
	agentSource := "bootstrap"
	currentExecutable, executableErr := os.Executable()
	if executableErr != nil || !fileMatchesSHA256(currentExecutable, manifest.Agent.SHA256) {
		var downloadErr error
		agentSource, downloadErr = downloadVerifiedSources(client, manifest.Agent.URLs, agentFile, manifest.Agent.SHA256)
		if downloadErr != nil {
			reporter.report("failed", "NM-E208", downloadErr.Error(), "all-sources")
			fatal(downloadErr.Error())
		}
	} else if err := copyExecutable(currentExecutable, agentFile); err != nil {
		reporter.report("failed", "NM-E210", err.Error(), "local")
		fatal("[NM-E210] stage bootstrap Agent: " + err.Error())
	}
	reporter.report("agent_downloaded", "", "Agent artifact verified", sourceHost(agentSource))
	runtimeSource, err := downloadVerifiedSources(client, manifest.SingBox.URLs, singBoxArchive, manifest.SingBox.SHA256)
	if err != nil {
		reporter.report("failed", "NM-E208", err.Error(), "all-sources")
		fatal(err.Error())
	}
	reporter.report("runtime_downloaded", "", "sing-box archive downloaded and verified", sourceHost(runtimeSource))
	singBoxFile := filepath.Join(temporary, "sing-box")
	if err := extractTarFile(singBoxArchive, strings.Trim(manifest.SingBox.ArchiveRoot, "/")+"/sing-box", singBoxFile); err != nil {
		reporter.report("failed", "NM-E209", err.Error(), "local")
		fatal(err.Error())
	}
	for _, operation := range []func() error{
		func() error { return os.MkdirAll(layout.BinDir, 0755) },
		func() error { return installExecutable(agentFile, layout.AgentPath) },
		func() error { return installExecutable(singBoxFile, layout.SingBoxPath) },
		func() error { return os.MkdirAll(layout.RuntimeDir, 0700) },
	} {
		if err := operation(); err != nil {
			reporter.report("failed", "NM-E210", err.Error(), "local")
			fatal("[NM-E210] install runtime: " + err.Error())
		}
	}
	if _, err := os.Stat(layout.RuntimeConfig); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(layout.RuntimeConfig, []byte(minimalRuntimeConfig), 0600); err != nil {
			reporter.report("failed", "NM-E210", err.Error(), "local")
			fatal("[NM-E210] write runtime config: " + err.Error())
		}
	}
	if err := repairReleaseLayout(layout.RuntimeConfig, layout.ReleasesRoot); err != nil {
		reporter.report("failed", "NM-E210", err.Error(), "local")
		fatal("[NM-E210] prepare A/B configuration: " + err.Error())
	}
	reporter.report("runtime_installed", "", "Agent and sing-box installed atomically", "local")
	if _, err := os.Stat(layout.AgentConfig); errors.Is(err, os.ErrNotExist) {
		if err := registerTicket(client, strings.TrimRight(*server, "/"), *ticket, *name, layout.AgentConfig, platform, layout); err != nil {
			reporter.report("failed", "NM-E205", err.Error(), sourceHost(*server))
			fatal(err.Error())
		}
	}
	if err := writeServices(platform.InitSystem, layout); err != nil {
		reporter.report("failed", "NM-E213", err.Error(), "local")
		fatal("[NM-E213] install services: " + err.Error())
	}
	reporter.report("service_installed", "", platform.InitSystem+" service definitions installed", "local")
	if err := enableServices(platform.InitSystem, mode); err != nil {
		reporter.report("failed", "NM-E214", err.Error(), "local")
		fatal("[NM-E214] start services: " + err.Error())
	}
	fmt.Printf("NodeManage installed successfully (%s/%s, %s/%s)\n", runtime.GOOS, runtime.GOARCH, platform.InitSystem, mode)
}

func sourceHost(rawURL string) string {
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil || request.URL.Hostname() == "" {
		return "local"
	}
	return request.URL.Hostname()
}

func repairCommand(args []string) {
	flags := flag.NewFlagSet("repair", flag.ExitOnError)
	manifestURL := flags.String("manifest", "", "release manifest URL")
	_ = flags.Parse(args)
	cfg, layout, err := maintenanceContext(defaultLayout().AgentConfig, "NM-E212")
	if err != nil {
		fatal(err.Error())
	}
	client := &http.Client{Timeout: 90 * time.Second}
	reporter := installReporter{client: &http.Client{Timeout: 5 * time.Second}, server: cfg.ServerURL, token: cfg.AgentToken, logPath: layout.LogPath}
	platform := detectPlatform()
	platform.InstallMode = cfg.InstallMode
	if cfg.InstallMode == "user" && (platform.InitSystem != "systemd" || !userSystemdAvailable()) {
		fatal("[NM-E203] user mode requires an active systemd user manager")
	}
	if cfg.InstallMode == "system" && platform.InitSystem != "systemd" && platform.InitSystem != "openrc" {
		reporter.report("failed", "NM-E203", "supported init system not found", "local")
		fatal("[NM-E203] supported init system not found")
	}
	if *manifestURL == "" {
		*manifestURL = strings.TrimRight(cfg.ServerURL, "/") + "/api/install/manifest?os=linux&arch=" + runtime.GOARCH
	}
	var manifest releaseManifest
	if err := getJSON(client, *manifestURL, &manifest); err != nil {
		reporter.report("failed", "NM-E204", err.Error(), sourceHost(*manifestURL))
		fatal("[NM-E204] fetch release manifest: " + err.Error())
	}
	temporary, err := os.MkdirTemp("", "nodemanage-repair-")
	if err != nil {
		reporter.report("failed", "NM-E210", err.Error(), "local")
		fatal("[NM-E210] create temporary directory: " + err.Error())
	}
	defer os.RemoveAll(temporary)
	if commandOutput(layout.AgentPath, "version") != manifest.Agent.Version {
		download := filepath.Join(temporary, "nodemanage-agent")
		if _, err := downloadVerifiedSources(client, manifest.Agent.URLs, download, manifest.Agent.SHA256); err != nil {
			reporter.report("failed", "NM-E208", err.Error(), "all-sources")
			fatal(err.Error())
		}
		if err := os.MkdirAll(layout.BinDir, 0755); err != nil {
			fatal("[NM-E210] " + err.Error())
		}
		if err := installExecutable(download, layout.AgentPath); err != nil {
			reporter.report("failed", "NM-E210", err.Error(), "local")
			fatal("[NM-E210] " + err.Error())
		}
	}
	if !strings.Contains(commandOutput(layout.SingBoxPath, "version"), manifest.SingBox.Version) {
		archive := filepath.Join(temporary, "sing-box.tar.gz")
		binary := filepath.Join(temporary, "sing-box")
		if _, err := downloadVerifiedSources(client, manifest.SingBox.URLs, archive, manifest.SingBox.SHA256); err != nil {
			reporter.report("failed", "NM-E208", err.Error(), "all-sources")
			fatal(err.Error())
		}
		if err := extractTarFile(archive, strings.Trim(manifest.SingBox.ArchiveRoot, "/")+"/sing-box", binary); err != nil {
			reporter.report("failed", "NM-E209", err.Error(), "local")
			fatal(err.Error())
		}
		if err := os.MkdirAll(layout.BinDir, 0755); err != nil {
			fatal("[NM-E210] " + err.Error())
		}
		if err := installExecutable(binary, layout.SingBoxPath); err != nil {
			reporter.report("failed", "NM-E210", err.Error(), "local")
			fatal("[NM-E210] " + err.Error())
		}
	}
	if err := os.MkdirAll(layout.RuntimeDir, 0700); err != nil {
		fatal("[NM-E210] " + err.Error())
	}
	if err := repairReleaseLayout(layout.RuntimeConfig, layout.ReleasesRoot); err != nil {
		reporter.report("failed", "NM-E210", err.Error(), "local")
		fatal("[NM-E210] repair A/B configuration: " + err.Error())
	}
	if err := writeServices(platform.InitSystem, layout); err != nil {
		reporter.report("failed", "NM-E213", err.Error(), "local")
		fatal("[NM-E213] " + err.Error())
	}
	if err := enableServices(platform.InitSystem, cfg.InstallMode); err != nil {
		reporter.report("failed", "NM-E214", err.Error(), "local")
		fatal("[NM-E214] " + err.Error())
	}
	reporter.report("service_installed", "", "Binaries, configuration and services repaired", "local")
	fmt.Println("NodeManage services repaired successfully")
}

func repairReleaseLayout(runtimePath, releasesRoot string) error {
	if err := os.MkdirAll(filepath.Dir(runtimePath), 0700); err != nil {
		return err
	}
	if !fileExists(runtimePath) {
		if info, err := os.Lstat(runtimePath); err == nil && info.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(runtimePath); err != nil {
				return err
			}
		}
		if err := os.WriteFile(runtimePath, []byte(minimalRuntimeConfig), 0600); err != nil {
			return err
		}
	}
	return ensureReleaseLayout(runtimePath, releasesRoot)
}

func upgradeCommand(args []string) {
	flags := flag.NewFlagSet("upgrade", flag.ExitOnError)
	manifestURL := flags.String("manifest", "", "release manifest URL")
	_ = flags.Parse(args)
	cfg, layout, err := maintenanceContext(defaultLayout().AgentConfig, "NM-E232")
	if err != nil {
		fatal(err.Error())
	}
	if *manifestURL == "" {
		*manifestURL = strings.TrimRight(cfg.ServerURL, "/") + "/api/install/manifest?os=linux&arch=" + runtime.GOARCH
	}
	client := &http.Client{Timeout: 90 * time.Second}
	reporter := installReporter{client: &http.Client{Timeout: 5 * time.Second}, server: cfg.ServerURL, token: cfg.AgentToken, logPath: layout.LogPath}
	var manifest releaseManifest
	if err := getJSON(client, *manifestURL, &manifest); err != nil {
		reporter.report("failed", "NM-E204", err.Error(), sourceHost(*manifestURL))
		fatal("[NM-E204] " + err.Error())
	}
	reporter.report("upgrading", "", "Binary upgrade started", sourceHost(*manifestURL))
	temporary, err := os.MkdirTemp("", "nodemanage-upgrade-")
	if err != nil {
		reporter.report("failed", "NM-E233", err.Error(), "local")
		fatal("[NM-E233] " + err.Error())
	}
	defer os.RemoveAll(temporary)
	backupRoot := layout.BackupRoot
	if err := os.MkdirAll(backupRoot, 0700); err != nil {
		fatal("[NM-E233] " + err.Error())
	}
	agentBackup := filepath.Join(backupRoot, "nodemanage-agent.previous")
	singBoxBackup := filepath.Join(backupRoot, "sing-box.previous")
	agentChanged, runtimeChanged := false, false

	if commandOutput(layout.AgentPath, "version") != manifest.Agent.Version {
		download := filepath.Join(temporary, "nodemanage-agent")
		if _, err := downloadVerifiedSources(client, manifest.Agent.URLs, download, manifest.Agent.SHA256); err != nil {
			reporter.report("failed", "NM-E208", err.Error(), "all-sources")
			fatal(err.Error())
		}
		if err := copyExecutable(layout.AgentPath, agentBackup); err != nil {
			fatal("[NM-E233] backup Agent: " + err.Error())
		}
		if err := installExecutable(download, layout.AgentPath); err != nil {
			fatal("[NM-E233] install Agent: " + err.Error())
		}
		if commandOutput(layout.AgentPath, "version") != manifest.Agent.Version {
			_ = installExecutable(agentBackup, layout.AgentPath)
			reporter.report("failed", "NM-E234", "new Agent failed version check", "local")
			fatal("[NM-E234] new Agent failed version check")
		}
		agentChanged = true
	}
	if !strings.Contains(commandOutput(layout.SingBoxPath, "version"), manifest.SingBox.Version) {
		archive := filepath.Join(temporary, "sing-box.tar.gz")
		binary := filepath.Join(temporary, "sing-box")
		if _, err := downloadVerifiedSources(client, manifest.SingBox.URLs, archive, manifest.SingBox.SHA256); err != nil {
			rollbackExecutables(layout, agentChanged, false, agentBackup, singBoxBackup)
			reporter.report("failed", "NM-E208", err.Error(), "all-sources")
			fatal(err.Error())
		}
		if err := extractTarFile(archive, strings.Trim(manifest.SingBox.ArchiveRoot, "/")+"/sing-box", binary); err != nil {
			rollbackExecutables(layout, agentChanged, false, agentBackup, singBoxBackup)
			fatal("[NM-E209] " + err.Error())
		}
		if err := copyExecutable(layout.SingBoxPath, singBoxBackup); err != nil {
			rollbackExecutables(layout, agentChanged, false, agentBackup, singBoxBackup)
			fatal("[NM-E233] backup sing-box: " + err.Error())
		}
		if err := installExecutable(binary, layout.SingBoxPath); err != nil {
			rollbackExecutables(layout, agentChanged, false, agentBackup, singBoxBackup)
			fatal("[NM-E233] install sing-box: " + err.Error())
		}
		if !strings.Contains(commandOutput(layout.SingBoxPath, "version"), manifest.SingBox.Version) {
			rollbackExecutables(layout, agentChanged, true, agentBackup, singBoxBackup)
			reporter.report("failed", "NM-E234", "new sing-box failed version check", "local")
			fatal("[NM-E234] new sing-box failed version check")
		}
		runtimeChanged = true
	}
	if runtimeChanged {
		if err := restartService(cfg.InitSystem, cfg.InstallMode, "sing-box"); err != nil {
			rollbackExecutables(layout, agentChanged, true, agentBackup, singBoxBackup)
			_ = restartService(cfg.InitSystem, cfg.InstallMode, "sing-box")
			reporter.report("failed", "NM-E235", err.Error(), "local")
			fatal("[NM-E235] restart sing-box: " + err.Error())
		}
		time.Sleep(time.Second)
		if !serviceActive(cfg.InitSystem, cfg.InstallMode, "sing-box") {
			rollbackExecutables(layout, agentChanged, true, agentBackup, singBoxBackup)
			_ = restartService(cfg.InitSystem, cfg.InstallMode, "sing-box")
			reporter.report("failed", "NM-E235", "sing-box is inactive after upgrade", "local")
			fatal("[NM-E235] sing-box is inactive after upgrade")
		}
	}
	if agentChanged {
		if err := restartService(cfg.InitSystem, cfg.InstallMode, "nodemanage-agent"); err != nil {
			rollbackExecutables(layout, true, runtimeChanged, agentBackup, singBoxBackup)
			reporter.report("failed", "NM-E235", err.Error(), "local")
			fatal("[NM-E235] restart Agent: " + err.Error())
		}
	}
	if !agentChanged && !runtimeChanged {
		reporter.report("upgraded", "", "Binaries already match stable manifest", "local")
	} else {
		reporter.report("upgraded", "", "Binary upgrade completed", "worker-assets")
	}
	fmt.Println("NodeManage upgrade completed successfully")
}

func copyExecutable(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.WriteFile(destination+".new", data, 0755); err != nil {
		return err
	}
	if err := os.Chmod(destination+".new", 0755); err != nil {
		return err
	}
	return os.Rename(destination+".new", destination)
}

func rollbackExecutables(layout installLayout, agentChanged, runtimeChanged bool, agentBackup, singBoxBackup string) {
	if agentChanged {
		_ = installExecutable(agentBackup, layout.AgentPath)
	}
	if runtimeChanged {
		_ = installExecutable(singBoxBackup, layout.SingBoxPath)
	}
}

func diagnoseCommand() {
	platform := detectPlatform()
	layout := defaultLayout()
	platform.InstallMode = layout.Mode
	result := map[string]any{"platform": platform, "is_root": os.Geteuid() == 0,
		"agent_installed": commandOK(layout.AgentPath, "version"), "sing_box_installed": commandOK(layout.SingBoxPath, "version"),
		"agent_config": fileExists(layout.AgentConfig), "runtime_config": fileExists(layout.RuntimeConfig),
		"agent_running": serviceActive(platform.InitSystem, layout.Mode, "nodemanage-agent"), "sing_box_running": serviceActive(platform.InitSystem, layout.Mode, "sing-box"),
		"paths": map[string]string{"agent": layout.AgentPath, "sing_box": layout.SingBoxPath, "config": layout.AgentConfig, "runtime": layout.RuntimeConfig, "state": layout.StateRoot}}
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(data))
}

func uninstallCommand(args []string) {
	flags := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := flags.Bool("purge", false, "also delete configurations")
	modeFlag := flags.String("mode", "auto", "install mode: auto, system or user")
	_ = flags.Parse(args)
	mode, err := resolveInstallMode(*modeFlag)
	if err != nil {
		fatal("[NM-E221] " + err.Error())
	}
	layout, err := layoutForMode(mode)
	if err != nil {
		fatal("[NM-E221] " + err.Error())
	}
	platform := detectPlatform()
	disableServices(platform.InitSystem, mode)
	for _, path := range serviceFiles(platform.InitSystem, layout) {
		_ = os.Remove(path)
	}
	if platform.InitSystem == "systemd" {
		_ = systemctl(mode, "daemon-reload").Run()
	}
	_ = os.Remove(layout.AgentPath)
	_ = os.Remove(layout.SingBoxPath)
	if *purge {
		_ = os.RemoveAll(filepath.Dir(layout.AgentConfig))
		if filepath.Clean(layout.RuntimeDir) != filepath.Clean(filepath.Dir(layout.AgentConfig)) {
			_ = os.RemoveAll(layout.RuntimeDir)
		}
		_ = os.RemoveAll(layout.StateRoot)
		_ = os.RemoveAll(layout.BackupRoot)
		_ = os.Remove(layout.LogPath)
	}
	fmt.Printf("NodeManage %s installation uninstalled; configuration retained unless --purge was used\n", mode)
}

func maintenanceContext(configPath, errorCode string) (config, installLayout, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return config{}, installLayout{}, fmt.Errorf("[%s] read Agent configuration: %w", errorCode, err)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil || cfg.ServerURL == "" || cfg.AgentID == "" || cfg.AgentToken == "" || cfg.SingBoxPath == "" || cfg.RuntimePath == "" || cfg.StatePath == "" || cfg.InitSystem == "" {
		return config{}, installLayout{}, fmt.Errorf("[%s] invalid Agent configuration", errorCode)
	}
	if cfg.InstallMode != "system" && cfg.InstallMode != "user" {
		return config{}, installLayout{}, fmt.Errorf("[%s] invalid install_mode", errorCode)
	}
	if cfg.InstallMode == "system" && os.Geteuid() != 0 {
		return config{}, installLayout{}, fmt.Errorf("[%s] system installation maintenance requires root", errorCode)
	}
	if cfg.InstallMode == "user" && os.Geteuid() == 0 {
		return config{}, installLayout{}, fmt.Errorf("[%s] user installation maintenance must run as the target user without sudo", errorCode)
	}
	layout, err := layoutFromConfig(cfg)
	if err != nil {
		return config{}, installLayout{}, fmt.Errorf("[%s] resolve installation layout: %w", errorCode, err)
	}
	layout.AgentConfig = configPath
	return cfg, layout, nil
}

func registerTicket(client *http.Client, server, ticket, name, configPath string, platform platformInfo, layout installLayout) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	claim, err := loadOrCreateInstallClaim(layout.ClaimPath)
	if err != nil {
		return fmt.Errorf("create install claim: %w", err)
	}
	body := map[string]string{"ticket": ticket, "claim": claim, "name": name, "hostname": hostname, "architecture": runtime.GOARCH, "os": runtime.GOOS,
		"distro": platform.Distribution, "distro_version": platform.DistributionVersion, "libc": platform.Libc, "init_system": platform.InitSystem, "install_mode": platform.InstallMode}
	var response struct {
		AgentID     string `json:"agent_id"`
		AgentToken  string `json:"agent_token"`
		PollSeconds int    `json:"poll_seconds"`
	}
	var registerErr error
	for attempt := 0; attempt < 3; attempt++ {
		registerErr = postJSON(client, server+"/api/agent/register", "", body, &response)
		if registerErr == nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	if registerErr != nil {
		return fmt.Errorf("[NM-E205] register: %w", registerErr)
	}
	if response.AgentID == "" || response.AgentToken == "" {
		return errors.New("[NM-E206] registration returned empty credentials")
	}
	cfg := config{ServerURL: server, AgentID: response.AgentID, AgentToken: response.AgentToken, PollSeconds: response.PollSeconds,
		SingBoxPath: layout.SingBoxPath, ServiceName: "sing-box", RuntimePath: layout.RuntimeConfig, StatePath: layout.StateRoot, InitSystem: platform.InitSystem, InstallMode: platform.InstallMode}
	if cfg.PollSeconds < 15 {
		cfg.PollSeconds = 60
	}
	if err := writeJSONAtomic(configPath, cfg, 0600); err != nil {
		return err
	}
	if err := os.Remove(layout.ClaimPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove install claim: %w", err)
	}
	return nil
}

func loadOrCreateInstallClaim(claimPath string) (string, error) {
	if data, err := os.ReadFile(claimPath); err == nil {
		claim := strings.TrimSpace(string(data))
		if len(claim) == 64 {
			if _, decodeErr := hex.DecodeString(claim); decodeErr == nil {
				return claim, nil
			}
		}
		return "", errors.New("stored install claim is invalid")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	claim := hex.EncodeToString(bytes)
	if err := os.MkdirAll(filepath.Dir(claimPath), 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(claimPath+".new", []byte(claim+"\n"), 0600); err != nil {
		return "", err
	}
	if err := os.Rename(claimPath+".new", claimPath); err != nil {
		return "", err
	}
	return claim, nil
}

func downloadVerified(client *http.Client, url, destination, expected string) error {
	if len(expected) != 64 {
		return errors.New("[NM-E207] release has no valid SHA-256")
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		response, err := client.Get(url)
		if err == nil {
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				err = fmt.Errorf("download returned %s", response.Status)
			} else {
				file, createErr := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
				if createErr != nil {
					response.Body.Close()
					return createErr
				}
				hash := sha256.New()
				written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, maxDownloadBytes+1))
				closeErr := file.Close()
				response.Body.Close()
				if copyErr == nil && closeErr == nil && written <= maxDownloadBytes && strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected) {
					return nil
				}
				if written > maxDownloadBytes {
					err = errors.New("download is too large")
				} else if copyErr != nil {
					err = copyErr
				} else if closeErr != nil {
					err = closeErr
				} else {
					err = errors.New("SHA-256 mismatch")
				}
			}
		}
		last = err
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	return fmt.Errorf("[NM-E208] download %s: %w", url, last)
}

func fileMatchesSHA256(path, expected string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false
	}
	return strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected)
}

func downloadVerifiedSources(client *http.Client, urls []string, destination, expected string) (string, error) {
	if len(urls) == 0 {
		return "", errors.New("[NM-E208] release has no download sources")
	}
	errorsBySource := make([]string, 0, len(urls))
	for _, source := range urls {
		if err := downloadVerified(client, source, destination, expected); err == nil {
			return source, nil
		} else {
			errorsBySource = append(errorsBySource, sourceHost(source)+": "+err.Error())
		}
	}
	return "", errors.New("[NM-E208] all download sources failed: " + strings.Join(errorsBySource, "; "))
}

func extractTarFile(archivePath, member, destination string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nextErr
		}
		if strings.TrimPrefix(filepath.ToSlash(header.Name), "./") == member && header.Typeflag == tar.TypeReg {
			output, createErr := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
			if createErr != nil {
				return createErr
			}
			_, copyErr := io.Copy(output, io.LimitReader(reader, 64<<20))
			closeErr := output.Close()
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		}
	}
	return errors.New("[NM-E209] sing-box binary is missing from archive")
}

func installExecutable(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	temporary := destination + ".new"
	if err := os.WriteFile(temporary, data, 0755); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0755); err != nil {
		return err
	}
	return os.Rename(temporary, destination)
}

func getJSON(client *http.Client, url string, output any) error {
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("manifest returned %s", response.Status)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output)
}

func detectPlatform() platformInfo {
	values := parseOSRelease("/etc/os-release")
	initSystem := "unknown"
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		initSystem = "systemd"
	} else if _, err := exec.LookPath("rc-service"); err == nil {
		initSystem = "openrc"
	}
	libc := "unknown"
	if output, _ := exec.Command("ldd", "--version").CombinedOutput(); len(output) > 0 {
		lower := strings.ToLower(string(output))
		if strings.Contains(lower, "musl") {
			libc = "musl"
		} else if strings.Contains(lower, "glibc") || strings.Contains(lower, "gnu libc") {
			libc = "glibc"
		}
	}
	return platformInfo{OS: runtime.GOOS, Architecture: runtime.GOARCH, Distribution: values["ID"], DistributionVersion: values["VERSION_ID"], Libc: libc, InitSystem: initSystem, InstallMode: "system"}
}

func parseOSRelease(path string) map[string]string {
	result := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && key != "" {
			result[key] = strings.Trim(strings.TrimSpace(value), "\"'")
		}
	}
	return result
}

func serviceFiles(initSystem string, layout installLayout) []string {
	if initSystem == "systemd" {
		return []string{filepath.Join(layout.ServiceDir, "sing-box.service"), filepath.Join(layout.ServiceDir, "nodemanage-agent.service")}
	}
	if initSystem == "openrc" && layout.Mode == "system" {
		return []string{"/etc/init.d/sing-box", "/etc/init.d/nodemanage-agent"}
	}
	return nil
}

func systemdQuote(path string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(path, `\`, `\\`), `"`, `\"`) + `"`
}

func writeServices(initSystem string, layout installLayout) error {
	if initSystem == "systemd" {
		wantedBy := "multi-user.target"
		capabilities := "AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
		if layout.Mode == "user" {
			wantedBy = "default.target"
			capabilities = ""
		}
		singBox := fmt.Sprintf("[Unit]\nDescription=sing-box proxy service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=%s run -c %s\nRestart=on-failure\nRestartSec=5s\nLimitNOFILE=1048576\n%sNoNewPrivileges=true\n\n[Install]\nWantedBy=%s\n", systemdQuote(layout.SingBoxPath), systemdQuote(layout.RuntimeConfig), capabilities, wantedBy)
		agent := fmt.Sprintf("[Unit]\nDescription=NodeManage Agent\nAfter=network-online.target sing-box.service\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=%s run --config %s\nRestart=always\nRestartSec=10s\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=%s\n", systemdQuote(layout.AgentPath), systemdQuote(layout.AgentConfig), wantedBy)
		if err := os.MkdirAll(layout.ServiceDir, 0700); err != nil {
			return err
		}
		files := serviceFiles(initSystem, layout)
		if err := os.WriteFile(files[0], []byte(singBox), 0644); err != nil {
			return err
		}
		return os.WriteFile(files[1], []byte(agent), 0644)
	}
	if initSystem == "openrc" && layout.Mode == "system" {
		singBox := fmt.Sprintf("#!/sbin/openrc-run\ncommand=%s\ncommand_args=\"run -c %s\"\ncommand_background=true\npidfile=/run/sing-box.pid\ndepend() { need net; }\n", layout.SingBoxPath, layout.RuntimeConfig)
		agent := fmt.Sprintf("#!/sbin/openrc-run\ncommand=%s\ncommand_args=\"run --config %s\"\ncommand_background=true\npidfile=/run/nodemanage-agent.pid\ndepend() { need net; after sing-box; }\n", layout.AgentPath, layout.AgentConfig)
		files := serviceFiles(initSystem, layout)
		if err := os.WriteFile(files[0], []byte(singBox), 0755); err != nil {
			return err
		}
		return os.WriteFile(files[1], []byte(agent), 0755)
	}
	return errors.New("unsupported init system")
}

func systemctl(mode string, args ...string) *exec.Cmd {
	if mode == "user" {
		args = append([]string{"--user"}, args...)
	}
	return exec.Command("systemctl", args...)
}

func userSystemdAvailable() bool {
	return systemctl("user", "show-environment").Run() == nil
}

func serviceControlAvailable(initSystem, mode string) bool {
	if initSystem == "systemd" {
		if mode == "user" {
			return userSystemdAvailable()
		}
		return os.Geteuid() == 0
	}
	return initSystem == "openrc" && mode == "system" && os.Geteuid() == 0
}

func enableServices(initSystem, mode string) error {
	if initSystem == "systemd" {
		if output, err := systemctl(mode, "daemon-reload").CombinedOutput(); err != nil {
			return fmt.Errorf("daemon-reload: %s", output)
		}
		if output, err := systemctl(mode, "enable", "--now", "sing-box.service", "nodemanage-agent.service").CombinedOutput(); err != nil {
			return fmt.Errorf("enable services: %s", output)
		}
		return nil
	}
	if initSystem == "openrc" && mode == "system" {
		for _, name := range []string{"sing-box", "nodemanage-agent"} {
			_ = exec.Command("rc-update", "add", name, "default").Run()
			if output, err := exec.Command("rc-service", name, "restart").CombinedOutput(); err != nil {
				return fmt.Errorf("start %s: %s", name, output)
			}
		}
		return nil
	}
	return errors.New("unsupported init system")
}

func disableServices(initSystem, mode string) {
	if initSystem == "systemd" {
		_ = systemctl(mode, "disable", "--now", "nodemanage-agent.service", "sing-box.service").Run()
		_ = systemctl(mode, "daemon-reload").Run()
	}
	if initSystem == "openrc" && mode == "system" {
		for _, name := range []string{"nodemanage-agent", "sing-box"} {
			_ = exec.Command("rc-service", name, "stop").Run()
			_ = exec.Command("rc-update", "del", name, "default").Run()
		}
	}
}

func serviceActive(initSystem, mode, name string) bool {
	if initSystem == "systemd" {
		return systemctl(mode, "is-active", "--quiet", name+".service").Run() == nil
	}
	if initSystem == "openrc" && mode == "system" {
		return commandOK("rc-service", name, "status")
	}
	return false
}

func restartService(initSystem, mode, name string) error {
	if initSystem == "systemd" {
		return systemctl(mode, "restart", name+".service").Run()
	}
	if initSystem == "openrc" && mode == "system" {
		return exec.Command("rc-service", name, "restart").Run()
	}
	return errors.New("unsupported init system")
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }
