package main

import (
	"archive/tar"
	"compress/gzip"
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
	client *http.Client
	server string
	ticket string
	token  string
}

func (reporter installReporter) report(stage, errorCode, message, source string) {
	if reporter.ticket != "" {
		message = strings.ReplaceAll(message, reporter.ticket, "[redacted]")
	}
	if reporter.token != "" {
		message = strings.ReplaceAll(message, reporter.token, "[redacted]")
	}
	line := fmt.Sprintf("%s stage=%s code=%s source=%s message=%s\n", time.Now().UTC().Format(time.RFC3339), stage, errorCode, source, message)
	if file, err := os.OpenFile("/var/log/nodemanage-install.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
		_, _ = file.WriteString(line)
		_ = file.Close()
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
	manifestURL := flags.String("manifest", "", "release manifest URL")
	configPath := flags.String("config", defaultConfigPath, "agent configuration path")
	_ = flags.Parse(args)
	client := &http.Client{Timeout: 90 * time.Second}
	reporter := installReporter{client: &http.Client{Timeout: 5 * time.Second}, server: strings.TrimRight(*server, "/"), ticket: *ticket}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		reporter.report("failed", "NM-E201", "install requires root on Linux", "local")
		fatal("[NM-E201] install requires root on Linux")
	}
	if *server == "" || *ticket == "" || *name == "" {
		fatal("[NM-E202] --server, --ticket and --name are required")
	}
	if *manifestURL == "" {
		*manifestURL = strings.TrimRight(*server, "/") + "/api/install/manifest?os=linux&arch=" + runtime.GOARCH
	}
	platform := detectPlatform()
	if platform.InitSystem != "systemd" && platform.InitSystem != "openrc" {
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
		func() error { return os.MkdirAll("/usr/local/bin", 0755) },
		func() error { return installExecutable(agentFile, "/usr/local/bin/nodemanage-agent") },
		func() error { return installExecutable(singBoxFile, "/usr/local/bin/sing-box") },
		func() error { return os.MkdirAll("/etc/sing-box", 0755) },
	} {
		if err := operation(); err != nil {
			reporter.report("failed", "NM-E210", err.Error(), "local")
			fatal("[NM-E210] install runtime: " + err.Error())
		}
	}
	if _, err := os.Stat("/etc/sing-box/config.json"); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile("/etc/sing-box/config.json", []byte(minimalRuntimeConfig), 0600); err != nil {
			reporter.report("failed", "NM-E210", err.Error(), "local")
			fatal("[NM-E210] write runtime config: " + err.Error())
		}
	}
	if err := repairReleaseLayout("/etc/sing-box/config.json"); err != nil {
		reporter.report("failed", "NM-E210", err.Error(), "local")
		fatal("[NM-E210] prepare A/B configuration: " + err.Error())
	}
	reporter.report("runtime_installed", "", "Agent and sing-box installed atomically", "local")
	if _, err := os.Stat(*configPath); errors.Is(err, os.ErrNotExist) {
		if err := registerTicket(client, strings.TrimRight(*server, "/"), *ticket, *name, *configPath, platform); err != nil {
			reporter.report("failed", "NM-E205", err.Error(), sourceHost(*server))
			fatal(err.Error())
		}
	}
	if err := writeServices(platform.InitSystem); err != nil {
		reporter.report("failed", "NM-E213", err.Error(), "local")
		fatal("[NM-E213] install services: " + err.Error())
	}
	reporter.report("service_installed", "", platform.InitSystem+" service definitions installed", "local")
	if err := enableServices(platform.InitSystem); err != nil {
		reporter.report("failed", "NM-E214", err.Error(), "local")
		fatal("[NM-E214] start services: " + err.Error())
	}
	fmt.Printf("NodeManage installed successfully (%s/%s, %s)\n", runtime.GOOS, runtime.GOARCH, platform.InitSystem)
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
	configPath := flags.String("config", defaultConfigPath, "agent configuration path")
	manifestURL := flags.String("manifest", "", "release manifest URL")
	_ = flags.Parse(args)
	if os.Geteuid() != 0 {
		fatal("[NM-E211] repair requires root")
	}
	data, err := os.ReadFile(*configPath)
	if err != nil {
		fatal("[NM-E212] Agent credentials are missing; generate a new install ticket: " + err.Error())
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil || cfg.ServerURL == "" || cfg.AgentToken == "" {
		fatal("[NM-E212] Agent configuration is invalid; generate a new install ticket")
	}
	client := &http.Client{Timeout: 90 * time.Second}
	reporter := installReporter{client: &http.Client{Timeout: 5 * time.Second}, server: cfg.ServerURL, token: cfg.AgentToken}
	platform := detectPlatform()
	if platform.InitSystem != "systemd" && platform.InitSystem != "openrc" {
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
	if commandOutput("/usr/local/bin/nodemanage-agent", "version") != manifest.Agent.Version {
		download := filepath.Join(temporary, "nodemanage-agent")
		if _, err := downloadVerifiedSources(client, manifest.Agent.URLs, download, manifest.Agent.SHA256); err != nil {
			reporter.report("failed", "NM-E208", err.Error(), "all-sources")
			fatal(err.Error())
		}
		if err := os.MkdirAll("/usr/local/bin", 0755); err != nil {
			fatal("[NM-E210] " + err.Error())
		}
		if err := installExecutable(download, "/usr/local/bin/nodemanage-agent"); err != nil {
			reporter.report("failed", "NM-E210", err.Error(), "local")
			fatal("[NM-E210] " + err.Error())
		}
	}
	if !strings.Contains(commandOutput("/usr/local/bin/sing-box", "version"), manifest.SingBox.Version) {
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
		if err := os.MkdirAll("/usr/local/bin", 0755); err != nil {
			fatal("[NM-E210] " + err.Error())
		}
		if err := installExecutable(binary, "/usr/local/bin/sing-box"); err != nil {
			reporter.report("failed", "NM-E210", err.Error(), "local")
			fatal("[NM-E210] " + err.Error())
		}
	}
	if err := os.MkdirAll("/etc/sing-box", 0755); err != nil {
		fatal("[NM-E210] " + err.Error())
	}
	if err := repairReleaseLayout("/etc/sing-box/config.json"); err != nil {
		reporter.report("failed", "NM-E210", err.Error(), "local")
		fatal("[NM-E210] repair A/B configuration: " + err.Error())
	}
	if err := writeServices(platform.InitSystem); err != nil {
		reporter.report("failed", "NM-E213", err.Error(), "local")
		fatal("[NM-E213] " + err.Error())
	}
	if err := enableServices(platform.InitSystem); err != nil {
		reporter.report("failed", "NM-E214", err.Error(), "local")
		fatal("[NM-E214] " + err.Error())
	}
	reporter.report("service_installed", "", "Binaries, configuration and services repaired", "local")
	fmt.Println("NodeManage services repaired successfully")
}

func repairReleaseLayout(runtimePath string) error {
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
	return ensureReleaseLayout(runtimePath)
}

func upgradeCommand(args []string) {
	flags := flag.NewFlagSet("upgrade", flag.ExitOnError)
	configPath := flags.String("config", defaultConfigPath, "agent configuration path")
	manifestURL := flags.String("manifest", "", "release manifest URL")
	_ = flags.Parse(args)
	if os.Geteuid() != 0 {
		fatal("[NM-E231] upgrade requires root")
	}
	data, err := os.ReadFile(*configPath)
	if err != nil {
		fatal("[NM-E232] read Agent configuration: " + err.Error())
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil || cfg.ServerURL == "" || cfg.AgentToken == "" {
		fatal("[NM-E232] invalid Agent configuration")
	}
	if *manifestURL == "" {
		*manifestURL = strings.TrimRight(cfg.ServerURL, "/") + "/api/install/manifest?os=linux&arch=" + runtime.GOARCH
	}
	client := &http.Client{Timeout: 90 * time.Second}
	reporter := installReporter{client: &http.Client{Timeout: 5 * time.Second}, server: cfg.ServerURL, token: cfg.AgentToken}
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
	backupRoot := "/usr/local/lib/nodemanage/backups"
	if err := os.MkdirAll(backupRoot, 0700); err != nil {
		fatal("[NM-E233] " + err.Error())
	}
	agentBackup := filepath.Join(backupRoot, "nodemanage-agent.previous")
	singBoxBackup := filepath.Join(backupRoot, "sing-box.previous")
	agentChanged, runtimeChanged := false, false

	if commandOutput("/usr/local/bin/nodemanage-agent", "version") != manifest.Agent.Version {
		download := filepath.Join(temporary, "nodemanage-agent")
		if _, err := downloadVerifiedSources(client, manifest.Agent.URLs, download, manifest.Agent.SHA256); err != nil {
			reporter.report("failed", "NM-E208", err.Error(), "all-sources")
			fatal(err.Error())
		}
		if err := copyExecutable("/usr/local/bin/nodemanage-agent", agentBackup); err != nil {
			fatal("[NM-E233] backup Agent: " + err.Error())
		}
		if err := installExecutable(download, "/usr/local/bin/nodemanage-agent"); err != nil {
			fatal("[NM-E233] install Agent: " + err.Error())
		}
		if commandOutput("/usr/local/bin/nodemanage-agent", "version") != manifest.Agent.Version {
			_ = installExecutable(agentBackup, "/usr/local/bin/nodemanage-agent")
			reporter.report("failed", "NM-E234", "new Agent failed version check", "local")
			fatal("[NM-E234] new Agent failed version check")
		}
		agentChanged = true
	}
	if !strings.Contains(commandOutput("/usr/local/bin/sing-box", "version"), manifest.SingBox.Version) {
		archive := filepath.Join(temporary, "sing-box.tar.gz")
		binary := filepath.Join(temporary, "sing-box")
		if _, err := downloadVerifiedSources(client, manifest.SingBox.URLs, archive, manifest.SingBox.SHA256); err != nil {
			rollbackExecutables(agentChanged, false, agentBackup, singBoxBackup)
			reporter.report("failed", "NM-E208", err.Error(), "all-sources")
			fatal(err.Error())
		}
		if err := extractTarFile(archive, strings.Trim(manifest.SingBox.ArchiveRoot, "/")+"/sing-box", binary); err != nil {
			rollbackExecutables(agentChanged, false, agentBackup, singBoxBackup)
			fatal("[NM-E209] " + err.Error())
		}
		if err := copyExecutable("/usr/local/bin/sing-box", singBoxBackup); err != nil {
			rollbackExecutables(agentChanged, false, agentBackup, singBoxBackup)
			fatal("[NM-E233] backup sing-box: " + err.Error())
		}
		if err := installExecutable(binary, "/usr/local/bin/sing-box"); err != nil {
			rollbackExecutables(agentChanged, false, agentBackup, singBoxBackup)
			fatal("[NM-E233] install sing-box: " + err.Error())
		}
		if !strings.Contains(commandOutput("/usr/local/bin/sing-box", "version"), manifest.SingBox.Version) {
			rollbackExecutables(agentChanged, true, agentBackup, singBoxBackup)
			reporter.report("failed", "NM-E234", "new sing-box failed version check", "local")
			fatal("[NM-E234] new sing-box failed version check")
		}
		runtimeChanged = true
	}
	if runtimeChanged {
		if err := restartService(cfg.InitSystem, "sing-box"); err != nil {
			rollbackExecutables(agentChanged, true, agentBackup, singBoxBackup)
			_ = restartService(cfg.InitSystem, "sing-box")
			reporter.report("failed", "NM-E235", err.Error(), "local")
			fatal("[NM-E235] restart sing-box: " + err.Error())
		}
		time.Sleep(time.Second)
		if !serviceActive(cfg.InitSystem, "sing-box") {
			rollbackExecutables(agentChanged, true, agentBackup, singBoxBackup)
			_ = restartService(cfg.InitSystem, "sing-box")
			reporter.report("failed", "NM-E235", "sing-box is inactive after upgrade", "local")
			fatal("[NM-E235] sing-box is inactive after upgrade")
		}
	}
	if agentChanged {
		if err := restartService(cfg.InitSystem, "nodemanage-agent"); err != nil {
			rollbackExecutables(true, runtimeChanged, agentBackup, singBoxBackup)
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

func rollbackExecutables(agentChanged, runtimeChanged bool, agentBackup, singBoxBackup string) {
	if agentChanged {
		_ = installExecutable(agentBackup, "/usr/local/bin/nodemanage-agent")
	}
	if runtimeChanged {
		_ = installExecutable(singBoxBackup, "/usr/local/bin/sing-box")
	}
}

func diagnoseCommand() {
	platform := detectPlatform()
	result := map[string]any{"platform": platform, "is_root": os.Geteuid() == 0,
		"agent_installed":    commandOK("/usr/local/bin/nodemanage-agent", "version"),
		"sing_box_installed": commandOK("/usr/local/bin/sing-box", "version"),
		"agent_config":       fileExists(defaultConfigPath), "runtime_config": fileExists("/etc/sing-box/config.json"),
		"agent_running": serviceActive(platform.InitSystem, "nodemanage-agent"), "sing_box_running": serviceActive(platform.InitSystem, "sing-box")}
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(data))
}

func uninstallCommand(args []string) {
	flags := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := flags.Bool("purge", false, "also delete configurations")
	_ = flags.Parse(args)
	if os.Geteuid() != 0 {
		fatal("[NM-E221] uninstall requires root")
	}
	platform := detectPlatform()
	disableServices(platform.InitSystem)
	for _, path := range serviceFiles(platform.InitSystem) {
		_ = os.Remove(path)
	}
	_ = os.Remove("/usr/local/bin/nodemanage-agent")
	_ = os.Remove("/usr/local/bin/sing-box")
	if *purge {
		_ = os.RemoveAll("/etc/nodemanage")
		_ = os.RemoveAll("/etc/sing-box")
	}
	fmt.Println("NodeManage uninstalled; configuration retained unless --purge was used")
}

func registerTicket(client *http.Client, server, ticket, name, configPath string, platform platformInfo) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	body := map[string]string{"ticket": ticket, "name": name, "hostname": hostname, "architecture": runtime.GOARCH, "os": runtime.GOOS,
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
		SingBoxPath: "/usr/local/bin/sing-box", ServiceName: "sing-box", RuntimePath: "/etc/sing-box/config.json", InitSystem: platform.InitSystem, InstallMode: platform.InstallMode}
	if cfg.PollSeconds < 15 {
		cfg.PollSeconds = 60
	}
	return writeJSONAtomic(configPath, cfg, 0600)
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

func serviceFiles(initSystem string) []string {
	if initSystem == "systemd" {
		return []string{"/etc/systemd/system/sing-box.service", "/etc/systemd/system/nodemanage-agent.service"}
	}
	if initSystem == "openrc" {
		return []string{"/etc/init.d/sing-box", "/etc/init.d/nodemanage-agent"}
	}
	return nil
}

func writeServices(initSystem string) error {
	if initSystem == "systemd" {
		singBox := `[Unit]\nDescription=sing-box proxy service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json\nRestart=on-failure\nRestartSec=5s\nLimitNOFILE=1048576\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nNoNewPrivileges=true\n\n[Install]\nWantedBy=multi-user.target\n`
		agent := `[Unit]\nDescription=NodeManage Agent\nAfter=network-online.target sing-box.service\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/nodemanage-agent run\nRestart=always\nRestartSec=10s\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n`
		if err := os.WriteFile(serviceFiles(initSystem)[0], []byte(singBox), 0644); err != nil {
			return err
		}
		return os.WriteFile(serviceFiles(initSystem)[1], []byte(agent), 0644)
	}
	if initSystem == "openrc" {
		singBox := "#!/sbin/openrc-run\ncommand=/usr/local/bin/sing-box\ncommand_args=\"run -c /etc/sing-box/config.json\"\ncommand_background=true\npidfile=/run/sing-box.pid\ndepend() { need net; }\n"
		agent := "#!/sbin/openrc-run\ncommand=/usr/local/bin/nodemanage-agent\ncommand_args=run\ncommand_background=true\npidfile=/run/nodemanage-agent.pid\ndepend() { need net; after sing-box; }\n"
		if err := os.WriteFile(serviceFiles(initSystem)[0], []byte(singBox), 0755); err != nil {
			return err
		}
		return os.WriteFile(serviceFiles(initSystem)[1], []byte(agent), 0755)
	}
	return errors.New("unsupported init system")
}

func enableServices(initSystem string) error {
	if initSystem == "systemd" {
		if output, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
			return fmt.Errorf("daemon-reload: %s", output)
		}
		if output, err := exec.Command("systemctl", "enable", "--now", "sing-box.service", "nodemanage-agent.service").CombinedOutput(); err != nil {
			return fmt.Errorf("enable services: %s", output)
		}
		return nil
	}
	if initSystem == "openrc" {
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

func disableServices(initSystem string) {
	if initSystem == "systemd" {
		_ = exec.Command("systemctl", "disable", "--now", "nodemanage-agent.service", "sing-box.service").Run()
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
	if initSystem == "openrc" {
		for _, name := range []string{"nodemanage-agent", "sing-box"} {
			_ = exec.Command("rc-service", name, "stop").Run()
			_ = exec.Command("rc-update", "del", name, "default").Run()
		}
	}
}

func serviceActive(initSystem, name string) bool {
	if initSystem == "systemd" {
		return commandOK("systemctl", "is-active", "--quiet", name+".service")
	}
	if initSystem == "openrc" {
		return commandOK("rc-service", name, "status")
	}
	return false
}

func restartService(initSystem, name string) error {
	if initSystem == "systemd" {
		return exec.Command("systemctl", "restart", name+".service").Run()
	}
	if initSystem == "openrc" {
		return exec.Command("rc-service", name, "restart").Run()
	}
	return errors.New("unsupported init system")
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }
