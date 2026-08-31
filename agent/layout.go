package main

import (
	"errors"
	"os"
	"path/filepath"
)

type installLayout struct {
	Mode            string
	BinDir          string
	AgentPath       string
	SingBoxPath     string
	CloudflaredPath string
	AgentConfig     string
	RuntimeDir      string
	RuntimeConfig   string
	StateRoot       string
	ReleasesRoot    string
	BackupRoot      string
	ClaimPath       string
	LogPath         string
	ServiceDir      string
}

func resolveInstallMode(requested string) (string, error) {
	if requested == "" || requested == "auto" {
		if os.Geteuid() == 0 {
			return "system", nil
		}
		return "user", nil
	}
	if requested != "system" && requested != "user" {
		return "", errors.New("mode must be auto, system or user")
	}
	if requested == "system" && os.Geteuid() != 0 {
		return "", errors.New("system mode requires root; use --mode user or sudo")
	}
	if requested == "user" && os.Geteuid() == 0 {
		return "", errors.New("user mode must run as the target non-root user, without sudo")
	}
	return requested, nil
}

func absoluteEnv(name, fallback string) string {
	if value := os.Getenv(name); filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return fallback
}

func layoutForMode(mode string) (installLayout, error) {
	if mode == "system" {
		return installLayout{
			Mode: "system", BinDir: "/usr/local/bin", AgentPath: "/usr/local/bin/nodemanage-agent", SingBoxPath: "/usr/local/bin/sing-box", CloudflaredPath: "/usr/local/bin/cloudflared",
			AgentConfig: "/etc/nodemanage/agent.json", RuntimeDir: "/etc/sing-box", RuntimeConfig: "/etc/sing-box/config.json",
			StateRoot: "/etc/nodemanage", ReleasesRoot: "/etc/nodemanage/releases", BackupRoot: "/usr/local/lib/nodemanage/backups",
			ClaimPath: "/etc/nodemanage/install-claim", LogPath: "/var/log/nodemanage-install.log", ServiceDir: "/etc/systemd/system",
		}, nil
	}
	if mode != "user" {
		return installLayout{}, errors.New("unsupported install mode")
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return installLayout{}, errors.New("cannot determine an absolute user home directory")
	}
	configHome := absoluteEnv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	stateHome := absoluteEnv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	binDir := filepath.Join(home, ".local", "bin")
	configRoot := filepath.Join(configHome, "nodemanage")
	stateRoot := filepath.Join(stateHome, "nodemanage")
	runtimeDir := filepath.Join(configRoot, "sing-box")
	return installLayout{
		Mode: "user", BinDir: binDir, AgentPath: filepath.Join(binDir, "nodemanage-agent"), SingBoxPath: filepath.Join(binDir, "sing-box"), CloudflaredPath: filepath.Join(binDir, "cloudflared"),
		AgentConfig: filepath.Join(configRoot, "agent.json"), RuntimeDir: runtimeDir, RuntimeConfig: filepath.Join(runtimeDir, "config.json"),
		StateRoot: stateRoot, ReleasesRoot: filepath.Join(stateRoot, "releases"), BackupRoot: filepath.Join(stateRoot, "backups"),
		ClaimPath: filepath.Join(stateRoot, "install-claim"), LogPath: filepath.Join(stateRoot, "install.log"), ServiceDir: filepath.Join(configHome, "systemd", "user"),
	}, nil
}

func defaultLayout() installLayout {
	mode := "user"
	if os.Geteuid() == 0 {
		mode = "system"
	}
	layout, _ := layoutForMode(mode)
	return layout
}

func layoutFromConfig(cfg config) (installLayout, error) {
	layout, err := layoutForMode(cfg.InstallMode)
	if err != nil {
		return installLayout{}, err
	}
	if cfg.SingBoxPath != "" {
		layout.SingBoxPath = cfg.SingBoxPath
	}
	if cfg.CloudflaredPath != "" {
		layout.CloudflaredPath = cfg.CloudflaredPath
	}
	if cfg.RuntimePath != "" {
		layout.RuntimeConfig = cfg.RuntimePath
		layout.RuntimeDir = filepath.Dir(cfg.RuntimePath)
	}
	if cfg.StatePath != "" {
		layout.StateRoot = cfg.StatePath
		layout.ReleasesRoot = filepath.Join(cfg.StatePath, "releases")
		layout.BackupRoot = filepath.Join(cfg.StatePath, "backups")
		layout.ClaimPath = filepath.Join(cfg.StatePath, "install-claim")
		layout.LogPath = filepath.Join(cfg.StatePath, "install.log")
	}
	return layout, nil
}
