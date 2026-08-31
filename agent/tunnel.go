package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var quickTunnelPattern = regexp.MustCompile(`https://([a-z0-9-]+\.trycloudflare\.com)`)

func tunnelPIDPath(cfg config) string { return filepath.Join(cfg.StatePath, "cloudflared.pid") }
func tunnelLogPath(cfg config) string { return filepath.Join(cfg.StatePath, "cloudflared.log") }

func tunnelActive(cfg config) bool {
	data, err := os.ReadFile(tunnelPIDPath(cfg))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || !processExists(pid) {
		return false
	}
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	return err == nil && strings.Contains(string(cmdline), cfg.CloudflaredPath)
}

func stopTunnel(cfg config) {
	data, err := os.ReadFile(tunnelPIDPath(cfg))
	if err == nil {
		if pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data))); parseErr == nil {
			_ = signalProcess(pid, false)
		}
	}
	_ = os.Remove(tunnelPIDPath(cfg))
}

func (a *agent) ensureTunnel() error {
	if a.config.IngressMode != "cloudflare_tunnel" {
		stopTunnel(a.config)
		return nil
	}
	if tunnelActive(a.config) {
		return nil
	}
	stopTunnel(a.config)
	if err := os.MkdirAll(a.config.StatePath, 0700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(tunnelLogPath(a.config), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	args := []string{"tunnel", "--no-autoupdate", "--protocol", "http2"}
	if a.config.TunnelKind == "quick" {
		args = append(args, "--url", fmt.Sprintf("http://127.0.0.1:%d", a.config.TunnelOriginPort))
	} else {
		args = append(args, "run", "--token", a.config.TunnelToken)
	}
	command := exec.Command(a.config.CloudflaredPath, args...)
	command.Stdout = logFile
	command.Stderr = logFile
	prepareDetached(command)
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start cloudflared: %w", err)
	}
	_ = logFile.Close()
	if err := os.WriteFile(tunnelPIDPath(a.config), []byte(strconv.Itoa(command.Process.Pid)+"\n"), 0600); err != nil {
		_ = signalProcess(command.Process.Pid, true)
		return err
	}
	_ = command.Process.Release()
	time.Sleep(500 * time.Millisecond)
	if !tunnelActive(a.config) {
		return errors.New("cloudflared exited during startup; inspect cloudflared.log")
	}
	return nil
}

func quickTunnelHostname(cfg config) string {
	file, err := os.Open(tunnelLogPath(cfg))
	if err != nil {
		return ""
	}
	defer file.Close()
	result := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if match := quickTunnelPattern.FindStringSubmatch(scanner.Text()); len(match) == 2 {
			result = match[1]
		}
	}
	return result
}

func websocketPath(runtimePath string) string {
	data, err := os.ReadFile(runtimePath)
	if err != nil {
		return "/"
	}
	var doc struct {
		Inbounds []struct {
			Transport struct {
				Type string `json:"type"`
				Path string `json:"path"`
			} `json:"transport"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return "/"
	}
	for _, in := range doc.Inbounds {
		if in.Transport.Type == "ws" && strings.HasPrefix(in.Transport.Path, "/") {
			return in.Transport.Path
		}
	}
	return "/"
}

func probeTunnel(client *http.Client, hostname, path string) error {
	if _, err := url.ParseRequestURI("https://" + hostname + path); err != nil {
		return fmt.Errorf("invalid tunnel endpoint: %w", err)
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+hostname+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(key))
	probeClient := *client
	probeClient.Timeout = 10 * time.Second
	resp, err := probeClient.Do(req)
	if err != nil {
		return fmt.Errorf("public WebSocket probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("public WebSocket probe returned %s", resp.Status)
	}
	return nil
}
