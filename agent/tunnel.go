package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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
		a.stopTunnelRouter()
		stopTunnel(a.config)
		return nil
	}
	if err := a.ensureTunnelRouter(); err != nil {
		return err
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

func (a *agent) ensureTunnelRouter() error {
	if a.tunnelRouter != nil {
		return nil
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", a.config.TunnelOriginPort))
	if err != nil {
		return fmt.Errorf("start tunnel WebSocket router: %w", err)
	}
	a.tunnelRouter = listener
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		routes := websocketRoutes(a.config.RuntimePath)
		port, ok := routes[request.URL.Path]
		if !ok {
			http.NotFound(response, request)
			return
		}
		target := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", port)}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, proxyErr error) {
			fmt.Fprintf(os.Stderr, "tunnel router: %v\n", proxyErr)
			http.Error(writer, "Tunnel protocol unavailable", http.StatusBadGateway)
		}
		proxy.ServeHTTP(response, request)
	})}
	go func() { _ = server.Serve(listener) }()
	return nil
}

func (a *agent) stopTunnelRouter() {
	if a.tunnelRouter != nil {
		_ = a.tunnelRouter.Close()
		a.tunnelRouter = nil
	}
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

func websocketRoutes(runtimePath string) map[string]int {
	data, err := os.ReadFile(runtimePath)
	if err != nil {
		return nil
	}
	var doc struct {
		Inbounds []struct {
			ListenPort int `json:"listen_port"`
			Transport  struct {
				Type string `json:"type"`
				Path string `json:"path"`
			} `json:"transport"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	routes := make(map[string]int)
	for _, in := range doc.Inbounds {
		if in.ListenPort > 0 && in.Transport.Type == "ws" && strings.HasPrefix(in.Transport.Path, "/") {
			routes[in.Transport.Path] = in.ListenPort
		}
	}
	return routes
}

func websocketPaths(runtimePath string) []string {
	paths := make([]string, 0)
	for path := range websocketRoutes(runtimePath) {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func validTunnelConnectPort(kind string, port int) bool {
	if kind == "quick" {
		return port == 443
	}
	if kind != "named" {
		return false
	}
	for _, allowed := range []int{443, 2053, 2083, 2087, 2096, 8443} {
		if port == allowed {
			return true
		}
	}
	return false
}

func probeTunnel(client *http.Client, hostname string, port int, path string) error {
	endpointHost := hostname
	if port != 443 {
		endpointHost = fmt.Sprintf("%s:%d", hostname, port)
	}
	if _, err := url.ParseRequestURI("https://" + endpointHost + path); err != nil {
		return fmt.Errorf("invalid tunnel endpoint: %w", err)
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+endpointHost+path, nil)
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
