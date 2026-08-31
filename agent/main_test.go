package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte("ID=alpine\nVERSION_ID=\"3.21\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	values := parseOSRelease(path)
	if values["ID"] != "alpine" || values["VERSION_ID"] != "3.21" {
		t.Fatalf("unexpected os-release: %#v", values)
	}
}

func TestUserLayoutUsesXDGDirectories(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	layout, err := layoutForMode("user")
	if err != nil {
		t.Fatal(err)
	}
	if layout.AgentPath != filepath.Join(home, ".local", "bin", "nodemanage-agent") {
		t.Fatalf("agent path = %q", layout.AgentPath)
	}
	if layout.AgentConfig != filepath.Join(home, "cfg", "nodemanage", "agent.json") {
		t.Fatalf("config path = %q", layout.AgentConfig)
	}
	if layout.ReleasesRoot != filepath.Join(home, "state", "nodemanage", "releases") {
		t.Fatalf("releases path = %q", layout.ReleasesRoot)
	}
}

func TestUserSystemdUnitsAreUnprivileged(t *testing.T) {
	root := t.TempDir()
	layout := installLayout{Mode: "user", AgentPath: filepath.Join(root, "bin", "nodemanage-agent"), SingBoxPath: filepath.Join(root, "bin", "sing-box"), AgentConfig: filepath.Join(root, "agent-config.json"), RuntimeConfig: filepath.Join(root, "config.json"), ServiceDir: filepath.Join(root, "systemd")}
	if err := writeServices("systemd", layout); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(layout.ServiceDir, "sing-box.service"))
	if err != nil {
		t.Fatal(err)
	}
	unit := string(data)
	if strings.Contains(unit, "CAP_NET_BIND_SERVICE") {
		t.Fatal("user service must not request privileged capabilities")
	}
	if !strings.Contains(unit, "WantedBy=default.target") || !strings.Contains(unit, "sing-box") {
		t.Fatalf("unexpected user unit:\n%s", unit)
	}
	agentUnit, err := os.ReadFile(filepath.Join(layout.ServiceDir, "nodemanage-agent.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(agentUnit), "--config") || !strings.Contains(string(agentUnit), "config.json") {
		t.Fatalf("Agent unit does not pin its configuration path:\n%s", agentUnit)
	}
}

func TestUserConfigRejectsPrivilegedPorts(t *testing.T) {
	if err := validateUserPorts([]byte(`{"inbounds":[{"listen_port":443}]}`)); err == nil {
		t.Fatal("expected privileged port rejection")
	}
	if err := validateUserPorts([]byte(`{"inbounds":[{"listen_port":8443}]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestStandaloneProcessLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("standalone process control is Linux-only")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	layout, err := layoutForMode("user")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.BinDir, 0700); err != nil {
		t.Fatal(err)
	}
	program := []byte("#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n")
	for _, path := range []string{layout.AgentPath, layout.SingBoxPath} {
		if err := os.WriteFile(path, program, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := restartStandalone("user", "sing-box"); err != nil {
		t.Fatal(err)
	}
	defer stopStandalone("user", "sing-box")
	if !standaloneActive("user", "sing-box") {
		t.Fatal("standalone sing-box process is not active")
	}
	if err := stopStandalone("user", "sing-box"); err != nil {
		t.Fatal(err)
	}
	if standaloneActive("user", "sing-box") {
		t.Fatal("standalone sing-box process remained active")
	}
}

func TestDownloadVerified(t *testing.T) {
	payload := []byte("verified agent")
	digest := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { _, _ = response.Write(payload) }))
	defer server.Close()
	destination := filepath.Join(t.TempDir(), "agent")
	if err := downloadVerified(server.Client(), server.URL, destination, hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(destination); err != nil || string(data) != string(payload) {
		t.Fatalf("downloaded data = %q, error = %v", data, err)
	}
}

func TestDownloadVerifiedSourcesFallsBack(t *testing.T) {
	payload := []byte("mirror payload")
	digest := sha256.Sum256(payload)
	failed := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "blocked", http.StatusBadGateway)
	}))
	defer failed.Close()
	working := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { _, _ = response.Write(payload) }))
	defer working.Close()
	destination := filepath.Join(t.TempDir(), "artifact")
	source, err := downloadVerifiedSources(working.Client(), []string{failed.URL, working.URL}, destination, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	if source != working.URL {
		t.Fatalf("source = %q, want %q", source, working.URL)
	}
}

func TestSupportedDistributionParsing(t *testing.T) {
	cases := map[string]string{"debian": "ID=debian\n", "ubuntu": "ID=ubuntu\n", "rocky": "ID=rocky\n", "alpine": "ID=alpine\n"}
	for expected, contents := range cases {
		t.Run(expected, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "os-release")
			if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			if got := parseOSRelease(path)["ID"]; got != expected {
				t.Fatalf("ID = %q, want %q", got, expected)
			}
		})
	}
}

func TestReadRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.revision")
	if got := readRevision(path); got != nil {
		t.Fatalf("missing revision = %v, want nil", *got)
	}
	if err := os.WriteFile(path, []byte("42\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got := readRevision(path)
	if got == nil || *got != 42 {
		t.Fatalf("revision = %v, want 42", got)
	}
}

func TestQuickTunnelHostnameUsesLatestLogEntry(t *testing.T) {
	state := t.TempDir()
	cfg := config{StatePath: state}
	log := "INF Your quick Tunnel has been created! Visit it at https://first.trycloudflare.com\nINF https://latest-name.trycloudflare.com\n"
	if err := os.WriteFile(tunnelLogPath(cfg), []byte(log), 0600); err != nil {
		t.Fatal(err)
	}
	if got := quickTunnelHostname(cfg); got != "latest-name.trycloudflare.com" {
		t.Fatalf("hostname = %q", got)
	}
}

func TestWebsocketRoutesReadEveryActiveInbound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"inbounds":[{"listen_port":18081,"transport":{"type":"ws","path":"/vless"}},{"listen_port":18082,"transport":{"type":"ws","path":"/trojan"}}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	routes := websocketRoutes(path)
	if routes["/vless"] != 18081 || routes["/trojan"] != 18082 {
		t.Fatalf("routes = %#v", routes)
	}
	paths := websocketPaths(path)
	if len(paths) != 2 || paths[0] != "/trojan" || paths[1] != "/vless" {
		t.Fatalf("paths = %#v", paths)
	}
}

func TestTunnelRouterForwardsByWebsocketPath(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write([]byte("forwarded:" + request.URL.Path))
	}))
	defer backend.Close()
	_, backendPortText, err := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	backendPort, _ := strconv.Atoi(backendPortText)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	routerPort := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	runtimePath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(runtimePath, []byte(fmt.Sprintf(`{"inbounds":[{"listen_port":%d,"transport":{"type":"ws","path":"/vless"}}]}`, backendPort)), 0600); err != nil {
		t.Fatal(err)
	}
	a := &agent{config: config{RuntimePath: runtimePath, TunnelOriginPort: routerPort}}
	if err := a.ensureTunnelRouter(); err != nil {
		t.Fatal(err)
	}
	defer a.stopTunnelRouter()
	response, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/vless", routerPort))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "forwarded:/vless" {
		t.Fatalf("body = %q", body)
	}
}

func TestTunnelConnectPorts(t *testing.T) {
	if !validTunnelConnectPort("quick", 443) || validTunnelConnectPort("quick", 8443) {
		t.Fatal("Quick Tunnel must only allow port 443")
	}
	for _, port := range []int{443, 2053, 2083, 2087, 2096, 8443} {
		if !validTunnelConnectPort("named", port) {
			t.Fatalf("Named Tunnel port %d should be supported", port)
		}
	}
	if validTunnelConnectPort("named", 9443) {
		t.Fatal("undocumented Named Tunnel port must be rejected")
	}
}

func TestResetReleaseLayoutReplacesStaleConfiguration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink lifecycle is verified on Linux")
	}
	root := t.TempDir()
	runtimePath := filepath.Join(root, "runtime", "config.json")
	releasesRoot := filepath.Join(root, "state", "releases")
	stale := filepath.Join(releasesRoot, "r2")
	if err := os.MkdirAll(stale, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "config.json"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(runtimePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(stale, "config.json"), runtimePath); err != nil {
		t.Fatal(err)
	}
	if err := resetReleaseLayout(runtimePath, releasesRoot); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != minimalRuntimeConfig {
		t.Fatalf("runtime config = %q", data)
	}
}

func TestPostJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer token" {
			t.Error("missing bearer token")
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	var output struct {
		OK bool `json:"ok"`
	}
	if err := postJSON(server.Client(), server.URL, "token", map[string]string{"hello": "world"}, &output); err != nil {
		t.Fatal(err)
	}
	if !output.OK {
		t.Fatal("response was not decoded")
	}
}
