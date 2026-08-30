package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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
