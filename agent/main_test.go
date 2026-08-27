package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
