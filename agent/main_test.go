package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

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
