package caddydnsjoker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
)

// TestJoker tests the DNS provider for Joker API
func TestJoker(t *testing.T) {
	// Mock Joker API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		username := r.URL.Query().Get("username")
		password := r.URL.Query().Get("password")
		if username != "user" || password != "pass" {
			t.Errorf("unexpected credentials: %s / %s", username, password)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	// Create the provider
	provider := &Provider{
		Username: "user",
		Password: "pass",
	}

	// Define a concrete implementation of libdns.Record (use libdns.RR)
	records := []libdns.Record{
		&libdns.RR{
			Name:  "test.example.com",
			Type:  "TXT",
			Data:  "testing123",
			TTL:   time.Minute,
		},
	}

	// Test AppendRecords
	t.Run("AppendRecords", func(t *testing.T) {
		got, err := provider.AppendRecords(context.Background(), "example.com", records)
		assert.Nil(t, err)
		assert.Equal(t, len(records), len(got))
	})

	// Test DeleteRecords
	t.Run("DeleteRecords", func(t *testing.T) {
		deleted, err := provider.DeleteRecords(context.Background(), "example.com", records)
		assert.Nil(t, err)
		assert.Equal(t, len(records), len(deleted))
	})
}
