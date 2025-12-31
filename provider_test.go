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

func TestJokerProvider(t *testing.T) {
	var lastForm map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)

		err := r.ParseForm()
		assert.NoError(t, err)

		lastForm = map[string]string{
			"username": r.FormValue("username"),
			"password": r.FormValue("password"),
			"hostname": r.FormValue("hostname"),
			"type":     r.FormValue("type"),
			"address":  r.FormValue("address"),
			"ttl":      r.FormValue("ttl"),
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	provider := &Provider{
		Username: "user",
		Password: "pass",
		Endpoint: server.URL,
		client:   server.Client(),
	}

	record := &libdns.RR{
		Name: "test.example.com",
		Type: "TXT",
		Data: `"testing123"`,
		TTL:  time.Minute,
	}

	ctx := context.Background()

	t.Run("AppendRecords", func(t *testing.T) {
		_, err := provider.AppendRecords(ctx, "example.com", []libdns.Record{record})
		assert.NoError(t, err)

		assert.Equal(t, "user", lastForm["username"])
		assert.Equal(t, "pass", lastForm["password"])
		assert.Equal(t, "test.example.com", lastForm["hostname"])
		assert.Equal(t, "TXT", lastForm["type"])
		assert.Equal(t, "testing123", lastForm["address"]) // quotes stripped
		assert.Equal(t, "60", lastForm["ttl"])
	})

	t.Run("DeleteRecords", func(t *testing.T) {
		_, err := provider.DeleteRecords(ctx, "example.com", []libdns.Record{record})
		assert.NoError(t, err)

		assert.Equal(t, "", lastForm["address"])
	})
}
