package api

import (
	"testing"

	"github.com/go-gost/x/config"
	"github.com/stretchr/testify/require"
)

func TestUpdateQuotaConfigSkipsNilEntries(t *testing.T) {
	first := &config.QuotaConfig{Name: "first"}
	updated := &config.QuotaConfig{Name: "target"}
	cfg := &config.Config{Quotas: []*config.QuotaConfig{nil, first, nil}}

	updateQuotaConfig(cfg, "first", updated)
	require.Same(t, updated, cfg.Quotas[1])
	require.Nil(t, cfg.Quotas[0])
	require.Nil(t, cfg.Quotas[2])
}
