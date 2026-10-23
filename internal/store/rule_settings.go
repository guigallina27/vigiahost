package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
)

// Chaves da tabela settings usadas pela configuração de regras e motores opcionais.
const (
	settingLMDEnabled      = "engines.lmd.enabled"
	settingDisabledSources = "rules.disabled_sources"
)

func (d *DB) ruleSetting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := d.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (d *DB) saveRuleSetting(ctx context.Context, key, value string) error {
	_, err := d.ExecContext(ctx, `INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, key, value, ts(d.now()))
	return err
}

// LMDEnabled diz se o administrador ligou o LMD como fonte adicional de assinaturas (desligado por padrão).
func (d *DB) LMDEnabled(ctx context.Context) (bool, error) {
	v, ok, err := d.ruleSetting(ctx, settingLMDEnabled)
	if err != nil || !ok {
		return false, err
	}
	return v == "true", nil
}

// SetLMDEnabled grava a escolha do administrador.
func (d *DB) SetLMDEnabled(ctx context.Context, on bool) error {
	v := "false"
	if on {
		v = "true"
	}
	return d.saveRuleSetting(ctx, settingLMDEnabled, v)
}

// DisabledRuleSources devolve as fontes de regras YARA desativadas, em ordem alfabética.
func (d *DB) DisabledRuleSources(ctx context.Context) ([]string, error) {
	v, ok, err := d.ruleSetting(ctx, settingDisabledSources)
	if err != nil || !ok {
		return nil, err
	}
	var list []string
	if err := json.Unmarshal([]byte(v), &list); err != nil {
		return nil, err
	}
	return list, nil
}

// SetDisabledRuleSources grava a lista (sem repetições, ordenada).
func (d *DB) SetDisabledRuleSources(ctx context.Context, names []string) error {
	seen := map[string]bool{}
	list := make([]string, 0, len(names))
	for _, n := range names {
		if n != "" && !seen[n] {
			seen[n] = true
			list = append(list, n)
		}
	}
	sort.Strings(list)
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return d.saveRuleSetting(ctx, settingDisabledSources, string(b))
}
