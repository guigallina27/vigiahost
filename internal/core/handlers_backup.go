package core

import (
	"errors"
	"net/http"
	"time"

	"github.com/guigallina27/vigiahost/internal/backup"
)

// ListBackups lista as cópias do banco guardadas no diretório do serviço.
func (s *Server) ListBackups(w http.ResponseWriter, r *http.Request) {
	if s.BackupDir == "" {
		writeError(w, http.StatusNotFound, "cópias do banco não configuradas", "not_found")
		return
	}
	list, err := backup.List(s.BackupDir)
	if err != nil {
		s.storeError(w, err)
		return
	}
	if list == nil {
		list = []backup.Info{}
	}
	writeJSON(w, http.StatusOK, struct {
		Directory     string        `json:"directory"`
		KeepAutomatic int           `json:"keep_automatic"`
		Backups       []backup.Info `json:"backups"`
	}{s.BackupDir, backup.KeepAutomatic, list})
}

// CreateBackup faz uma cópia manual consistente (VACUUM INTO) sem parar o serviço.
func (s *Server) CreateBackup(w http.ResponseWriter, r *http.Request) {
	if s.BackupDir == "" {
		writeError(w, http.StatusNotFound, "cópias do banco não configuradas", "not_found")
		return
	}
	info, err := backup.Create(r.Context(), s.DB.DB, s.BackupDir, "manual", time.Now())
	if errors.Is(err, backup.ErrExists) {
		writeError(w, http.StatusConflict, "já há uma cópia deste segundo; aguarde e tente de novo", "conflict")
		return
	}
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "backup_created", info.Name, "sha256 "+info.SHA256)
	writeJSON(w, http.StatusCreated, info)
}
