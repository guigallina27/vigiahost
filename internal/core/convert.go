package core

import (
	"time"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
)

func ptr[T any](v T) *T { return &v }

func optTime(t *time.Time) *time.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	v := *t
	return &v
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func optSlice(s []string) *[]string {
	if len(s) == 0 {
		return nil
	}
	return &s
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func toAPIProfile(p report.Profile) api.ResourceProfile {
	return api.ResourceProfile{Name: p.Name, CpuQuotaPercent: p.CPUQuotaPercent, MemoryMaxBytes: p.MemoryMaxBytes,
		IoReadBytesPerSec: p.IOReadBytesPerSec, IoWeight: p.IOWeight, Workers: p.Workers,
		ClamdConcurrency: p.ClamdConcurrency, MaxRuntimeSec: p.MaxRuntimeSec, Nice: p.Nice, MaxFileBytes: p.MaxFileBytes,
		PressureCpu: ptr(p.PressureCPU), PressureIo: ptr(p.PressureIO), PressureMemory: ptr(p.PressureMemory)}
}

func fromAPIProfile(p api.ResourceProfile) report.Profile {
	deref := func(v *int) int {
		if v == nil {
			return 0
		}
		return *v
	}
	return report.Profile{Name: p.Name, CPUQuotaPercent: p.CpuQuotaPercent, MemoryMaxBytes: p.MemoryMaxBytes,
		IOReadBytesPerSec: p.IoReadBytesPerSec, IOWeight: p.IoWeight, Workers: p.Workers,
		ClamdConcurrency: p.ClamdConcurrency, MaxRuntimeSec: p.MaxRuntimeSec, Nice: p.Nice, MaxFileBytes: p.MaxFileBytes,
		PressureCPU: deref(p.PressureCpu), PressureIO: deref(p.PressureIo), PressureMemory: deref(p.PressureMemory)}
}

func toAPILimitSet(l store.Limits) api.RunLimitSet {
	return api.RunLimitSet{CpuQuotaPercent: l.CPUQuotaPercent, MemoryMaxBytes: l.MemoryMaxBytes,
		IoReadBytesPerSec: l.IOReadBytesPerSec, IoWeight: l.IOWeight}
}

func toAPIMetrics(m *report.Metrics) *api.RunMetrics {
	if m == nil {
		return nil
	}
	out := api.RunMetrics{Phases: make([]api.PhaseTiming, 0, len(m.Phases)), CpuSeconds: float32(m.CPUSeconds),
		MemoryPeakBytes: m.MemoryPeakBytes, BytesRead: m.BytesRead, Source: api.RunMetricsSource(m.Source),
		Throttle: api.ThrottleStats{Available: m.Throttle.Available, Enabled: m.Throttle.Enabled,
			LimitedSeconds: float32(m.Throttle.LimitedSeconds), PausedSeconds: float32(m.Throttle.PausedSeconds),
			Events: make([]api.ThrottleEvent, 0, len(m.Throttle.Events)), EventsDropped: m.Throttle.EventsDropped}}
	if m.Source == "" {
		out.Source = api.RunMetricsSource("none")
	}
	for _, ph := range m.Phases {
		out.Phases = append(out.Phases, api.PhaseTiming{Phase: string(ph.Phase), Seconds: float32(ph.Seconds)})
	}
	if m.BytesRead > 0 && m.CPUSeconds > 0 {
		out.CpuSecondsPerGb = ptr(float32(m.CPUSeconds / (float64(m.BytesRead) / (1 << 30))))
	}
	for _, e := range m.Throttle.Events {
		out.Throttle.Events = append(out.Throttle.Events, api.ThrottleEvent{At: e.At, Action: api.ThrottleEventAction(e.Action),
			Resource: api.PressureResource(e.Resource), Pressure: float32(e.Pressure), Threshold: e.Threshold, Workers: e.Workers})
	}
	return &out
}

func skips(m map[report.SkipReason]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[string(k)] = v
	}
	return out
}

func toAPIRun(r store.Run) api.Run {
	out := api.Run{Id: r.ID, Kind: api.RunKind(r.Kind), Status: api.RunStatus(r.Status), Origin: api.RunOrigin(r.Origin),
		RequestedBy: r.RequestedBy, ScheduleId: r.ScheduleID, ScheduledFor: optTime(r.ScheduledFor),
		Paths: nonNil(r.Paths), Exclude: nonNil(r.Exclude), Incremental: r.Incremental, Profile: toAPIProfile(r.Profile),
		Priority: r.Priority, Attempts: r.Attempts, CreatedAt: r.CreatedAt, StartedAt: optTime(r.StartedAt),
		FinishedAt: optTime(r.FinishedAt), Phase: r.Phase, Paused: r.Paused, FilesSeen: r.FilesSeen,
		FilesEligible: r.FilesEligible, FilesProcessed: r.FilesProcessed, BytesEligible: r.BytesEligible,
		BytesProcessed: r.BytesProcessed, FindingsCount: r.FindingsCount, Error: r.Error}
	if len(r.Accounts) > 0 {
		uids := make([]int64, 0, len(r.Accounts))
		for _, u := range r.Accounts {
			uids = append(uids, int64(u))
		}
		out.Accounts = &uids
	}
	if sm := r.Summary; sm != nil {
		sum := api.RunSummary{Status: api.RunStatus(sm.Status), Error: optional(sm.Error), StartedAt: timePtr(sm.StartedAt),
			FinishedAt: timePtr(sm.FinishedAt), FilesSeen: sm.FilesSeen, FilesEligible: sm.FilesEligible,
			BytesEligible: sm.BytesEligible, Findings: sm.Findings, Objects: sm.Objects, CacheHits: sm.CacheHits,
			FilesPerSecond: float32(sm.FilesPerSecond), MbPerSecond: float32(sm.MBPerSecond), Warnings: optSlice(sm.Warnings)}
		if len(sm.Skipped) > 0 {
			sum.Skipped = ptr(skips(sm.Skipped))
		}
		sum.Metrics = toAPIMetrics(sm.Metrics)
		out.Summary = &sum
	}
	if th := r.Throttle; th != nil && r.Status == store.RunRunning {
		out.Throttle = &api.ThrottleState{State: api.ThrottleStateState(th.State), Workers: th.Workers,
			Resource: api.PressureResource(th.Resource), Pressure: float32(th.Pressure)}
	}
	if len(r.Adjustments) > 0 {
		adj := make([]api.RunAdjustment, 0, len(r.Adjustments))
		for _, a := range r.Adjustments {
			adj = append(adj, api.RunAdjustment{At: a.At, Actor: a.Actor, Before: toAPILimitSet(a.Before), After: toAPILimitSet(a.After)})
		}
		out.Adjustments = &adj
	}
	return out
}

func toAPIRuns(rs []store.Run) []api.Run {
	out := make([]api.Run, 0, len(rs))
	for _, r := range rs {
		out = append(out, toAPIRun(r))
	}
	return out
}

func toAPIEngine(e store.RunEngine) api.EngineCoverage {
	sk, er := e.Skipped, e.Errors
	if sk == nil {
		sk = map[string]int64{}
	}
	if er == nil {
		er = map[string]int64{}
	}
	out := api.EngineCoverage{Engine: e.Engine, Version: e.Version, RulesVersion: e.RulesVersion, Available: e.Available,
		SelftestPassed: e.SelfTestPassed, SelftestDetail: e.SelfTestDetail, Eligible: e.Eligible, Analyzed: e.Analyzed,
		FromCache: e.FromCache, BytesAnalyzed: e.BytesAnalyzed, Seconds: float32(e.Seconds), Skipped: sk, Errors: er,
		Error: e.Error}
	// Vazão por segundo de motor: só os arquivos analisados de fato (os do cache não passaram pelo motor).
	if e.Seconds > 0 {
		out.FilesPerSecond = ptr(float32(float64(max(e.Analyzed-e.FromCache, 0)) / e.Seconds))
		out.MbPerSecond = ptr(float32(float64(e.BytesAnalyzed) / (1 << 20) / e.Seconds))
	}
	return out
}

func toAPILocation(l report.Location) api.Location {
	return api.Location{Path: l.Path, PathHex: optional(l.PathHex), Dev: int64(l.Dev), Ino: int64(l.Ino), //nolint:gosec // identificadores do sistema de arquivos
		Size: l.Size, Mode: int64(l.Mode), Uid: int64(l.UID), Gid: int64(l.GID), Nlink: int64(l.Nlink), //nolint:gosec // idem
		Mtime: timePtr(l.Mtime), Ctime: timePtr(l.Ctime)}
}

func toAPIFinding(f store.Finding) api.Finding {
	out := api.Finding{Id: f.ID, Kind: api.FindingKind(f.Kind), Engine: f.Engine, EngineVersion: f.EngineVersion,
		RulesVersion: f.RulesVersion, Signature: f.Signature, Source: f.Source, License: f.License, Author: f.Author,
		Reference: f.Reference, Description: f.Description, Category: f.Category, Severity: api.Severity(f.Severity),
		Sha256: optional(f.SHA256), FileType: f.FileType, State: api.FindingState(f.State), Assignee: f.Assignee,
		ExceptionId: f.ExceptionID, FirstRun: f.FirstRun, LastRun: f.LastRun, FirstSeen: f.FirstSeen,
		LastSeen: f.LastSeen, StateChanged: f.StateChanged, TimesSeen: f.TimesSeen, LocationsCount: f.Locations,
		Evidence: f.Evidence, Subject: optional(f.Subject)}
	if out.Evidence == nil {
		out.Evidence = map[string]string{}
	}
	if f.Location != nil {
		out.Location = ptr(toAPILocation(*f.Location))
	}
	if p := f.Process; p != nil {
		out.Process = &api.ProcessEvidence{Pid: p.PID, Ppid: p.PPID, Uid: int64(p.UID), Comm: p.Comm, Exe: p.Exe,
			Cmdline: optSlice(p.Cmdline), Unit: optional(p.Unit), Cgroup: optional(p.Cgroup),
			ExeSha256: optional(p.ExeSHA256), StartTime: optional(p.StartTime), Listening: optSlice(p.Listening),
			Connected: optSlice(p.Connected)}
	}
	if p := f.Persistence; p != nil {
		out.Persistence = &api.PersistenceEntry{Kind: p.Kind, Path: p.Path, Detail: optional(p.Detail),
			Sha256: optional(p.SHA256), Owner: optional(p.Owner), Package: optional(p.Package)}
		if p.Change != "" {
			out.Persistence.Change = ptr(api.PersistenceEntryChange(p.Change))
		}
	}
	return out
}

func toAPIFindings(fs []store.Finding) []api.Finding {
	out := make([]api.Finding, 0, len(fs))
	for _, f := range fs {
		out = append(out, toAPIFinding(f))
	}
	return out
}

func toAPIException(e store.Exception, now time.Time) api.Exception {
	return api.Exception{Id: e.ID, Scope: api.ExceptionScope(e.Scope), Sha256: e.SHA256, Signature: e.Signature,
		PathPrefix: e.PathPrefix, Reason: e.Reason, CreatedBy: e.CreatedBy, CreatedAt: e.CreatedAt,
		ExpiresAt: optTime(e.ExpiresAt), RevokedAt: optTime(e.RevokedAt), RevokedBy: e.RevokedBy, Active: e.Active(now)}
}

func toAPIUser(u store.User) api.User {
	return api.User{Id: u.ID, Username: u.Username, DisplayName: u.DisplayName, Role: api.Role(u.Role),
		Disabled: u.Disabled, MfaEnabled: u.MFAEnabled(), CreatedAt: u.CreatedAt, LastLoginAt: optTime(u.LastLoginAt)}
}

func toAPIToken(t store.APIToken) api.ApiToken {
	return api.ApiToken{Id: t.ID, Name: t.Name, Username: t.Username, Role: api.Role(t.Role), Prefix: t.Prefix,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsed: optTime(t.LastUsed), RevokedAt: optTime(t.RevokedAt)}
}
