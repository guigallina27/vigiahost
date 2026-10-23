//go:build !linux

package perf

// ProcessUsage só tem implementação no Linux; aqui não há o que medir.
func ProcessUsage() Usage { return Usage{} }
