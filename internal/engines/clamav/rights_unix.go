//go:build unix

package clamav

import "syscall"

func unixRights(fd int) []byte { return syscall.UnixRights(fd) }
