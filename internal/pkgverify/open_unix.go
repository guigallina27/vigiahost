//go:build unix

package pkgverify

import "syscall"

// openNoFollow: não segue link no último componente e não bloqueia ao abrir FIFO (o tipo é conferido depois).
const openNoFollow = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
