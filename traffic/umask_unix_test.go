//go:build unix

package traffic

import "syscall"

// syscallUmask is the unix implementation; a Windows stub keeps the suite
// portable. Returning the previous mask lets tests restore it.
func syscallUmask(mask int) int {
	return syscall.Umask(mask)
}
