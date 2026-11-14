//go:build windows

package traffic

// syscallUmask is a no-op on Windows, where permission bits are not governed
// by a process umask. Tests treat the -1 return as "cannot control umask".
func syscallUmask(mask int) int {
	return -1
}
