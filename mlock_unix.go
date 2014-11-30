// +build !windows

package main

import (
	"syscall"
)

const (
	MCL_CURRENT = 1
	MCL_FUTURE  = 2
)

func lockMemory() {
	syscall.Mlockall(MCL_CURRENT | MCL_FUTURE)
}
