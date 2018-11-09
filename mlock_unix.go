// +build !windows

package main

import (
	"syscall"
)

const (
	mclCurrent = 1
	mclFuture  = 2
)

func lockMemory() {
	syscall.Mlockall(mclCurrent | mclFuture)
}
