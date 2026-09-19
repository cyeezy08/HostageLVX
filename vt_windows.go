//go:build windows

package main

import (
    "os"
    "syscall"
    "unsafe"
)

// init runs before main: flips console into VT mode so ANSI colors render.
func init() { enableVT() }

func enableVT() {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    getMode := kernel32.NewProc("GetConsoleMode")
    setMode := kernel32.NewProc("SetConsoleMode")
    h := syscall.Handle(os.Stdout.Fd())
    var mode uint32
    getMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
    setMode.Call(uintptr(h), uintptr(mode|0x0004)) // ENABLE_VIRTUAL_TERMINAL_PROCESSING
}