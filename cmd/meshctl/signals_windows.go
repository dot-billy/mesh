//go:build windows

package main

import "os"

func agentSignals() []os.Signal { return []os.Signal{os.Interrupt} }
