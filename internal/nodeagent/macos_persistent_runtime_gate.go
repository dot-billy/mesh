package nodeagent

import (
	"bytes"
	"errors"
)

var darwinPersistentRuntimeGateContent = []byte("mesh-runtime-enabled-v1\n")

const (
	darwinModeTypeMask    = uint16(0170000)
	darwinModeRegularFile = uint16(0100000)
	darwinRuntimeGateMode = uint16(0o400)
)

type darwinRuntimeGateSnapshot struct {
	device     int32
	inode      uint64
	mode       uint16
	links      uint16
	uid        uint32
	gid        uint32
	size       int64
	modifiedS  int64
	modifiedNS int64
	changedS   int64
	changedNS  int64
	flags      uint32
	generation uint32
}

func validateDarwinPersistentRuntimeGate(snapshot darwinRuntimeGateSnapshot, content []byte) error {
	if snapshot.mode&darwinModeTypeMask != darwinModeRegularFile || snapshot.mode&0o7777 != darwinRuntimeGateMode {
		return errors.New("Darwin persistent runtime gate must be an exact mode-0400 regular file")
	}
	if snapshot.uid != 0 || snapshot.gid != 0 || snapshot.links != 1 {
		return errors.New("Darwin persistent runtime gate must be root:wheel and singly linked")
	}
	if snapshot.flags != 0 {
		return errors.New("Darwin persistent runtime gate cannot carry file flags")
	}
	if snapshot.size != int64(len(darwinPersistentRuntimeGateContent)) || !bytes.Equal(content, darwinPersistentRuntimeGateContent) {
		return errors.New("Darwin persistent runtime gate does not contain the exact reviewed authorization")
	}
	return nil
}
