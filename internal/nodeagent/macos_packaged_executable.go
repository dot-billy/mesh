package nodeagent

import "errors"

const darwinPackagedExecutableMode = uint16(0o555)

func validateDarwinPackagedExecutable(snapshot darwinRuntimeGateSnapshot) error {
	if snapshot.mode&darwinModeTypeMask != darwinModeRegularFile || snapshot.mode&0o7777 != darwinPackagedExecutableMode {
		return errors.New("Darwin packaged executable must be an exact mode-0555 regular file")
	}
	if snapshot.uid != 0 || snapshot.gid != 0 || snapshot.links != 1 {
		return errors.New("Darwin packaged executable must be root:wheel and singly linked")
	}
	if snapshot.flags != 0 {
		return errors.New("Darwin packaged executable cannot carry file flags")
	}
	if snapshot.size < 1 {
		return errors.New("Darwin packaged executable cannot be empty")
	}
	return nil
}
