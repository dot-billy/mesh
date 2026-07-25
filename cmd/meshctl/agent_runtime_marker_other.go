//go:build !linux

package main

import "errors"

func packagedRuntimeReadinessMarker(service string) (runtimeReadinessMarker, error) {
	if service == "mesh-nebula.service" {
		return nil, errors.New("the packaged mesh-nebula.service runtime gate requires Linux")
	}
	return nil, nil
}
