package main

import "testing"

func TestKubernetesTLSMaterializerRejectsUnknownArguments(t *testing.T) {
	if err := runKubernetesTLSMaterializer([]string{"--unknown"}); err == nil {
		t.Fatal("Kubernetes TLS materializer accepted an unknown argument")
	}
}
