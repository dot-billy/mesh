package main

import (
	"errors"
	"flag"
	"io"

	"mesh/internal/kubeinit"
)

const kubernetesTLSMaterializeCommand = "materialize-kubernetes-tls"

func runKubernetesTLSMaterializer(arguments []string) error {
	var options kubeinit.TLSOptions
	flags := flag.NewFlagSet(kubernetesTLSMaterializeCommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.TLSSourceDir, "tls-source-dir", "", "projected TLS volume root")
	flags.StringVar(&options.OutputRoot, "output-root", "", "shared emptyDir publication root")
	flags.StringVar(&options.TLSServerName, "tls-server-name", "", "expected TLS certificate DNS name or IP")
	flags.IntVar(&options.RuntimeUID, "runtime-uid", 65532, "non-root release-origin runtime UID")
	flags.IntVar(&options.RuntimeGID, "runtime-gid", 65532, "non-root release-origin runtime GID")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid Kubernetes TLS materializer arguments")
	}
	return kubeinit.RunTLS(options)
}
