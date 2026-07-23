package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"mesh/internal/control"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version":
		err = version(os.Args[2:])
	case "verify-release":
		err = verifyRelease(os.Args[2:])
	case "enroll":
		err = enroll(os.Args[2:])
	case "agent":
		err = runAgent(os.Args[2:])
	case "recover-agent":
		err = recoverAgent(os.Args[2:])
	case "create-network":
		err = createNetwork(os.Args[2:])
	case "create-node":
		err = createNode(os.Args[2:])
	case "reissue-enrollment":
		err = reissueEnrollment(os.Args[2:])
	case "issue-agent-recovery":
		err = issueAgentRecovery(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "meshctl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: meshctl <version|verify-release|enroll|agent|recover-agent|create-network|create-node|reissue-enrollment|issue-agent-recovery> [flags]")
}

func createNetwork(args []string) error {
	flags := flag.NewFlagSet("create-network", flag.ContinueOnError)
	server := flags.String("server", "http://127.0.0.1:8080", "control plane URL")
	admin := flags.String("admin-token", os.Getenv("MESH_ADMIN_TOKEN"), "admin token (or MESH_ADMIN_TOKEN)")
	name := flags.String("name", "", "network name")
	cidr := flags.String("cidr", "10.42.0.0/24", "Nebula CIDR")
	if err := flags.Parse(args); err != nil {
		return err
	}
	var result control.Network
	if err := call(http.MethodPost, strings.TrimRight(*server, "/")+"/api/v1/networks", *admin, control.CreateNetworkInput{Name: *name, CIDR: *cidr}, &result); err != nil {
		return err
	}
	fmt.Printf("Created network %s (%s), id %s\n", result.Name, result.CIDR, result.ID)
	return nil
}

func createNode(args []string) error {
	flags := flag.NewFlagSet("create-node", flag.ContinueOnError)
	server := flags.String("server", "http://127.0.0.1:8080", "control plane URL")
	admin := flags.String("admin-token", os.Getenv("MESH_ADMIN_TOKEN"), "admin token (or MESH_ADMIN_TOKEN)")
	network := flags.String("network", "", "network id")
	name := flags.String("name", "", "node name")
	role := flags.String("role", "member", "member or lighthouse")
	endpoint := flags.String("endpoint", "", "public lighthouse host:port")
	site := flags.String("site", "", "placement site label (defaults to unassigned)")
	failureDomain := flags.String("failure-domain", "", "placement failure-domain label (defaults to unassigned)")
	groups := flags.String("groups", "", "comma-separated groups")
	if err := flags.Parse(args); err != nil {
		return err
	}
	input := control.CreateNodeInput{
		Name: *name, Role: *role, PublicEndpoint: *endpoint,
		Site: *site, FailureDomain: *failureDomain,
	}
	if *groups != "" {
		input.Groups = strings.Split(*groups, ",")
	}
	var result control.CreatedNode
	if err := call(http.MethodPost, strings.TrimRight(*server, "/")+"/api/v1/networks/"+*network+"/nodes", *admin, input, &result); err != nil {
		return err
	}
	fmt.Printf("Created %s (%s). Enrollment token (shown once, expires %s):\n%s\n", result.Node.Name, result.Node.IP, result.ExpiresAt.Format(time.RFC3339), result.EnrollmentToken)
	return nil
}

func reissueEnrollment(args []string) error {
	return reissueEnrollmentTo(args, os.Stdout)
}

func reissueEnrollmentTo(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("reissue-enrollment", flag.ContinueOnError)
	server := flags.String("server", "http://127.0.0.1:8080", "control plane URL")
	admin := flags.String("admin-token", os.Getenv("MESH_ADMIN_TOKEN"), "admin token (or MESH_ADMIN_TOKEN)")
	node := flags.String("node", "", "pending node id")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*node) == "" {
		return fmt.Errorf("--node is required")
	}
	var result control.ReissuedEnrollment
	endpoint := strings.TrimRight(*server, "/") + "/api/v1/nodes/" + url.PathEscape(strings.TrimSpace(*node)) + "/enrollment/reissue"
	if err := call(http.MethodPost, endpoint, *admin, struct{}{}, &result); err != nil {
		return err
	}
	fmt.Fprintf(output, "Reissued enrollment for %s (%s). Replacement token (shown once, expires %s):\n%s\n", result.Node.Name, result.Node.IP, result.ExpiresAt.Format(time.RFC3339), result.EnrollmentToken)
	return nil
}

func issueAgentRecovery(args []string) error {
	return issueAgentRecoveryTo(args, os.Stdout)
}

func issueAgentRecoveryTo(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("issue-agent-recovery", flag.ContinueOnError)
	server := flags.String("server", "http://127.0.0.1:8080", "control plane URL")
	admin := flags.String("admin-token", os.Getenv("MESH_ADMIN_TOKEN"), "admin token (or MESH_ADMIN_TOKEN)")
	node := flags.String("node", "", "active node id")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("issue-agent-recovery does not accept positional arguments")
	}
	nodeID := strings.TrimSpace(*node)
	if nodeID == "" {
		return fmt.Errorf("--node is required")
	}
	var result control.IssuedAgentRecovery
	endpoint := strings.TrimRight(*server, "/") + "/api/v1/nodes/" + url.PathEscape(nodeID) + "/agent-recovery"
	if err := call(http.MethodPost, endpoint, *admin, struct{}{}, &result); err != nil {
		return err
	}
	fmt.Fprintf(output, "Issued agent recovery for %s (%s). Token shown once; expires %s:\n%s\n", result.Node.Name, result.Node.IP, result.ExpiresAt.Format(time.RFC3339), result.RecoveryToken)
	fmt.Fprintln(output, "Issuance alone does not invalidate the current agent credential; a successful node recovery replaces it atomically.")
	return nil
}

func call(method, url, adminToken string, input, output any) error {
	return callContext(context.Background(), secureHTTPClient(), method, url, adminToken, input, output)
}

func callContext(ctx context.Context, client *http.Client, method, url, adminToken string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr map[string]string
		if json.Unmarshal(response, &apiErr) == nil && apiErr["error"] != "" {
			return &httpResponseError{StatusCode: resp.StatusCode, Message: apiErr["error"]}
		}
		return &httpResponseError{StatusCode: resp.StatusCode}
	}
	if output != nil {
		return json.Unmarshal(response, output)
	}
	return nil
}

type httpResponseError struct {
	StatusCode int
	Message    string
}

func (e *httpResponseError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("server returned HTTP %d", e.StatusCode)
}

func secureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
