// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/certutil"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/pgptest"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

// TestFleetManagedUpgradeUnprivileged tests that the build under test can retrieve an action from
// Fleet and perform the upgrade as an unprivileged Elastic Agent. It does not need to test
// all the combinations of versions as the standalone tests already perform those tests and
// would be redundant.
func TestFleetManagedUpgradeUnprivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})
	testFleetManagedUpgrade(t, info, true)
}

// TestFleetManagedUpgradePrivileged tests that the build under test can retrieve an action from
// Fleet and perform the upgrade as a privileged Elastic Agent. It does not need to test all
// the combinations of  versions as the standalone tests already perform those tests and
// would be redundant.
func TestFleetManagedUpgradePrivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: FleetPrivileged,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})
	testFleetManagedUpgrade(t, info, false)
}

func TestFleetManagedUpgradeToPRBuild(t *testing.T) {
	stack := define.Require(t, define.Requirements{
		Group: Fleet,
		OS:    []define.OS{{Type: define.Linux}},
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})
	ctx := context.Background()

	tempDir := t.TempDir()
	// tempDir := "/tmp/agent-test"

	endFixture, err := define.NewFixtureFromLocalBuild(t,
		define.Version(), atesting.WithLogOutput())
	require.NoError(t, err, "failed creating new fixture")

	pkgSrcPath, err := endFixture.SrcPackage(ctx)
	require.NoError(t, err, "could not get package source directory")
	t.Log("================pkgSrcPath:", pkgSrcPath)
	pkgSrcSHAPath := pkgSrcPath + ".sha512"
	endVersion, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err, "could not get end binary version")

	dir, binHandler := agentBinaryHandler(t, tempDir, endVersion)

	_, pkgName := filepath.Split(pkgSrcPath)
	pkgDstPath := filepath.Join(dir, pkgName)
	pkgDstSHAPath := pkgDstPath + ".sha512"

	// copy agent package and sha512 file to server directory
	src, err := os.Open(pkgSrcPath)
	require.NoError(t, err, "could not src (%q) for copy", pkgSrcPath)
	srcSHA, err := os.Open(pkgSrcSHAPath)
	require.NoError(t, err, "could not src (%q) for copy", pkgSrcSHAPath)

	dst, err := os.OpenFile(pkgDstPath, os.O_CREATE|os.O_RDWR, 0664)
	require.NoError(t, err, "could not open dst (%q) for copy", pkgDstPath)
	dstSHA, err := os.OpenFile(pkgDstSHAPath, os.O_CREATE|os.O_RDWR, 0664)
	require.NoError(t, err, "could not open dst (%q) for copy", pkgDstSHAPath)

	_, err = io.Copy(dst, src)
	require.NoErrorf(t, err, "could not copy %q to %q", src.Name(), dst.Name())
	_ = src.Close()

	_, err = io.Copy(dstSHA, srcSHA)
	require.NoErrorf(t, err, "could not copy %q to %q",
		srcSHA.Name(), dstSHA.Name())
	_ = srcSHA.Close()
	_ = dstSHA.Close()

	// sign the agent package
	pubKey, sig := pgptest.Sing(t, dst)
	dst.Close()

	// save the agent package the signature
	err = os.WriteFile(pkgDstPath+".asc", sig, 0660)
	require.NoError(t, err, "could not save agent's package signature")

	// redirect artifacts.elastic.co to mock server
	appendToEtcHosts(t)

	// serve the signing public key
	gpgHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pgp-keys")
		t.Logf("%s - %s: serving agent signing key", r.Method, r.URL.String())
		_, err := w.Write(pubKey)
		assert.NoError(t, err, "failed sending signing public key")
	})
	// register handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("it works!\n")) })
	mux.Handle("/GPG-KEY-elastic-agent", gpgHandler)
	mux.Handle("/", binHandler)

	caPEM, certPEM, err := certutil.NewCAAndCerts("artifacts.elastic.co", "staging.elastic.co")
	require.NoError(t, err, "could not generate CA and certificate")
	certPair, err := tls.X509KeyPair(certPEM.Cert, certPEM.Key)
	require.NoError(t, err, "could not create tls.Certificates from child certificate")

	capool := x509.NewCertPool()
	capool.AppendCertsFromPEM(caPEM.Cert)

	l, err := net.Listen("tcp", "127.0.0.1:443") //nolint:gosec,nolintlint // it's a test
	require.NoError(t, err, "failed to create a net.Listener for httptest.Server")
	server := &httptest.Server{
		Listener: l,
		//nolint:gosec,nolintlint // it's a test
		Config: &http.Server{Handler: mux},
		TLS: &tls.Config{
			Certificates: []tls.Certificate{certPair},
			RootCAs:      capool,
		},
	}
	server.StartTLS()
	t.Logf("runnign mock artifacts.elastic.co on %s", server.URL)

	// /etc/ssl/certs
	// add server's CA to system trusted CAs
	server.Certificate()
	err = os.WriteFile(
		"/etc/ssl/certs/TestFleetManagedUpgradeToPRBuild-ca.pem",
		caPEM.Cert,
		0644)
	require.NoError(t, err, "could not add server CA to system CAs")

	// all is set up. The actual test is below
	startVer, err := upgradetest.PreviousMinor()
	require.NoError(t, err, "could not get PreviousMinor agent version")

	startFixture, err := atesting.NewFixture(t, startVer.String())
	require.NoErrorf(t, err,
		"could not create start fixture for version %s", startVer.String())

	downloadSource := kibana.DownloadSource{
		Name: "local-pr-build" + uuid.NewString(),
		Host: fmt.Sprintf("%s/%s-%s/downloads/",
			server.URL, endVersion.Binary.Version, endVersion.Binary.Commit[:8]),
		IsDefault: false, // other tests reuse the stack, let's not mess things up
	}
	t.Logf("creating download source %q, using %q.",
		downloadSource.Name, downloadSource.Host)
	downloadSrc, err := stack.KibanaClient.CreateDownloadSource(ctx, downloadSource)
	require.NoError(t, err, "could not create download source")

	policy := defaultPolicy()
	policy.DownloadSourceID = downloadSrc.Item.ID

	// need to pass the CA to the agent
	testUpgradeFleetManagedElasticAgent(ctx, t,
		stack, startFixture, endFixture, policy, false,
		&atesting.InstallOpts{Insecure: true})
}

func appendToEtcHosts(t *testing.T) {
	etcHosts, err := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_RDWR, 0644)
	require.NoError(t, err, "could not open /etc/hosts")

	artifactsLine := "127.0.0.1 artifacts.elastic.co"
	// stagingLine := "127.0.0.1 staging.elastic.co"

	// addArtifactsLine, addStagingLine := true, true
	addArtifactsLine := true
	scan := bufio.NewScanner(etcHosts)
	for scan.Scan() {
		l := scan.Text()
		if strings.Contains(l, artifactsLine) {
			addArtifactsLine = false
		}
		// if strings.Contains(l, stagingLine) {
		// 	addStagingLine = false
		// }
	}

	fmt.Println("scanner error:", scan.Err())

	if addArtifactsLine {
		_, err = etcHosts.WriteString("\n" + artifactsLine)
		require.NoErrorf(t, err, "could not add %q to /etc/hosts", artifactsLine)
		fmt.Println("wrote artifactsLine")
	}
	// if addStagingLine {
	// 	_, err = etcHosts.WriteString("\n" + stagingLine)
	// 	fmt.Println("wrote addStagingLine")
	// 	require.NoErrorf(t, err, "could not add %q to /etc/hosts", stagingLine)
	// }

	require.NoError(t, etcHosts.Close(), "failed closing /etc/hosts")
	return
}

func agentBinaryHandler(t *testing.T, dir string, endVersion atesting.AgentVersionOutput) (string, http.Handler) {
	// https://staging.elastic.co/8.13.2-a00e5658/downloads/beats/elastic-agent/elastic-agent-8.13.2-linux-arm64.tar.gz

	downloadAt := filepath.Join(dir,
		fmt.Sprintf("%s-%s",
			endVersion.Binary.Version, endVersion.Binary.Commit[:8]),
		"downloads", "beats", "elastic-agent")
	err := os.MkdirAll(downloadAt, 0700)
	require.NoError(t, err, "could not create directory structure for file server")

	logOnce := sync.OnceFunc(func() {
		// it's useful for debugging
		dl, err := os.ReadDir(downloadAt)
		require.NoError(t, err)
		var files []string
		for _, d := range dl {
			files = append(files, d.Name())
		}
		t.Logf("ArtifactsServer root dir %q, served files %q\n",
			dir, files)
	})

	fileServer := http.FileServer(http.Dir(dir))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logOnce()

		t.Logf("%s - %s: serving agent file", r.Method, r.URL.String())
		fileServer.ServeHTTP(w, r)
	})
	return downloadAt, handler
}

func testFleetManagedUpgrade(t *testing.T, info *define.Info, unprivileged bool) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	startFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	err = startFixture.Prepare(ctx)
	require.NoError(t, err)
	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)

	// Upgrade to a different build but of the same version (always a snapshot).
	// In the case there is not a different build then the test is skipped.
	// Fleet doesn't allow a downgrade to occur, so we cannot go to a lower version.
	endFixture, err := atesting.NewFixture(
		t,
		upgradetest.EnsureSnapshot(define.Version()),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	err = endFixture.Prepare(ctx)
	require.NoError(t, err)

	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)
	if startVersionInfo.Binary.String() == endVersionInfo.Binary.String() &&
		startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		t.Skipf("Build under test is the same as the build from the artifacts repository (version: %s) [commit: %s]",
			startVersionInfo.Binary.String(), startVersionInfo.Binary.Commit)
	}

	t.Logf("Testing Elastic Agent upgrade from %s to %s with Fleet...",
		define.Version(), endVersionInfo.Binary.String())

	testUpgradeFleetManagedElasticAgent(ctx, t, info, startFixture, endFixture, defaultPolicy(), unprivileged, nil)
}

func TestFleetAirGappedUpgradeUnprivileged(t *testing.T) {
	stack := define.Require(t, define.Requirements{
		Group: FleetAirgapped,
		Stack: &define.Stack{},
		// The test uses iptables to simulate the air-gaped environment.
		OS:    []define.OS{{Type: define.Linux}},
		Local: false, // Needed as the test requires Agent installation
		Sudo:  true,  // Needed as the test uses iptables and installs the Agent
	})
	testFleetAirGappedUpgrade(t, stack, true)
}

func TestFleetAirGappedUpgradePrivileged(t *testing.T) {
	stack := define.Require(t, define.Requirements{
		Group: FleetAirgappedPrivileged,
		Stack: &define.Stack{},
		// The test uses iptables to simulate the air-gaped environment.
		OS:    []define.OS{{Type: define.Linux}},
		Local: false, // Needed as the test requires Agent installation
		Sudo:  true,  // Needed as the test uses iptables and installs the Agent
	})
	testFleetAirGappedUpgrade(t, stack, false)
}

func testFleetAirGappedUpgrade(t *testing.T, stack *define.Info, unprivileged bool) {
	ctx, _ := testcontext.WithDeadline(
		t, context.Background(), time.Now().Add(10*time.Minute))

	latest := define.Version()

	// We need to prepare it first because it'll download the artifact, and it
	// has to happen before we block the artifacts API IPs.
	// The test does not need a fixture, but testUpgradeFleetManagedElasticAgent
	// uses it to get some information about the agent version.
	upgradeTo, err := atesting.NewFixture(
		t,
		latest,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)
	err = upgradeTo.Prepare(ctx)
	require.NoError(t, err)

	s := newArtifactsServer(ctx, t, latest, upgradeTo.PackageFormat())
	host := "artifacts.elastic.co"
	simulateAirGapedEnvironment(t, host)

	rctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, "https://"+host, nil)
	_, err = http.DefaultClient.Do(req)
	if !(errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded)) {
		t.Fatalf(
			"request to %q should have failed, iptables rules should have blocked it",
			host)
	}

	_, err = stack.ESClient.Info()
	require.NoErrorf(t, err,
		"failed to interact with ES after blocking %q through iptables", host)
	_, body, err := stack.KibanaClient.Request(http.MethodGet, "/api/features",
		nil, nil, nil)
	require.NoErrorf(t, err,
		"failed to interact with Kibana after blocking %q through iptables. "+
			"It should not affect the connection to the stack. Host: %s, response body: %s",
		stack.KibanaClient.URL, host, body)

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s with Fleet...",
		define.Version(), latest)

	downloadSource := kibana.DownloadSource{
		Name:      "local-air-gaped-" + uuid.NewString(),
		Host:      s.URL + "/downloads/beats/elastic-agent/",
		IsDefault: false, // other tests reuse the stack, let's not mess things up
	}
	t.Logf("creating download source %q, using %q.",
		downloadSource.Name, downloadSource.Host)
	src, err := stack.KibanaClient.CreateDownloadSource(ctx, downloadSource)
	require.NoError(t, err, "could not create download source")

	policy := defaultPolicy()
	policy.DownloadSourceID = src.Item.ID

	testUpgradeFleetManagedElasticAgent(
		ctx, t, stack, fixture, upgradeTo, policy, unprivileged, &atesting.InstallOpts{
			Insecure: true,
		})
}

func testUpgradeFleetManagedElasticAgent(
	ctx context.Context,
	t *testing.T,
	info *define.Info,
	startFixture *atesting.Fixture,
	endFixture *atesting.Fixture,
	policy kibana.AgentPolicy,
	unprivileged bool,
	extraInstallOpts *atesting.InstallOpts) {
	kibClient := info.KibanaClient

	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)
	startParsedVersion, err := version.ParseVersion(startVersionInfo.Binary.String())
	require.NoError(t, err)
	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)
	endParsedVersion, err := version.ParseVersion(endVersionInfo.Binary.String())
	require.NoError(t, err)

	if unprivileged {
		if startParsedVersion.Less(*upgradetest.Version_8_13_0) {
			t.Skipf("Starting version %s is less than 8.13 and doesn't support --unprivileged", startParsedVersion.String())
		}
		if endParsedVersion.Less(*upgradetest.Version_8_13_0) {
			t.Skipf("Ending version %s is less than 8.13 and doesn't support --unprivileged", endParsedVersion.String())
		}
		if runtime.GOOS != define.Linux {
			t.Skip("Unprivileged mode is currently only supported on Linux")
		}
	}

	if startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		t.Skipf("target version has the same commit hash %q", endVersionInfo.Binary.Commit)
		return
	}

	t.Log("Creating Agent policy...")
	policyResp, err := kibClient.CreatePolicy(ctx, policy)
	require.NoError(t, err, "failed creating policy")
	policy = policyResp.AgentPolicy

	t.Log("Creating Agent enrollment API key...")
	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policyResp.ID,
	}
	enrollmentToken, err := kibClient.CreateEnrollmentAPIKey(ctx, createEnrollmentApiKeyReq)
	require.NoError(t, err, "failed creating enrollment API key")

	t.Log("Getting default Fleet Server URL...")
	fleetServerURL, err := fleettools.DefaultURL(ctx, kibClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	t.Logf("Installing Elastic Agent (unprivileged: %t)...", unprivileged)
	var nonInteractiveFlag bool
	if upgradetest.Version_8_2_0.Less(*startParsedVersion) {
		nonInteractiveFlag = true
	}

	if extraInstallOpts == nil {
		extraInstallOpts = &atesting.InstallOpts{}
	}
	installOpts := *extraInstallOpts

	installOpts.NonInteractive = nonInteractiveFlag
	installOpts.Force = true
	installOpts.Insecure = true
	installOpts.Privileged = !unprivileged
	installOpts.EnrollOpts = atesting.EnrollOpts{
		URL:             fleetServerURL,
		EnrollmentToken: enrollmentToken.APIKey,
	}

	output, err := startFixture.Install(ctx, &installOpts)
	require.NoError(t, err, "failed to install start agent [output: %s]", string(output))

	t.Log("Waiting for Agent to be correct version and healthy...")
	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, startVersionInfo.Binary, 2*time.Minute, 10*time.Second, t)
	require.NoError(t, err)

	t.Log("Waiting for enrolled Agent status to be online...")
	require.Eventually(t,
		check.FleetAgentStatus(
			ctx, t, kibClient, policyResp.ID, "online"),
		2*time.Minute,
		10*time.Second,
		"Agent status is not online")

	t.Logf("Upgrading from version \"%s-%s\" to version \"%s-%s\"...",
		startParsedVersion, startVersionInfo.Binary.Commit,
		endVersionInfo.Binary.String(), endVersionInfo.Binary.Commit)
	err = fleettools.UpgradeAgent(ctx, kibClient, policyResp.ID, endVersionInfo.Binary.String(), true)
	require.NoError(t, err)

	t.Log("Waiting from upgrade details to show up in Fleet")
	hostname, err := os.Hostname()
	require.NoError(t, err)
	var agent *kibana.AgentExisting
	require.Eventuallyf(t, func() bool {
		agent, err = fleettools.GetAgentByPolicyIDAndHostnameFromList(ctx, kibClient, policy.ID, hostname)
		return err == nil && agent.UpgradeDetails != nil
	},
		5*time.Minute, time.Second,
		"last error: %v. agent.UpgradeDetails: %s",
		err, agentUpgradeDetailsString(agent))

	// wait for the watcher to show up
	t.Logf("Waiting for upgrade watcher to start...")
	err = upgradetest.WaitForWatcher(ctx, 5*time.Minute, 10*time.Second)
	require.NoError(t, err, "upgrade watcher did not start")
	t.Logf("Upgrade watcher started")

	// wait for the agent to be healthy and correct version
	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary, 2*time.Minute, 10*time.Second, t)
	require.NoError(t, err)

	t.Log("Waiting for enrolled Agent status to be online...")
	require.Eventually(t, check.FleetAgentStatus(ctx, t, kibClient, policyResp.ID, "online"), 10*time.Minute, 15*time.Second, "Agent status is not online")

	// wait for version
	require.Eventually(t, func() bool {
		t.Log("Getting Agent version...")
		newVersion, err := fleettools.GetAgentVersion(ctx, kibClient, policyResp.ID)
		if err != nil {
			t.Logf("error getting agent version: %v", err)
			return false
		}
		return endVersionInfo.Binary.Version == newVersion
	}, 5*time.Minute, time.Second)

	t.Logf("Waiting for upgrade watcher to finish...")
	err = upgradetest.WaitForNoWatcher(ctx, 2*time.Minute, 10*time.Second, 1*time.Minute+15*time.Second)
	require.NoError(t, err)
	t.Logf("Upgrade watcher finished")

	// now that the watcher has stopped lets ensure that it's still the expected
	// version, otherwise it's possible that it was rolled back to the original version
	err = upgradetest.CheckHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary)
	assert.NoError(t, err)
}

func defaultPolicy() kibana.AgentPolicy {
	policyUUID := uuid.New().String()

	policy := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	return policy
}

// simulateAirGapedEnvironment uses iptables to block outgoing packages to the
// IPs (v4 and v6) associated with host.
func simulateAirGapedEnvironment(t *testing.T, host string) {
	ips, err := net.LookupIP(host)
	require.NoErrorf(t, err, "could not get IPs for host %q", host)

	// iptables -A OUTPUT -j DROP -d IP
	t.Logf("found %v IPs for %q, blocking them...", ips, host)
	var toCleanUp [][]string
	const iptables = "iptables"
	const ip6tables = "ip6tables"
	var cmd string
	for _, ip := range ips {
		cmd = iptables
		if ip.To4() == nil {
			cmd = ip6tables
		}
		args := []string{"-A", "OUTPUT", "-j", "DROP", "-d", ip.String()}

		out, err := exec.Command(
			cmd, args...).
			CombinedOutput()
		if err != nil {
			fmt.Println("FAILED:", cmd, args)
			fmt.Println(string(out))
		}
		t.Logf("added iptables rule %v", args[1:])
		toCleanUp = append(toCleanUp, append([]string{cmd, "-D"}, args[1:]...))

		// Just in case someone executes the test locally.
		t.Logf("use \"%s -D %s\" to remove it", cmd, strings.Join(args[1:], " "))
	}
	t.Cleanup(func() {
		for _, c := range toCleanUp {
			cmd := c[0]
			args := c[1:]

			out, err := exec.Command(
				cmd, args...).
				CombinedOutput()
			if err != nil {
				fmt.Println("clean up FAILED:", cmd, args)
				fmt.Println(string(out))
			}
		}
	})
}

func newArtifactsServer(ctx context.Context, t *testing.T, version string, packageFormat string) *httptest.Server {
	fileServerDir := t.TempDir()
	downloadAt := filepath.Join(fileServerDir, "downloads", "beats", "elastic-agent", "beats", "elastic-agent")
	err := os.MkdirAll(downloadAt, 0700)
	require.NoError(t, err, "could not create directory structure for file server")

	fetcher := atesting.ArtifactFetcher()
	fr, err := fetcher.Fetch(ctx, runtime.GOOS, runtime.GOARCH, version, packageFormat)
	require.NoErrorf(t, err, "could not prepare fetcher to download agent %s",
		version)
	err = fr.Fetch(ctx, t, downloadAt)
	require.NoError(t, err, "could not download agent %s", version)

	// it's useful for debugging
	dl, err := os.ReadDir(downloadAt)
	require.NoError(t, err)
	var files []string
	for _, d := range dl {
		files = append(files, d.Name())
	}
	fmt.Printf("ArtifactsServer root dir %q, served files %q\n",
		fileServerDir, files)

	fs := http.FileServer(http.Dir(fileServerDir))

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	}))
}

func agentUpgradeDetailsString(a *kibana.AgentExisting) string {
	if a == nil {
		return "agent is NIL"
	}
	if a.UpgradeDetails == nil {
		return "upgrade details is NIL"
	}

	return fmt.Sprintf("%#v", *a.UpgradeDetails)
}
