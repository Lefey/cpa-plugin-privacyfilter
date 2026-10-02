package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func resetABIStateForTest(t *testing.T) {
	t.Helper()
	privacyFilterABIState.Lock()
	runtime := privacyFilterABIState.runtime
	privacyFilterABIState.plugin = nil
	privacyFilterABIState.runtime = nil
	privacyFilterABIState.shuttingDown = false
	privacyFilterABIState.host = nil
	privacyFilterABIState.Unlock()
	if runtime != nil && runtime.cache != nil {
		runtime.cache.Clear()
	}
	t.Cleanup(func() {
		privacyFilterABIState.nativeInFlight.Wait()
		privacyFilterABIState.inFlight.Wait()
		privacyFilterABIState.Lock()
		runtime := privacyFilterABIState.runtime
		privacyFilterABIState.plugin = nil
		privacyFilterABIState.runtime = nil
		privacyFilterABIState.shuttingDown = false
		privacyFilterABIState.host = nil
		privacyFilterABIState.Unlock()
		if runtime != nil && runtime.cache != nil {
			runtime.cache.Clear()
		}
	})
}

func registerForTest(t *testing.T, hostSchema uint32) abiRegistration {
	t.Helper()
	return registerWithConfigForTest(t, hostSchema, nil)
}

func registerWithConfigForTest(t *testing.T, hostSchema uint32, config []byte) abiRegistration {
	t.Helper()
	req, err := json.Marshal(abiLifecycleRequest{
		SchemaVersion: hostSchema,
		ConfigYAML:    config,
		PluginDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handlePrivacyFilterRegister(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var env abiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("registration envelope not OK: response_len=%d", len(raw))
	}
	var reg abiRegistration
	if err := json.Unmarshal(env.Result, &reg); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	return reg
}

func TestNegotiateSchemaVersion(t *testing.T) {
	tests := []struct {
		name string
		host uint32
		want uint32
	}{
		{name: "legacy omitted", host: 0, want: 1},
		{name: "legacy explicit", host: 1, want: 1},
		{name: "minimum active termination", host: 2, want: 2},
		{name: "newer host capped", host: pluginabi.SchemaVersion, want: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := negotiateSchemaVersion(tc.host, implementedSchemaVersion); got != tc.want {
				t.Fatalf("negotiateSchemaVersion(%d) = %d, want %d", tc.host, got, tc.want)
			}
		})
	}
}

func TestNativeScanLimitsAreFixed(t *testing.T) {
	if nativeScanConcurrency != 4 {
		t.Fatalf("native scan concurrency = %d, want 4", nativeScanConcurrency)
	}
	if nativeScanAdmissionWait <= 0 || nativeScanAdmissionWait > 100*time.Millisecond {
		t.Fatalf("native admission wait = %s, want (0, 100ms]", nativeScanAdmissionWait)
	}
	if nativeScanDeadline != 10*time.Second {
		t.Fatalf("native scan deadline = %s, want 10s", nativeScanDeadline)
	}
}

func TestNativeScanAdmissionCapsConcurrencyAndReleases(t *testing.T) {
	if got := len(nativeScanSlots); got != 0 {
		t.Fatalf("native scan slots occupied before test: %d", got)
	}
	releases := make([]func(), 0, nativeScanConcurrency)
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for index := 0; index < nativeScanConcurrency; index++ {
		release, err := acquireNativeScan(context.Background(), 0)
		if err != nil {
			t.Fatalf("acquire slot %d: %v", index, err)
		}
		releases = append(releases, release)
	}
	if _, err := acquireNativeScan(context.Background(), 0); !errors.Is(err, errNativeScanAdmission) {
		t.Fatalf("fifth scan admission error = %v, want %v", err, errNativeScanAdmission)
	}

	releases[0]()
	releases = releases[1:]
	replacementRelease, err := acquireNativeScan(context.Background(), 0)
	if err != nil {
		t.Fatalf("acquire released slot: %v", err)
	}
	releases = append(releases, replacementRelease)
	for _, release := range releases {
		release()
	}
	releases = nil
	if got := len(nativeScanSlots); got != 0 {
		t.Fatalf("native scan slots occupied after release: %d", got)
	}
}

func TestNativeScanAdmissionHonorsWaitAndContext(t *testing.T) {
	if got := len(nativeScanSlots); got != 0 {
		t.Fatalf("native scan slots occupied before test: %d", got)
	}
	releases := make([]func(), 0, nativeScanConcurrency)
	for index := 0; index < nativeScanConcurrency; index++ {
		release, err := acquireNativeScan(context.Background(), 0)
		if err != nil {
			t.Fatalf("acquire slot %d: %v", index, err)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()

	if _, err := acquireNativeScan(context.Background(), 5*time.Millisecond); !errors.Is(err, errNativeScanAdmission) {
		t.Fatalf("timed admission error = %v, want %v", err, errNativeScanAdmission)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := acquireNativeScan(ctx, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled admission error = %v, want context canceled", err)
	}
}

func TestRegistrationNegotiatesLifecycleCapability(t *testing.T) {
	for _, tc := range []struct {
		name          string
		hostSchema    uint32
		wantSchema    uint32
		wantLifecycle bool
	}{
		{name: "legacy", hostSchema: 1, wantSchema: 1, wantLifecycle: false},
		{name: "schema two", hostSchema: 2, wantSchema: 2, wantLifecycle: true},
		{name: "current host", hostSchema: pluginabi.SchemaVersion, wantSchema: 2, wantLifecycle: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetABIStateForTest(t)
			var reg abiRegistration
			if tc.hostSchema < implementedSchemaVersion {
				reg = registerWithConfigForTest(t, tc.hostSchema, []byte("on_error: passthrough\n"))
			} else {
				reg = registerForTest(t, tc.hostSchema)
			}
			if reg.SchemaVersion != tc.wantSchema {
				t.Fatalf("schema = %d, want %d", reg.SchemaVersion, tc.wantSchema)
			}
			if !reg.Capabilities.RequestInterceptor {
				t.Fatal("request interceptor capability missing")
			}
			if reg.Capabilities.RequestLifecyclePlugin != tc.wantLifecycle {
				t.Fatalf("lifecycle capability = %v, want %v", reg.Capabilities.RequestLifecyclePlugin, tc.wantLifecycle)
			}
		})
	}
}

func TestLegacyHostRejectsDefaultFailClosedConfig(t *testing.T) {
	resetABIStateForTest(t)
	req, err := json.Marshal(abiLifecycleRequest{
		SchemaVersion: 1,
		PluginDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handlePrivacyFilterRegister(req); err == nil {
		t.Fatal("schema-1 host accepted default fail-closed configuration")
	}
}

func TestRequestCompleteDispatch(t *testing.T) {
	resetABIStateForTest(t)
	registerForTest(t, 2)
	req, err := json.Marshal(pluginapi.RequestCompletion{
		RequestID: "request-1",
		Outcome:   pluginapi.RequestCompletionSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handlePrivacyFilterABIMethod(context.Background(), pluginabi.MethodRequestComplete, req)
	if err != nil {
		t.Fatalf("request.complete: %v", err)
	}
	var env abiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if !env.OK {
		t.Fatalf("request.complete envelope not OK: response_len=%d", len(raw))
	}
}

func TestRequestCompleteRemainsAvailableWhileQuiesced(t *testing.T) {
	resetABIStateForTest(t)
	registerForTest(t, 2)

	privacyFilterABIState.RLock()
	runtime := privacyFilterABIState.runtime
	privacyFilterABIState.RUnlock()
	if runtime == nil || runtime.cache == nil {
		t.Fatal("registered runtime cache is nil")
	}
	runtime.cache.Acquire("request-quiesce", testRequestScanContext())
	if _, err := handlePrivacyFilterQuiesce(); err != nil {
		t.Fatalf("quiesce: %v", err)
	}

	req, err := json.Marshal(pluginapi.RequestCompletion{
		RequestID: "request-quiesce",
		Outcome:   pluginapi.RequestCompletionSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handlePrivacyFilterABIMethod(context.Background(), pluginabi.MethodRequestComplete, req); err != nil {
		t.Fatalf("request.complete while quiesced: %v", err)
	}
	if runtime.cache.Len() != 0 {
		t.Fatalf("cache retained %d entries after quiesced completion", runtime.cache.Len())
	}
}

func TestQuiesceWaitsForAdmittedNativeScan(t *testing.T) {
	resetABIStateForTest(t)
	registerForTest(t, 2)
	done, err := beginNativeScanCall()
	if err != nil {
		t.Fatalf("begin native scan: %v", err)
	}

	quiesced := make(chan error, 1)
	go func() {
		_, quiesceErr := handlePrivacyFilterQuiesce()
		quiesced <- quiesceErr
	}()
	deadline := time.Now().Add(time.Second)
	for {
		privacyFilterABIState.RLock()
		shuttingDown := privacyFilterABIState.shuttingDown
		privacyFilterABIState.RUnlock()
		if shuttingDown {
			break
		}
		if time.Now().After(deadline) {
			done()
			t.Fatal("quiesce did not enter shutting-down state")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-quiesced:
		done()
		t.Fatalf("quiesce returned before native scan release: %v", err)
	default:
	}

	done()
	select {
	case err := <-quiesced:
		if err != nil {
			t.Fatalf("quiesce: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("quiesce did not return after native scan release")
	}
}

func TestQuiesceStopsNewCallsUntilRegister(t *testing.T) {
	resetABIStateForTest(t)
	registerForTest(t, 2)
	if _, err := handlePrivacyFilterQuiesce(); err != nil {
		t.Fatalf("quiesce: %v", err)
	}
	if _, _, err := beginPrivacyFilterPluginCall(); err == nil {
		t.Fatal("begin call succeeded while quiesced")
	}

	registerForTest(t, 2)
	_, done, err := beginPrivacyFilterPluginCall()
	if err != nil {
		t.Fatalf("begin call after re-register: %v", err)
	}
	done()
}

func TestABIPanicEnvelopeFailsClosedForRequestInterceptors(t *testing.T) {
	for _, method := range []string{
		pluginabi.MethodRequestInterceptBefore,
		pluginabi.MethodRequestInterceptAfter,
	} {
		raw := abiPanicEnvelope(method)
		var env abiEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		if !env.OK {
			t.Fatalf("panic envelope is not an OK response: response_len=%d", len(raw))
		}
		var resp pluginapi.RequestInterceptResponse
		if err := json.Unmarshal(env.Result, &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.Terminate || resp.StatusCode != 503 {
			t.Fatalf("panic response terminate=%t status=%d body_len=%d, want terminate 503", resp.Terminate, resp.StatusCode, len(resp.ResponseBody))
		}
		if got := resp.ResponseHeaders.Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q", got)
		}
	}
}

func TestABIFailureEnvelopeTerminatesRequest(t *testing.T) {
	raw := abiFailureEnvelope(
		pluginabi.MethodRequestInterceptBefore,
		413,
		"request_too_large",
		"privacy filter request payload exceeds the native plugin limit",
	)
	var env abiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if !env.OK {
		t.Fatalf("failure envelope is not an OK response: response_len=%d", len(raw))
	}
	var resp pluginapi.RequestInterceptResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Terminate || resp.StatusCode != 413 {
		t.Fatalf("response terminate=%t status=%d body_len=%d, want terminate 413", resp.Terminate, resp.StatusCode, len(resp.ResponseBody))
	}
	if got := string(resp.ResponseBody); got == "" || !json.Valid(resp.ResponseBody) {
		t.Fatalf("response body is not valid JSON: body_len=%d", len(got))
	}
}

func TestABIFailureEnvelopeUsesPluginErrorOutsideRequest(t *testing.T) {
	raw := abiFailureEnvelope(pluginabi.MethodPluginRegister, 503, "plugin_error", "safe message")
	var env abiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.OK || env.Error == nil || env.Error.Code != "plugin_error" {
		t.Fatalf("unexpected envelope: ok=%t has_error=%t response_len=%d", env.OK, env.Error != nil, len(raw))
	}
}

func TestBuildPluginDeclaresImplementedSchema(t *testing.T) {
	plugin, err := buildPlugin(nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if plugin.SchemaVersion != implementedSchemaVersion {
		t.Fatalf("schema = %d, want %d", plugin.SchemaVersion, implementedSchemaVersion)
	}
	if plugin.Capabilities.RequestLifecyclePlugin == nil {
		t.Fatal("lifecycle capability missing")
	}
}
