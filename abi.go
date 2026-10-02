package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int PrivacyFilterPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void PrivacyFilterPluginFree(void*, size_t);
extern void PrivacyFilterPluginShutdown(void);

static int privacyfilter_call_host(cliproxy_host_api* api, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	return api->call(api->host_ctx, method, request, request_len, response);
}

static void privacyfilter_free_host_buffer(cliproxy_host_api* api, void* ptr, size_t len) {
	api->free_buffer(ptr, len);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

var privacyFilterABIState = struct {
	sync.RWMutex
	host           *C.cliproxy_host_api
	plugin         *privacyFilterPlugin
	runtime        *runtimeState
	shuttingDown   bool
	nativeInFlight sync.WaitGroup
	inFlight       sync.WaitGroup
}{}

const (
	// implementedSchemaVersion is the newest RPC contract this plugin uses.
	// Schema 2 adds active request termination and request.complete lifecycle
	// notifications while keeping later response-stream omission semantics out
	// of this request-only implementation.
	implementedSchemaVersion uint32 = 2
	legacySchemaVersion      uint32 = 1
	// tokenizeSchemaVersion is negotiated only in tokenize mode. From schema 3
	// the Host stops resending the request bodies, and from schema 5 the chunk
	// history, with every stream chunk; the stream interceptor needs neither.
	tokenizeSchemaVersion uint32 = 5

	// maxABIRequestBytes is checked before C.GoBytes duplicates the host payload.
	// Request bodies have their own tighter configurable limit at the walker.
	maxABIRequestBytes = C.size_t(64 << 20)

	nativeScanConcurrency   = 4
	nativeScanAdmissionWait = 100 * time.Millisecond
	nativeScanDeadline      = 10 * time.Second
)

var (
	errNativeScanAdmission = errors.New("privacyfilter: native scan admission unavailable")
	nativeScanSlots        = make(chan struct{}, nativeScanConcurrency)
)

type abiEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *abiError       `json:"error,omitempty"`
}

type abiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type abiLifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
	// PluginDir was never part of the v7.2.157 host payload. Keep accepting it
	// for test harnesses and legacy hosts; production falls back to dladdr.
	PluginDir string `json:"plugin_dir,omitempty"`
}

type abiRequestInterceptRequest struct {
	pluginapi.RequestInterceptRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiRegistration struct {
	SchemaVersion uint32             `json:"schema_version"`
	Metadata      pluginapi.Metadata `json:"metadata"`
	Capabilities  abiCapabilities    `json:"capabilities"`
}

type abiCapabilities struct {
	RequestInterceptor     bool `json:"request_interceptor"`
	RequestLifecyclePlugin bool `json:"request_lifecycle_plugin"`
	// The response hooks exist only in tokenize mode. They are omitted when
	// false so every other mode registers exactly as it did before.
	ResponseInterceptor    bool `json:"response_interceptor,omitempty"`
	StreamChunkInterceptor bool `json:"response_stream_interceptor,omitempty"`
}

func main() {}

func inferPluginDir() string {
	sharedObjectPath := sharedLibraryPath()
	if sharedObjectPath == "" {
		return ""
	}
	return filepath.Dir(sharedObjectPath)
}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if host == nil || plugin == nil {
		return 1
	}
	privacyFilterABIState.Lock()
	privacyFilterABIState.host = host
	privacyFilterABIState.shuttingDown = false
	privacyFilterABIState.Unlock()

	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.PrivacyFilterPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.PrivacyFilterPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.PrivacyFilterPluginShutdown)
	return 0
}

//export PrivacyFilterPluginCall
func PrivacyFilterPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) (result C.int) {
	result = 1
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	methodName := ""
	defer func() {
		if recover() == nil {
			return
		}
		if writeABIResponse(response, abiPanicEnvelope(methodName)) {
			result = 0
		}
	}()
	if method != nil {
		methodName = C.GoString(method)
	}

	if method == nil {
		return writeABIResult(response, abiErrorEnvelope("invalid_method", "method is required"))
	}
	if requestLen > maxABIRequestBytes {
		return writeABIResult(response, abiFailureEnvelope(
			methodName,
			http.StatusRequestEntityTooLarge,
			"request_too_large",
			"privacy filter request payload exceeds the native plugin limit",
		))
	}
	if requestLen > 0 && request == nil {
		return writeABIResult(response, abiFailureEnvelope(
			methodName,
			http.StatusServiceUnavailable,
			"invalid_request",
			"privacy filter received an invalid native request buffer",
		))
	}

	ctx := context.Background()
	cancel := func() {}
	if isRequestInterceptMethod(methodName) {
		done, errBegin := beginNativeScanCall()
		if errBegin != nil {
			return writeABIResult(response, abiFailureEnvelope(
				methodName,
				http.StatusServiceUnavailable,
				"plugin_unavailable",
				"privacy filter is not available for request inspection",
			))
		}
		defer done()

		ctx, cancel = context.WithTimeout(ctx, nativeScanDeadline)
		defer cancel()
		release, errAdmission := acquireNativeScan(ctx, nativeScanAdmissionWait)
		if errAdmission != nil {
			code := "privacy_filter_busy"
			message := "privacy filter scan capacity is temporarily unavailable"
			if errors.Is(errAdmission, context.DeadlineExceeded) {
				code = "privacy_filter_deadline"
				message = "privacy filter inspection deadline exceeded"
			}
			return writeABIResult(response, abiFailureEnvelope(
				methodName,
				http.StatusServiceUnavailable,
				code,
				message,
			))
		}
		defer release()
	}

	var requestBytes []byte
	if requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handlePrivacyFilterABIMethod(ctx, methodName, requestBytes)
	if isRequestInterceptMethod(methodName) && ctx.Err() != nil {
		return writeABIResult(response, abiFailureEnvelope(
			methodName,
			http.StatusServiceUnavailable,
			"privacy_filter_deadline",
			"privacy filter inspection deadline exceeded",
		))
	}
	if errHandle != nil {
		message := "privacy filter could not safely inspect the request"
		if methodName == pluginabi.MethodPluginRegister || methodName == pluginabi.MethodPluginReconfigure {
			// Lifecycle errors contain only configuration/rule diagnostics and are
			// needed by operators to correct a plugin that cannot start. Request
			// interceptor failures stay generic because they may be input-derived.
			message = errHandle.Error()
		}
		return writeABIResult(response, abiFailureEnvelope(
			methodName,
			http.StatusServiceUnavailable,
			"plugin_error",
			message,
		))
	}
	return writeABIResult(response, raw)
}

func isRequestInterceptMethod(method string) bool {
	return method == pluginabi.MethodRequestInterceptBefore || method == pluginabi.MethodRequestInterceptAfter
}

func acquireNativeScan(ctx context.Context, wait time.Duration) (func(), error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if wait <= 0 {
		select {
		case nativeScanSlots <- struct{}{}:
			return func() { <-nativeScanSlots }, nil
		default:
			return nil, errNativeScanAdmission
		}
	}

	timer := time.NewTimer(wait)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	select {
	case nativeScanSlots <- struct{}{}:
		return func() { <-nativeScanSlots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errNativeScanAdmission
	}
}

//export PrivacyFilterPluginFree
func PrivacyFilterPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export PrivacyFilterPluginShutdown
func PrivacyFilterPluginShutdown() {
	privacyFilterABIState.Lock()
	privacyFilterABIState.shuttingDown = true
	privacyFilterABIState.plugin = nil
	privacyFilterABIState.host = nil
	runtime := privacyFilterABIState.runtime
	privacyFilterABIState.Unlock()
	privacyFilterABIState.nativeInFlight.Wait()
	privacyFilterABIState.inFlight.Wait()
	if runtime != nil && runtime.cache != nil {
		runtime.cache.Clear()
	}
	runtime.loadedTokenRuntime().clear()
	privacyFilterABIState.Lock()
	if privacyFilterABIState.runtime == runtime {
		privacyFilterABIState.runtime = nil
	}
	privacyFilterABIState.Unlock()
}

func handlePrivacyFilterABIMethod(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return handlePrivacyFilterRegister(request)
	case pluginabi.MethodPluginQuiesce:
		return handlePrivacyFilterQuiesce()
	case pluginabi.MethodRequestComplete:
		return handlePrivacyFilterRequestComplete(ctx, request)
	}

	p, done, errPlugin := beginPrivacyFilterPluginCall()
	if errPlugin != nil {
		return nil, errPlugin
	}
	defer done()

	switch method {
	case pluginabi.MethodRequestInterceptBefore:
		var req abiRequestInterceptRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.InterceptRequestBeforeAuth(ctx, req.RequestInterceptRequest)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodRequestInterceptAfter:
		var req abiRequestInterceptRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.InterceptRequestAfterAuth(ctx, req.RequestInterceptRequest)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodResponseInterceptAfter:
		var req pluginapi.ResponseInterceptRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.InterceptResponse(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodResponseInterceptStreamChunk:
		var req pluginapi.StreamChunkInterceptRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.InterceptStreamChunk(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	default:
		return abiErrorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

// request.complete remains accepted while quiesced. It only touches the
// concurrency-safe runtime cache, so it cannot start new interceptor work or
// race plugin teardown, and late lifecycle notifications still release state.
func handlePrivacyFilterRequestComplete(_ context.Context, request []byte) ([]byte, error) {
	var req pluginapi.RequestCompletion
	if errDecode := json.Unmarshal(request, &req); errDecode != nil {
		return nil, errDecode
	}
	privacyFilterABIState.RLock()
	runtime := privacyFilterABIState.runtime
	privacyFilterABIState.RUnlock()
	if runtime != nil {
		releaseRequestScanState(runtime.cache, req)
		releaseRestoreSession(runtime.loadedTokenRuntime(), req)
	}
	return abiOKEnvelope(struct{}{})
}

func handlePrivacyFilterRegister(request []byte) ([]byte, error) {
	var req abiLifecycleRequest
	if errDecode := json.Unmarshal(request, &req); errDecode != nil {
		return nil, errDecode
	}
	privacyFilterABIState.Lock()
	if privacyFilterABIState.runtime == nil {
		privacyFilterABIState.runtime = newRuntimeState()
	}
	runtime := privacyFilterABIState.runtime
	privacyFilterABIState.Unlock()

	plugin, errBuild := buildPluginWithRuntime(req.ConfigYAML, req.PluginDir, runtime)
	if errBuild != nil {
		return nil, errBuild
	}
	p, ok := plugin.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	if !ok || p == nil {
		return nil, fmt.Errorf("privacyfilter plugin registration returned invalid interceptor")
	}
	wantSchema := implementedSchemaVersion
	if p.tok != nil {
		wantSchema = tokenizeSchemaVersion
	}
	negotiatedSchema := negotiateSchemaVersion(req.SchemaVersion, wantSchema)
	if negotiatedSchema < implementedSchemaVersion &&
		(p.cfg.OnError == onErrorBlock || len(p.blockRuleIDs) > 0) {
		return nil, fmt.Errorf("privacyfilter: fail-closed mode requires host schema %d or newer", implementedSchemaVersion)
	}
	plugin.SchemaVersion = negotiatedSchema
	if negotiatedSchema < implementedSchemaVersion {
		plugin.Capabilities.RequestLifecyclePlugin = nil
	}
	privacyFilterABIState.Lock()
	privacyFilterABIState.plugin = p
	privacyFilterABIState.shuttingDown = false
	privacyFilterABIState.Unlock()
	if p.tok == nil {
		// Leaving tokenize mode: the Host stops calling the response hooks, so
		// nothing can be restored anymore and the stored values must not linger.
		runtime.loadedTokenRuntime().clear()
	}
	log.WithFields(log.Fields{
		"version":  pluginVersion,
		"revision": pluginRevision,
	}).Info("privacyfilter plugin registered")
	if p.keyFilter.active() {
		log.WithFields(log.Fields{
			"mode":                string(p.cfg.KeyFilter.Mode),
			"identities":          len(p.keyFilter.scopes),
			"on_missing_identity": string(p.cfg.KeyFilter.OnMissingIdentity),
		}).Info("privacyfilter: key filter active")
	}
	if p.tok != nil {
		// The Host runs request and response interceptors in the same priority
		// order and does not tell a plugin about its neighbours, so the
		// operator has to check the ordering; say so on every registration.
		log.WithFields(log.Fields{
			"priority":      p.cfg.Priority,
			"schema":        negotiatedSchema,
			"restore_scope": string(p.cfg.Tokenize.RestoreScope),
		}).Warn("privacyfilter: tokenize is active; response interceptors that run after this plugin see restored values, and request interceptors that run before it see original values")
		if negotiatedSchema < tokenizeSchemaVersion {
			log.WithField("schema", negotiatedSchema).Warn("privacyfilter: Host schema is older than 5; every stream chunk carries the request body and chunk history")
		}
	}
	return abiOKEnvelope(abiRegistration{
		SchemaVersion: negotiatedSchema,
		Metadata:      plugin.Metadata,
		Capabilities: abiCapabilities{
			RequestInterceptor:     plugin.Capabilities.RequestInterceptor != nil,
			RequestLifecyclePlugin: plugin.Capabilities.RequestLifecyclePlugin != nil,
			ResponseInterceptor:    plugin.Capabilities.ResponseInterceptor != nil,
			StreamChunkInterceptor: plugin.Capabilities.StreamChunkInterceptor != nil,
		},
	})
}

// negotiateSchemaVersion returns the newest schema both sides support, where
// want is the newest one this configuration uses.
func negotiateSchemaVersion(hostSchema, want uint32) uint32 {
	if hostSchema == 0 {
		hostSchema = legacySchemaVersion
	}
	if hostSchema < want {
		return hostSchema
	}
	return want
}

func handlePrivacyFilterQuiesce() ([]byte, error) {
	privacyFilterABIState.Lock()
	privacyFilterABIState.shuttingDown = true
	privacyFilterABIState.Unlock()
	privacyFilterABIState.nativeInFlight.Wait()
	privacyFilterABIState.inFlight.Wait()
	return abiOKEnvelope(struct{}{})
}

func beginNativeScanCall() (func(), error) {
	privacyFilterABIState.Lock()
	defer privacyFilterABIState.Unlock()
	if privacyFilterABIState.shuttingDown {
		return nil, fmt.Errorf("privacyfilter plugin is shutting down")
	}
	if privacyFilterABIState.plugin == nil {
		return nil, fmt.Errorf("privacyfilter plugin is not registered")
	}
	privacyFilterABIState.nativeInFlight.Add(1)
	return privacyFilterABIState.nativeInFlight.Done, nil
}

func beginPrivacyFilterPluginCall() (*privacyFilterPlugin, func(), error) {
	privacyFilterABIState.Lock()
	defer privacyFilterABIState.Unlock()
	if privacyFilterABIState.shuttingDown {
		return nil, nil, fmt.Errorf("privacyfilter plugin is shutting down")
	}
	if privacyFilterABIState.plugin == nil {
		return nil, nil, fmt.Errorf("privacyfilter plugin is not registered")
	}
	privacyFilterABIState.inFlight.Add(1)
	return privacyFilterABIState.plugin, privacyFilterABIState.inFlight.Done, nil
}

func abiOKEnvelopeWithError(v any, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return abiOKEnvelope(v)
}

func abiOKEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(abiEnvelope{OK: true, Result: raw})
}

func abiErrorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(abiEnvelope{OK: false, Error: &abiError{Code: code, Message: message}})
	return raw
}

func abiPanicEnvelope(method string) []byte {
	return abiFailureEnvelope(
		method,
		http.StatusServiceUnavailable,
		"plugin_panic",
		"privacy filter recovered an internal panic and failed closed",
	)
}

func abiFailureEnvelope(method string, status int, code, message string) []byte {
	if method == pluginabi.MethodRequestInterceptBefore || method == pluginabi.MethodRequestInterceptAfter {
		body, _ := json.Marshal(map[string]any{
			"error": map[string]string{
				"type":    code,
				"message": message,
			},
		})
		raw, err := abiOKEnvelope(pluginapi.RequestInterceptResponse{
			Terminate:       true,
			StatusCode:      status,
			ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
			ResponseBody:    body,
		})
		if err == nil {
			return raw
		}
	}
	return abiErrorEnvelope(code, message)
}

func writeABIResult(response *C.cliproxy_buffer, raw []byte) C.int {
	if !writeABIResponse(response, raw) {
		return 1
	}
	return 0
}

func writeABIResponse(response *C.cliproxy_buffer, raw []byte) bool {
	if response == nil || len(raw) == 0 {
		return false
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return false
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
	return true
}
