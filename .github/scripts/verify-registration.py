#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import argparse
import ctypes
import json
from pathlib import Path

PLUGIN_ID = "privacyfilter"
REPOSITORY = "https://github.com/ahoo/cpa-plugin-privacyfilter"
MAX_RESPONSE_BYTES = 8 << 20


class Buffer(ctypes.Structure):
    _fields_ = [("ptr", ctypes.c_void_p), ("len", ctypes.c_size_t)]


HostCall = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(Buffer),
)
HostFree = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)
PluginCall = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(Buffer),
)
PluginFree = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)
PluginShutdown = ctypes.CFUNCTYPE(None)


class HostAPI(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("host_ctx", ctypes.c_void_p),
        ("call", HostCall),
        ("free_buffer", HostFree),
    ]


class PluginAPI(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("call", PluginCall),
        ("free_buffer", PluginFree),
        ("shutdown", PluginShutdown),
    ]


def load_functions(path: Path):
    library = ctypes.CDLL(str(path.resolve()))
    for symbol in (
        "cliproxy_plugin_init",
        "PrivacyFilterPluginCall",
        "PrivacyFilterPluginFree",
        "PrivacyFilterPluginShutdown",
    ):
        getattr(library, symbol)

    def host_call(_context, _method, _request, _request_len, response):
        if response:
            response.contents.ptr = None
            response.contents.len = 0
        return 1

    def host_free(_pointer, _length):
        return None

    host_call_callback = HostCall(host_call)
    host_free_callback = HostFree(host_free)
    host = HostAPI(1, None, host_call_callback, host_free_callback)
    plugin = PluginAPI()

    initialize = library.cliproxy_plugin_init
    initialize.argtypes = [ctypes.POINTER(HostAPI), ctypes.POINTER(PluginAPI)]
    initialize.restype = ctypes.c_int
    if initialize(ctypes.byref(host), ctypes.byref(plugin)) != 0:
        raise SystemExit("native plugin initialization failed")
    if plugin.abi_version != 1 or not plugin.call or not plugin.free_buffer or not plugin.shutdown:
        raise SystemExit("native plugin ABI table mismatch")

    # Keep the Host table and Python callbacks alive until plugin.shutdown.
    native_state = (host, host_call_callback, host_free_callback)
    return library, plugin, native_state


def invoke(call, free, method: str, payload: bytes = b""):
    request = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload) if payload else None
    response = Buffer()
    status = call(method.encode(), request, len(payload), ctypes.byref(response))
    if not response.ptr or response.len == 0 or response.len > MAX_RESPONSE_BYTES:
        raise SystemExit(f"{method} returned invalid response ownership metadata")
    try:
        data = ctypes.string_at(response.ptr, response.len)
    finally:
        free(response.ptr, response.len)
    try:
        return status, json.loads(data)
    except json.JSONDecodeError as error:
        raise SystemExit(f"{method} returned invalid JSON") from error


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()

    _library, plugin, _native_state = load_functions(args.library)
    try:
        request = json.dumps(
            {"config_yaml": None, "schema_version": 2, "plugin_dir": ""},
            separators=(",", ":"),
        ).encode()
        status, envelope = invoke(plugin.call, plugin.free_buffer, "plugin.register", request)
        if status != 0 or envelope.get("ok") is not True:
            error = envelope.get("error")
            code = error.get("code", "missing") if isinstance(error, dict) else "missing"
            message = error.get("message", "missing") if isinstance(error, dict) else "missing"
            detail = " ".join(str(message).split())[:512]
            raise SystemExit(f"registration failed: status={status} code={code} message={detail}")
        registration = envelope.get("result", {})
        metadata = registration.get("metadata", {})
        require(registration.get("schema_version") == 2, "RPC schema negotiation mismatch")
        require(metadata.get("Name") == PLUGIN_ID, "plugin name mismatch")
        require(metadata.get("Version") == args.version, "plugin version mismatch")
        require(metadata.get("Author") == "ahoo (fork of rheodev)", "plugin author mismatch")
        require(metadata.get("GitHubRepository") == REPOSITORY, "plugin repository mismatch")
        config_fields = metadata.get("ConfigFields")
        require(isinstance(config_fields, list) and len(config_fields) == 12, "config field metadata mismatch")
        capabilities = registration.get("capabilities", {})
        require(
            capabilities
            == {"request_interceptor": True, "request_lifecycle_plugin": True},
            "plugin capability mismatch",
        )

        empty_request = json.dumps(
            {"RequestID": "registration-check", "SourceFormat": "openai", "Body": None},
            separators=(",", ":"),
        ).encode()
        status, envelope = invoke(plugin.call, plugin.free_buffer, "request.intercept_before", empty_request)
        result = envelope.get("result", {})
        require(status == 0 and envelope.get("ok") is True, "interceptor transport envelope mismatch")
        require(result.get("Terminate") is True and result.get("StatusCode") == 400, "active termination mismatch")

        status, envelope = invoke(
            plugin.call,
            plugin.free_buffer,
            "request.complete",
            b'{"RequestID":"registration-check"}',
        )
        require(status == 0 and envelope.get("ok") is True, "request completion failed")
    finally:
        plugin.shutdown()

    print(f"verified {PLUGIN_ID} {args.version}, ABI 1, schema 2, capabilities, and active termination")


if __name__ == "__main__":
    main()
