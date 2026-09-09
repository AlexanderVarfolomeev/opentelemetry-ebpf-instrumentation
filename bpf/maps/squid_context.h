// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

enum squid_object_kind {
    k_squid_connection,
    k_squid_client_request,
    k_squid_request,
    k_squid_forward,
    k_squid_http,
};

typedef struct squid_object_key {
    u64 address;
    u64 process_start;
    u64 activation;
    u32 pid;
    u32 kind;
} squid_object_key_t;

typedef struct squid_context {
    tp_info_pid_t parent;
    pid_connection_info_t connection;
    u64 generation;
    u64 address;
    u64 request;
} squid_context_t;

typedef struct squid_connection_key {
    pid_connection_info_t connection;
    u64 process_start;
    u64 activation;
} squid_connection_key_t;

typedef struct squid_request_ref {
    u64 address;
    u64 generation;
} squid_request_ref_t;

typedef struct squid_call_scope {
    u64 process_start;
    u64 activation;
    u64 reading;
    u64 constructing_http;
} squid_call_scope_t;

typedef struct squid_executable_key {
    u64 inode;
    u32 dev;
    u32 pad;
} squid_executable_key_t;

// Published only after the complete lifecycle probe group has attached.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, squid_executable_key_t);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} squid_executables SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, squid_object_key_t);
    __type(value, squid_context_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} squid_objects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, squid_connection_key_t);
    __type(value, squid_request_ref_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} squid_outgoing SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, squid_call_scope_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} squid_call_scopes SEC(".maps");
