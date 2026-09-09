// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_builtins.h>

#include <common/event_defs.h>
#include <common/scratch_mem.h>
#include <maps/ongoing_http.h>
#include <maps/squid_context.h>

SCRATCH_MEM_TYPED(squid_parent, tp_info_pid_t);

static __always_inline u64 squid_activation(void) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    const struct inode *inode = (const struct inode *)BPF_CORE_READ(task, mm, exe_file, f_inode);
    const squid_executable_key_t key = {
        .inode = BPF_CORE_READ(inode, i_ino),
        .dev = BPF_CORE_READ(inode, i_sb, s_dev),
    };
    const u64 *generation = bpf_map_lookup_elem(&squid_executables, &key);
    return generation ? *generation : 0;
}

static __always_inline u64 squid_process_start(void) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, group_leader, start_time);
}

static __always_inline squid_object_key_t squid_key(u64 address, u32 kind) {
    return (squid_object_key_t){
        .address = address,
        .process_start = squid_process_start(),
        .activation = squid_activation(),
        .pid = bpf_get_current_pid_tgid() >> 32,
        .kind = kind,
    };
}

static __always_inline void squid_clear_object(u64 address, u32 kind) {
    const squid_object_key_t key = squid_key(address, kind);
    if (key.activation) {
        bpf_map_delete_elem(&squid_objects, &key);
    }
}

static __always_inline void
squid_copy_request(u64 source, u32 source_kind, u64 destination, u32 destination_kind) {
    const squid_object_key_t source_key = squid_key(source, source_kind);
    if (!source_key.activation) {
        return;
    }
    const squid_context_t *source_context = bpf_map_lookup_elem(&squid_objects, &source_key);
    squid_context_t context = {0};
    if (source_context && source_context->address == source) {
        context = *source_context;
    }
    context.address = destination;
    context.generation = bpf_ktime_get_ns();
    context.request = 0;
    const squid_object_key_t destination_key = squid_key(destination, destination_kind);
    // Constructors must clear stale state even when the new source is unknown
    // or allocating its replacement fails.
    bpf_map_delete_elem(&squid_objects, &destination_key);
    if (destination && destination_key.process_start) {
        bpf_map_update_elem(&squid_objects, &destination_key, &context, BPF_ANY);
    }
}

static __always_inline void squid_claim_request(u64 connection, u64 request) {
    const squid_object_key_t connection_key = squid_key(connection, k_squid_connection);
    if (!connection_key.activation) {
        return;
    }
    squid_context_t *connection_context = bpf_map_lookup_elem(&squid_objects, &connection_key);
    squid_context_t context = {.address = request, .generation = bpf_ktime_get_ns()};
    if (connection_context && connection_context->address == connection) {
        const http_info_t *server =
            bpf_map_lookup_elem(&ongoing_http, &connection_context->connection);
        if (server && server->type == k_event_type_http_request && server->start_monotime_ns &&
            !server->status && !server->submitted && server->tp.ts &&
            server->tp.ts >= connection_context->generation &&
            (server->tp.ts != connection_context->parent.tp.ts ||
             bpf_memcmp(server->tp.span_id,
                        connection_context->parent.tp.span_id,
                        SPAN_ID_SIZE_BYTES) != 0)) {
            context.parent.tp = server->tp;
            context.parent.pid = connection_key.pid;
            context.parent.req_type = k_event_type_http_request;
            context.parent.valid = 1;
            context.connection = connection_context->connection;
            // One observed SERVER cannot stand in for several parsed requests.
            connection_context->parent = context.parent;
        }
    }
    const squid_object_key_t request_key = squid_key(request, k_squid_client_request);
    bpf_map_delete_elem(&squid_objects, &request_key);
    if (request && request_key.process_start) {
        bpf_map_update_elem(&squid_objects, &request_key, &context, BPF_ANY);
    }
}

static __always_inline tp_info_pid_t *
find_squid_parent_trace(const pid_connection_info_t *connection) {
    const u64 start = squid_process_start();
    const u64 activation = squid_activation();
    if (!activation) {
        return NULL;
    }
    tp_info_pid_t *parent = (tp_info_pid_t *)squid_parent_mem();
    if (!parent) {
        return NULL;
    }
    bpf_memset(parent, 0, sizeof(*parent));
    const squid_connection_key_t key = {
        .connection = *connection,
        .process_start = start,
        .activation = activation,
    };
    const squid_request_ref_t *ref = bpf_map_lookup_elem(&squid_outgoing, &key);
    if (!ref) {
        return parent;
    }
    const squid_request_ref_t snapshot = *ref;
    const squid_object_key_t request_key = squid_key(snapshot.address, k_squid_http);
    const squid_context_t *request = bpf_map_lookup_elem(&squid_objects, &request_key);
    if (request && request->address == snapshot.address &&
        request->generation == snapshot.generation) {
        *parent = request->parent;
    }
    // A known Squid connection with lost request state must not use a thread parent.
    return parent;
}
