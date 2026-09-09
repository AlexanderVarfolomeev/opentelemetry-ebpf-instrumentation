// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/preempt_guard.h>
#include <common/sockaddr.h>
#include <common/squid.h>
#include <pid/pid.h>

static __always_inline squid_call_scope_t *squid_scope(void) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return NULL;
    }
    const u64 start = squid_process_start();
    if (!start) {
        return NULL;
    }
    const u64 activation = squid_activation();
    if (!activation) {
        return NULL;
    }
    squid_call_scope_t *scope = bpf_map_lookup_elem(&squid_call_scopes, &id);
    if (!scope || scope->process_start != start || scope->activation != activation) {
        const squid_call_scope_t empty = {.process_start = start, .activation = activation};
        if (bpf_map_update_elem(&squid_call_scopes, &id, &empty, BPF_ANY)) {
            return NULL;
        }
        scope = bpf_map_lookup_elem(&squid_call_scopes, &id);
    }
    return scope;
}

static __always_inline bool squid_fd_connection(s32 fd, pid_connection_info_t *connection) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    const struct fdtable *table = BPF_CORE_READ(task, files, fdt);
    if (fd < 0 || (u32)fd >= BPF_CORE_READ(table, max_fds)) {
        return false;
    }
    struct file **files = BPF_CORE_READ(table, fd);
    struct file *file = NULL;
    bpf_probe_read_kernel(&file, sizeof(file), &files[fd]);
    if (!file || (BPF_CORE_READ(file, f_inode, i_mode) & 0170000) != 0140000) {
        return false;
    }
    const struct socket *socket = BPF_CORE_READ(file, private_data);
    struct sock *sk = BPF_CORE_READ(socket, sk);
    if (!sk || !parse_sock_info(sk, &connection->conn)) {
        return false;
    }
    connection->pid = bpf_get_current_pid_tgid() >> 32;
    sort_connection_info(&connection->conn);
    return true;
}

SEC("uprobe/squid_connection_start")
int GUARDED_PROG(obi_squid_connection_start, struct pt_regs *, ctx) {
    if (squid_scope()) {
        const squid_object_key_t key = squid_key(PT_REGS_PARM1(ctx), k_squid_connection);
        const squid_context_t context = {
            .address = key.address,
            .generation = bpf_ktime_get_ns(),
        };
        bpf_map_delete_elem(&squid_objects, &key);
        bpf_map_update_elem(&squid_objects, &key, &context, BPF_ANY);
    }
    return 0;
}

SEC("uprobe/squid_after_read")
int GUARDED_PROG(obi_squid_after_read, struct pt_regs *, ctx) {
    squid_call_scope_t *scope = squid_scope();
    if (scope) {
        scope->reading = PT_REGS_PARM1(ctx);
    }
    return 0;
}

SEC("uretprobe/squid_after_read")
int GUARDED_PROG(obi_squid_after_read_ret, struct pt_regs *, ctx) {
    (void)ctx;
    squid_call_scope_t *scope = squid_scope();
    if (scope) {
        scope->reading = 0;
    }
    return 0;
}

SEC("uprobe/squid_fd_note")
int GUARDED_PROG(obi_squid_fd_note, struct pt_regs *, ctx) {
    squid_call_scope_t *scope = squid_scope();
    if (!scope || !scope->reading) {
        return 0;
    }
    char note[21] = {0};
    bpf_probe_read_user(note, sizeof(note), (void *)PT_REGS_PARM2(ctx));
    if (bpf_memcmp(note, "Reading next request", 20) != 0) {
        return 0;
    }
    const squid_object_key_t key = squid_key(scope->reading, k_squid_connection);
    // Without a connection birth or continuous state, an old ongoing_http
    // entry must not be claimed by the first request seen after warm attachment.
    squid_context_t context = {.address = scope->reading, .generation = bpf_ktime_get_ns()};
    if (!squid_fd_connection(PT_REGS_PARM1(ctx), &context.connection)) {
        bpf_map_delete_elem(&squid_objects, &key);
        return 0;
    }
    const squid_context_t *previous = bpf_map_lookup_elem(&squid_objects, &key);
    if (previous && previous->address == context.address &&
        (!previous->connection.pid ||
         bpf_memcmp(&previous->connection, &context.connection, sizeof(context.connection)) == 0)) {
        context.parent = previous->parent;
        context.generation = previous->generation;
    }
    bpf_map_delete_elem(&squid_objects, &key);
    bpf_map_update_elem(&squid_objects, &key, &context, BPF_ANY);
    return 0;
}

SEC("uprobe/squid_client_request")
int GUARDED_PROG(obi_squid_client_request, struct pt_regs *, ctx) {
    if (valid_pid(bpf_get_current_pid_tgid())) {
        squid_claim_request(PT_REGS_PARM2(ctx), PT_REGS_PARM1(ctx));
    }
    return 0;
}

SEC("uprobe/squid_assign_request")
int GUARDED_PROG(obi_squid_assign_request, struct pt_regs *, ctx) {
    if (valid_pid(bpf_get_current_pid_tgid())) {
        squid_copy_request(
            PT_REGS_PARM1(ctx), k_squid_client_request, PT_REGS_PARM2(ctx), k_squid_request);
        const squid_object_key_t key = squid_key(PT_REGS_PARM1(ctx), k_squid_client_request);
        squid_context_t *client = bpf_map_lookup_elem(&squid_objects, &key);
        if (client) {
            client->request = PT_REGS_PARM2(ctx);
        }
    }
    return 0;
}

SEC("uprobe/squid_clear_request")
int GUARDED_PROG(obi_squid_clear_request, struct pt_regs *, ctx) {
    const squid_object_key_t key = squid_key(PT_REGS_PARM1(ctx), k_squid_client_request);
    squid_context_t *client = bpf_map_lookup_elem(&squid_objects, &key);
    if (client && client->request) {
        squid_clear_object(client->request, k_squid_request);
        client->request = 0;
    }
    return 0;
}

SEC("uprobe/squid_forward")
int GUARDED_PROG(obi_squid_forward, struct pt_regs *, ctx) {
    if (valid_pid(bpf_get_current_pid_tgid())) {
        squid_copy_request(
            PT_REGS_PARM4(ctx), k_squid_request, PT_REGS_PARM1(ctx), k_squid_forward);
    }
    return 0;
}

SEC("uprobe/squid_request_reset")
int GUARDED_PROG(obi_squid_request_reset, struct pt_regs *, ctx) {
    squid_clear_object(PT_REGS_PARM1(ctx), k_squid_request);
    return 0;
}

SEC("uprobe/squid_http")
int GUARDED_PROG(obi_squid_http, struct pt_regs *, ctx) {
    squid_call_scope_t *scope = squid_scope();
    if (scope) {
        const u64 http = PT_REGS_PARM1(ctx);
        squid_copy_request(PT_REGS_PARM2(ctx), k_squid_forward, http, k_squid_http);
        scope->constructing_http = http;
    }
    return 0;
}

SEC("uretprobe/squid_http")
int GUARDED_PROG(obi_squid_http_ret, struct pt_regs *, ctx) {
    (void)ctx;
    squid_call_scope_t *scope = squid_scope();
    if (scope) {
        scope->constructing_http = 0;
    }
    return 0;
}

SEC("uprobe/squid_add_close_handler")
int GUARDED_PROG(obi_squid_add_close_handler, struct pt_regs *, ctx) {
    squid_call_scope_t *scope = squid_scope();
    if (!scope || !scope->constructing_http) {
        return 0;
    }
    squid_connection_key_t key = {
        .process_start = scope->process_start,
        .activation = scope->activation,
    };
    if (!squid_fd_connection(PT_REGS_PARM1(ctx), &key.connection)) {
        return 0;
    }
    const squid_object_key_t object = squid_key(scope->constructing_http, k_squid_http);
    const squid_context_t *http = bpf_map_lookup_elem(&squid_objects, &object);
    squid_request_ref_t ref = {.address = scope->constructing_http};
    if (http) {
        ref.generation = http->generation;
    }
    bpf_map_delete_elem(&squid_outgoing, &key);
    bpf_map_update_elem(&squid_outgoing, &key, &ref, BPF_ANY);
    return 0;
}

SEC("uprobe/squid_connection_destroy")
int GUARDED_PROG(obi_squid_connection_destroy, struct pt_regs *, ctx) {
    squid_clear_object(PT_REGS_PARM1(ctx), k_squid_connection);
    return 0;
}

SEC("uprobe/squid_client_destroy")
int GUARDED_PROG(obi_squid_client_destroy, struct pt_regs *, ctx) {
    squid_clear_object(PT_REGS_PARM1(ctx), k_squid_client_request);
    return 0;
}

SEC("uprobe/squid_forward_destroy")
int GUARDED_PROG(obi_squid_forward_destroy, struct pt_regs *, ctx) {
    squid_clear_object(PT_REGS_PARM1(ctx), k_squid_forward);
    return 0;
}

SEC("uprobe/squid_http_destroy")
int GUARDED_PROG(obi_squid_http_destroy, struct pt_regs *, ctx) {
    squid_clear_object(PT_REGS_PARM1(ctx), k_squid_http);
    return 0;
}
