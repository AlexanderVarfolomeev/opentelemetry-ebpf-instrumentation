// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#undef SEC
#define SEC(name)
enum { BPF_ANY = 0 };
static unsigned long long process_start = 100;
static unsigned long long now = 1000;
static void *lookup(void *map, const void *key);
static long update(void *map, const void *key, const void *value, unsigned long long flags);
static long remove_key(void *map, const void *key);

#undef BPF_CORE_READ
#define BPF_CORE_READ(src, ...) ((void)(src), process_start)
#define bpf_get_current_task() 0
#define bpf_get_current_pid_tgid() ((42ULL << 32) | 42)
#define bpf_ktime_get_ns() (++now)
#define bpf_map_lookup_elem lookup
#define bpf_map_update_elem update
#define bpf_map_delete_elem remove_key
#include <common/squid.h>

enum { capacity = 16 };
static squid_object_key_t object_keys[capacity];
static squid_context_t objects[capacity];
static bool live[capacity];
static squid_connection_key_t outgoing_keys[2];
static squid_request_ref_t outgoing[2];
static pid_connection_info_t connections[2];
static http_info_t requests[2];
static tp_info_pid_t parent;
static unsigned long long activation = 1;
static bool outgoing_live[2] = {true, true};

static void *lookup(void *map, const void *key) {
    if (map == &squid_executables) {
        return &activation;
    }
    if (map == &squid_parent_storage) {
        return &parent;
    }
    if (map == &squid_objects) {
        for (unsigned int i = 0; i < capacity; ++i) {
            if (live[i] && memcmp(key, &object_keys[i], sizeof(object_keys[i])) == 0) {
                return &objects[i];
            }
        }
    }
    if (map == &ongoing_http) {
        for (unsigned int i = 0; i < 2; ++i) {
            if (memcmp(key, &connections[i], sizeof(connections[i])) == 0) {
                return &requests[i];
            }
        }
    }
    if (map == &squid_outgoing) {
        for (unsigned int i = 0; i < 2; ++i) {
            if (outgoing_live[i] && memcmp(key, &outgoing_keys[i], sizeof(outgoing_keys[i])) == 0) {
                return &outgoing[i];
            }
        }
    }
    return NULL;
}

static long update(void *map, const void *key, const void *value, unsigned long long flags) {
    assert(map == &squid_objects && flags == BPF_ANY);
    squid_context_t *existing = lookup(map, key);
    if (existing) {
        *existing = *(const squid_context_t *)value;
        return 0;
    }
    for (unsigned int i = 0; i < capacity; ++i) {
        if (!live[i]) {
            object_keys[i] = *(const squid_object_key_t *)key;
            objects[i] = *(const squid_context_t *)value;
            live[i] = true;
            return 0;
        }
    }
    return -12;
}

static long remove_key(void *map, const void *key) {
    assert(map == &squid_objects);
    for (unsigned int i = 0; i < capacity; ++i) {
        if (live[i] && memcmp(key, &object_keys[i], sizeof(object_keys[i])) == 0) {
            live[i] = false;
            return 0;
        }
    }
    return -2;
}

static void set_up(unsigned int i) {
    connections[i].pid = 42;
    connections[i].conn.s_port = 40000 + i;
    connections[i].conn.d_port = 3128;
    requests[i].type = k_event_type_http_request;
    requests[i].pid.host_pid = 42;
    requests[i].start_monotime_ns = 10 + i;
    requests[i].tp.ts = 10 + i;
    requests[i].tp.trace_id[0] = 1;
    requests[i].tp.parent_id[0] = 2; // Both requests forwarded exactly the same header.
    requests[i].tp.span_id[0] = 3 + i;
    const squid_object_key_t conn = squid_key(10 + i, k_squid_connection);
    const squid_context_t context = {
        .address = 10 + i, .connection = connections[i], .generation = 1};
    update(&squid_objects, &conn, &context, BPF_ANY);
    squid_claim_request(10 + i, 20 + i);
    squid_copy_request(20 + i, k_squid_client_request, 30 + i, k_squid_request);
    squid_copy_request(30 + i, k_squid_request, 40 + i, k_squid_forward);
    squid_copy_request(40 + i, k_squid_forward, 50 + i, k_squid_http);
    const squid_object_key_t http_key = squid_key(50 + i, k_squid_http);
    const squid_context_t *http = lookup(&squid_objects, &http_key);
    assert(http && http->parent.valid);
    outgoing_keys[i].connection = connections[i];
    outgoing_keys[i].connection.conn.d_port = 8080;
    outgoing_keys[i].process_start = process_start;
    outgoing_keys[i].activation = activation;
    outgoing[i] = (squid_request_ref_t){.address = 50 + i, .generation = http->generation};
}

int main(void) {
    set_up(0);
    set_up(1);
    assert(find_squid_parent_trace(&outgoing_keys[0].connection)->tp.span_id[0] == 3);
    assert(find_squid_parent_trace(&outgoing_keys[1].connection)->tp.span_id[0] == 4);

    // A streaming response does not destroy the owning Squid request.
    requests[0].status = 200;
    requests[0].end_monotime_ns = 100;
    assert(find_squid_parent_trace(&outgoing_keys[0].connection)->tp.span_id[0] == 3);

    // Another parsed request cannot claim the same observed SERVER again.
    squid_claim_request(11, 22);
    const squid_object_key_t extra = squid_key(22, k_squid_client_request);
    assert(!((squid_context_t *)lookup(&squid_objects, &extra))->parent.valid);

    // An old SERVER seen after warm attachment or connection eviction is not
    // evidence that the newly parsed request owns that SERVER.
    const squid_object_key_t conn = squid_key(11, k_squid_connection);
    squid_context_t *connection = lookup(&squid_objects, &conn);
    connection->generation = now;
    memset(&connection->parent, 0, sizeof(connection->parent));
    squid_claim_request(11, 22);
    assert(!((squid_context_t *)lookup(&squid_objects, &extra))->parent.valid);
    requests[1].tp.ts = ++now;
    squid_claim_request(11, 22);
    assert(((squid_context_t *)lookup(&squid_objects, &extra))->parent.valid);

    // PID reuse, destructor cleanup, eviction and object-address reuse do not
    // turn an old outgoing reference into the new request's parent.
    ++process_start;
    assert(!find_squid_parent_trace(&outgoing_keys[0].connection)->valid);
    --process_start;
    squid_clear_object(50, k_squid_http);
    assert(!find_squid_parent_trace(&outgoing_keys[0].connection)->valid);
    squid_copy_request(41, k_squid_forward, 50, k_squid_http);
    assert(!find_squid_parent_trace(&outgoing_keys[0].connection)->valid);
    squid_copy_request(999, k_squid_forward, 51, k_squid_http);
    assert(!find_squid_parent_trace(&outgoing_keys[1].connection)->valid);
    outgoing_live[1] = false;
    assert(!find_squid_parent_trace(&outgoing_keys[1].connection)->valid);
    activation = 0;
    assert(find_squid_parent_trace(&outgoing_keys[0].connection) == NULL);
    activation = 2;
    assert(!find_squid_parent_trace(&outgoing_keys[0].connection)->valid);
    puts("Squid request context checks passed");
    return 0;
}
