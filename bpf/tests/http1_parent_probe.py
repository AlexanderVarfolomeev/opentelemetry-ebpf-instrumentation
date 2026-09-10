#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
"""Standalone regression probe for the HTTP/1 parent helpers.

Run: python3 bpf/tests/http1_parent_probe.py [path/to/tpinjector.c]
Requires a native C compiler (cc). Compiles the actual helper source with
minimal stubs; does not test kernel handoff or replace BPF integration tests.
This probe is run manually, not by the C-only bpf/tests Makefile.
"""

import pathlib
import subprocess
import sys
import tempfile


source_path = (
    pathlib.Path(sys.argv[1])
    if len(sys.argv) > 1
    else pathlib.Path(__file__).resolve().parents[1] / "tpinjector/tpinjector.c"
)
source = source_path.read_text()
start = source.index("static __always_inline bool apply_parent_tp(")
end = source.index("//k_tail_find_existing_tp", start)
functions = source[start:end].replace("__always_inline", "inline")

prefix = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define TRACE_ID_SIZE_BYTES 16
#define SPAN_ID_SIZE_BYTES 8
#define bpf_memcmp memcmp
#define bpf_memcpy memcpy
#define bpf_dbg_printk(...) ((void)0)
typedef struct {
    unsigned char trace_id[16], span_id[8], parent_id[8];
} tp_info_t;
typedef struct {
    bool has_parent_tp;
    tp_info_t parent_tp;
} tailcall_ctx;
static unsigned char generated;
static void urand_bytes(unsigned char *ptr, size_t size) {
    memset(ptr, ++generated, size);
}
static void encode_hex(unsigned char *out, const unsigned char *in, size_t size) {
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < size; ++i) {
        out[2*i] = hex[in[i] >> 4];
        out[2*i+1] = hex[in[i] & 15];
    }
}
"""

cases = r"""
static void check_wire(const unsigned char *wire, const tp_info_t *tp) {
    unsigned char expected[16];
    encode_hex(expected, tp->span_id, sizeof(tp->span_id));
    assert(memcmp(wire, expected, sizeof(expected)) == 0);
    assert(wire[16] == 0xff);
}
int main(void) {
    tailcall_ctx ctx = {0};
    tp_info_t incoming = {0};
    memset(incoming.trace_id, 0x11, 16);
    memset(incoming.span_id, 0xaa, 8);
    unsigned char wire[17];
    memset(wire, 0xff, sizeof(wire));
    encode_hex(wire, incoming.span_id, 8);

    tp_info_t tp = incoming;
    assign_parent_tp(&ctx, &tp, wire);
    assert(memcmp(tp.parent_id, incoming.span_id, 8) == 0);
    assert(memcmp(tp.span_id, incoming.span_id, 8) != 0);
    assert(memcmp(tp.trace_id, incoming.trace_id, 16) == 0);
    check_wire(wire, &tp);
    const tp_info_t first = tp;
    tp = incoming;
    assign_parent_tp(&ctx, &tp, wire);
    assert(memcmp(tp.span_id, first.span_id, 8) != 0);
    assert(memcmp(tp.parent_id, incoming.span_id, 8) == 0);
    check_wire(wire, &tp);

    ctx.has_parent_tp = true;
    memset(ctx.parent_tp.trace_id, 0x22, 16);
    memset(ctx.parent_tp.span_id, 0xbb, 8);
    memcpy(ctx.parent_tp.parent_id, incoming.span_id, 8);
    tp = incoming;
    assign_parent_tp(&ctx, &tp, wire);
    assert(memcmp(tp.parent_id, incoming.span_id, 8) == 0);
    assert(memcmp(tp.trace_id, incoming.trace_id, 16) == 0);
    check_wire(wire, &tp);

    memcpy(ctx.parent_tp.trace_id, incoming.trace_id, 16);
    tp = incoming;
    assign_parent_tp(&ctx, &tp, wire);
    assert(memcmp(tp.parent_id, ctx.parent_tp.span_id, 8) == 0);
    assert(memcmp(tp.span_id, incoming.span_id, 8) != 0);
    check_wire(wire, &tp);

    tp = incoming;
    memset(tp.span_id, 0xcc, 8);
    encode_hex(wire, tp.span_id, 8);
    const unsigned char previous_generated = generated;
    assign_parent_tp(&ctx, &tp, wire);
    assert(generated == previous_generated);
    assert(tp.span_id[0] == 0xcc);
    assert(memcmp(tp.parent_id, ctx.parent_tp.span_id, 8) == 0);
    check_wire(wire, &tp);

    ctx.has_parent_tp = false;
    tp = incoming;
    assert(!apply_parent_tp(&ctx, &tp));
    assert(memcmp(tp.span_id, incoming.span_id, 8) == 0);
    assert(generated == previous_generated);
    puts("PASS: missing/mismatched parent, repeated context, accepted parent, distinct application ID, wire encoding, HTTP/2 helper unchanged");
}
"""

with tempfile.TemporaryDirectory(prefix="obi-http1-probe-") as directory:
    binary = str(pathlib.Path(directory) / "probe")
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-x", "c", "-o", binary, "-"],
        input=prefix + functions + cases,
        text=True,
        check=True,
    )
    subprocess.run([binary], check=True)
