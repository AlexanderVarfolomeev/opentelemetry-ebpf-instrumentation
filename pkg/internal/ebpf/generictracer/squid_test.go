// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

func TestSquidActivationIgnoresUnrelatedProbes(t *testing.T) {
	tracer := &Tracer{}
	cleanup, err := tracer.ActivateUProbeGroup("/unavailable/executable", map[string][]*ebpfcommon.ProbeDesc{
		"SSL_read": {{Required: true}},
	})
	require.NoError(t, err)
	require.Nil(t, cleanup)
}

func TestSquidActivationRejectsUnavailableExecutable(t *testing.T) {
	tracer := &Tracer{}
	cleanup, err := tracer.ActivateUProbeGroup(filepath.Join(t.TempDir(), "missing"), map[string][]*ebpfcommon.ProbeDesc{
		squidActivationSymbol: {{Required: true}},
	})
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Nil(t, cleanup)
}

func TestSquidExecutableKeyUsesKernelDeviceEncoding(t *testing.T) {
	path := "/proc/self/exe"
	var stat unix.Stat_t
	require.NoError(t, unix.Stat(path, &stat))
	key, err := squidExecutableKey(path)
	require.NoError(t, err)
	require.Equal(t, stat.Ino, key.Inode)
	require.Equal(t, unix.Major(stat.Dev), key.Dev>>20)
	require.Equal(t, unix.Minor(stat.Dev), key.Dev&((1<<20)-1))
}
