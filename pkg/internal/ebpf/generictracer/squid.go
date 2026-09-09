// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

const squidActivationSymbol = "_ZN13ConnStateData5startEv"

type squidActivation struct {
	executables *ebpf.Map
	key         BpfSquidExecutableKeyT
	once        sync.Once
	err         error
}

func (a *squidActivation) Close() error {
	a.once.Do(func() {
		err := a.executables.Delete(a.key)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			err = nil
		}
		a.err = errors.Join(err, a.executables.Close())
	})
	return a.err
}

func squidExecutableKey(path string) (BpfSquidExecutableKeyT, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return BpfSquidExecutableKeyT{}, fmt.Errorf("inspecting Squid executable: %w", err)
	}
	return BpfSquidExecutableKeyT{
		Inode: stat.Ino,
		Dev:   unix.Major(stat.Dev)<<20 | unix.Minor(stat.Dev),
	}, nil
}

func (p *Tracer) ActivateUProbeGroup(path string, probes map[string][]*ebpfcommon.ProbeDesc) (io.Closer, error) {
	if _, squid := probes[squidActivationSymbol]; !squid {
		return nil, nil
	}
	key, err := squidExecutableKey(path)
	if err != nil {
		return nil, err
	}
	if p.bpfObjects.SquidExecutables == nil {
		return nil, errors.New("Squid executable activation map is unavailable")
	}
	executables, err := p.bpfObjects.SquidExecutables.Clone()
	if err != nil {
		return nil, fmt.Errorf("cloning Squid executable activation map: %w", err)
	}
	if err := executables.Put(key, ebpfcommon.NewRuntimeMetricGeneration()); err != nil {
		_ = executables.Close()
		return nil, fmt.Errorf("activating Squid executable: %w", err)
	}
	return &squidActivation{executables: executables, key: key}, nil
}

func (p *Tracer) squidProbes() map[string][]*ebpfcommon.ProbeDesc {
	probes := map[string][]*ebpfcommon.ProbeDesc{
		squidActivationSymbol: {{Start: p.bpfObjects.ObiSquidConnectionStart}},
		"_ZN13ConnStateData15afterClientReadEv": {{
			Start: p.bpfObjects.ObiSquidAfterRead,
			End:   p.bpfObjects.ObiSquidAfterReadRet,
		}},
		"_Z7fd_noteiPKc": {{Start: p.bpfObjects.ObiSquidFdNote}},
		"_ZN17ClientHttpRequestC1EP13ConnStateData":            {{Start: p.bpfObjects.ObiSquidClientRequest}},
		"_ZN17ClientHttpRequest13assignRequestEP11HttpRequest": {{Start: p.bpfObjects.ObiSquidAssignRequest}},
		"_ZN17ClientHttpRequest12clearRequestEv":               {{Start: p.bpfObjects.ObiSquidClearRequest}},
		"_ZN11HttpRequestC1ERK8RefCountI13MasterXactionE":      {{Start: p.bpfObjects.ObiSquidRequestReset}},
		"_ZN11HttpRequestC1ERK17HttpRequestMethodN4AnyP12ProtocolTypeEPKcS6_RK8RefCountI13MasterXactionE": {{
			Start: p.bpfObjects.ObiSquidRequestReset,
		}},
		"_ZN11HttpRequestD1Ev": {{Start: p.bpfObjects.ObiSquidRequestReset}},
		"_ZN11HttpRequestD2Ev": {{Start: p.bpfObjects.ObiSquidRequestReset}},
		"_ZN8FwdStateC1ERK8RefCountIN4Comm10ConnectionEEP10StoreEntryP11HttpRequestRKS0_I14AccessLogEntryE": {{
			Start: p.bpfObjects.ObiSquidForward,
		}},
		"_ZN13HttpStateDataC1EP8FwdState": {{
			Start: p.bpfObjects.ObiSquidHttp,
			End:   p.bpfObjects.ObiSquidHttpRet,
		}},
		"_Z22comm_add_close_handleriR8RefCountI9AsyncCallE": {{Start: p.bpfObjects.ObiSquidAddCloseHandler}},
		"_ZN13ConnStateDataD1Ev":                            {{Start: p.bpfObjects.ObiSquidConnectionDestroy}},
		"_ZN13ConnStateDataD2Ev":                            {{Start: p.bpfObjects.ObiSquidConnectionDestroy}},
		"_ZN17ClientHttpRequestD1Ev":                        {{Start: p.bpfObjects.ObiSquidClientDestroy}},
		"_ZN8FwdStateD1Ev":                                  {{Start: p.bpfObjects.ObiSquidForwardDestroy}},
		"_ZN13HttpStateDataD1Ev":                            {{Start: p.bpfObjects.ObiSquidHttpDestroy}},
	}
	// The loader rolls back this group if any lifecycle probe fails to attach.
	for _, descriptions := range probes {
		for _, probe := range descriptions {
			probe.Required = true
		}
	}
	return probes
}
