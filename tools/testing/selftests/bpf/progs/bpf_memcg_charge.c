// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2024 Google LLC

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/cgroup

char _license[] SEC("license") = "GPL";

SEC("struct_ops/bpf_memcg_charge")
void *BPF_PROG(t_get_memcg_noop, struct folio *folio)
{
	bpf_printk("Accessed get_memcg");
	return NULL;
}

SEC(".struct_ops.link")
struct memcg_charge_ops no_ops = {
	.get_memcg = (void *)t_get_memcg_noop,
};

SEC("struct_ops/bpf_memcg_charge")
void *BPF_PROG(t_get_memcg_2, struct folio *folio)
{
	return bpf_get_root_cgroup();
}

SEC(".struct_ops.link")
struct memcg_charge_ops all_root = {
	.get_memcg = (void *)t_get_memcg_2,
};


