// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google, LLC and affiliates. */
#include <test_progs.h>

#include "bpf_memcg_charge.skel.h"

static void do_some_charging(void)
{
	size_t size = 100 * 1024 * 1024;
	char *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (!ASSERT_OK(ptr == MAP_FAILED)) {
	    return;
	}

	for (size_t i = 0; i < size; i += 4096) {
	    ptr[i] = 1;
	}

}

static void fallback(void)
{
	static struct bpf_memcg_charge *skel;
	static struct bpf_link *link;

	skel = bpf_memcg_charge__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_memcg_charge_open_and_load"))
		return;

	link = bpf_map__attach_struct_ops(skel->all_root);
	ASSERT_OK_PTR(link, "attach_test_mod_1");
	if (!link)
		return -1;

	do_some_charging();


	munmap(ptr, size);
	bpf_memcg_charge__destroy(skel);
}

void test_bpf_memcg_charge(void)
{
	if (test__start_subtest("fallback"))
		fallback();
	if (test__start_subtest("root"))
		root_cg();
}
