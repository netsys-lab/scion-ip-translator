#include <cstring>
#include <iostream>
#include <memory>
#include <net/if.h>
#include <stdexcept>
#include <string>

#include "libbpf.h"
#include "EgressLoader.hxx"

EgressLoader::EgressLoader()
	: tc_hook(std::make_shared<struct bpf_tc_hook>())
	, tc_opts(std::make_shared<struct bpf_tc_opts>())
{
	// libbpf encourages its structs to be declared with these macros
	// to provide upwards and downwards compatibility.
	LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);

	std::memcpy(this->tc_hook.get(), &tc_hook, sizeof(struct bpf_tc_hook));
	std::memcpy(this->tc_opts.get(), &tc_opts, sizeof(struct bpf_tc_opts));
}

EgressLoader::~EgressLoader()
{
	int err;

	// Detach TC hook on exit
	tc_opts->flags = tc_opts->prog_fd = tc_opts->prog_id = 0;
	if ((err = bpf_tc_detach(tc_hook.get(), tc_opts.get()))) {
		std::cerr << "Failed to detach TC: " << err << "\n";
	}

	if (tc_skel)
		egress_bpf__destroy(tc_skel);
	if (hook_created)
		bpf_tc_hook_destroy(tc_hook.get());
}

void EgressLoader::attach(const std::string &interface)
{
	auto index = if_nametoindex(interface.c_str());
	if (index == 0) {
		throw std::invalid_argument("Invalid interface index");
	}

	this->attach(index);
}

void EgressLoader::attach(const unsigned int interfaceIndex)
{
	int err;

	tc_hook->ifindex = interfaceIndex;

	// Load bpf object code
	tc_skel = egress_bpf__open_and_load();
	if (!tc_skel) {
		std::cerr << "Failed to open BPF skeleton\n";
		throw std::runtime_error("Egress program load");
	}

	// Create TC hook
	err = bpf_tc_hook_create(tc_hook.get());
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		std::cerr << "Failed to create TC hook: " << strerror(err) << "\n";
		throw std::runtime_error("Egress hook creation");
	}

	// Attach bpf program to TC hook
	tc_opts->prog_fd = bpf_program__fd(tc_skel->progs.scion_egress);
	err = bpf_tc_attach(tc_hook.get(), tc_opts.get());
	if (err) {
		std::cerr << "Failed to attach TC: " << strerror(err) << "\n";
		throw std::runtime_error("Egress attachment");
	}
}

struct bpf_map *EgressLoader::pathMap()
{
	struct bpf_map *pathMap = bpf_object__find_map_by_name(tc_skel->obj, "path_map");
	if (!pathMap) {
		std::cerr << "Could not get path map: " << strerror(errno) << "\n";
		throw std::runtime_error("Path Map open");
	}
	return pathMap;
}

struct bpf_map *EgressLoader::requestQueue()
{
  return tc_skel->maps.path_req;
}
