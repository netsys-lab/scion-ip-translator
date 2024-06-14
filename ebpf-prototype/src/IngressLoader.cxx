#include <cstring>
#include <iostream>
#include <memory>
#include <net/if.h>
#include <stdexcept>
#include <string>

#include "libbpf.h"
#include "IngressLoader.hxx"

IngressLoader::IngressLoader()
{
}

IngressLoader::~IngressLoader()
{
	if (xdp_skel)
		ingress_bpf__destroy(xdp_skel);
}

void IngressLoader::attach(const std::string &interface)
{
	auto index = if_nametoindex(interface.c_str());
	if (index == 0) {
		throw std::invalid_argument("Invalid interface index");
	}

	this->attach(index);
}

void IngressLoader::attach(const unsigned int interfaceIndex)
{
	xdp_skel = ingress_bpf__open_and_load();
	if (!xdp_skel) {
		std::cerr << "Failed to open ingress BPF skeleton\n";
		throw std::runtime_error("Ingress load error");
	}

	// Attach bpf program to interface
	if(!bpf_program__attach_xdp(xdp_skel->progs.scion_ingress, interfaceIndex)) {
    std::cerr << "Failed to attach eBPF program to XDP: " << strerror(errno) << "\n";
    throw std::runtime_error("Ingress attach error");
  }
}
