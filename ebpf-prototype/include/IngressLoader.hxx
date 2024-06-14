#pragma once

#include <string>

#include "ingress.skel.h"

/// IngressLoader manages the loading and attachment of the Ingress BPF (XDP) program
class IngressLoader {
    public:
	IngressLoader();
	~IngressLoader();

	/// Attaches bpf programs to the specified interface
	void attach(const std::string &interface);
	void attach(const unsigned int interfaceIndex);

    private:
	/// Embedded object code of ingress BPF program
	struct ingress_bpf *xdp_skel;
};
