#pragma once

#include <memory>
#include <string>

#include "egress.skel.h"

/// EgressLoader manages the loading and attachment of the egress BPF (TC) program
class EgressLoader {
    public:
	EgressLoader();
	~EgressLoader();

	/// Attaches bpf programs to the specified interface
	void attach(const std::string &interface);
	void attach(const unsigned int interfaceIndex);

	/// Returns a pointer to the Path Cache bpf map
	struct bpf_map *pathMap();
  /// Returns a pointer to the Request Queue bpf_map
  struct bpf_map *requestQueue();

    private:
	/// Embedded object code of egress BPF program
	struct egress_bpf *tc_skel;

	/// TC hook to attach the BPF program to
	std::shared_ptr<struct bpf_tc_hook> tc_hook;
	/// TC options of the attached interface
	std::shared_ptr<struct bpf_tc_opts> tc_opts;

	/// Required for proper cleanup
	bool hook_created = false;
};
