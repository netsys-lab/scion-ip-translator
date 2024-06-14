#ifndef PATH_SERVICE_HXX_GUARD_
#define PATH_SERVICE_HXX_GUARD_

#include <cstdint>
#include <string>

#include <snet/snet.hpp>
#include "bpf.h"

/// The PathService is responsible for the management of the Path Cache.
///
/// It is listening for new path requests and populates the Path Cache accordingly.
///
/// Example:
/// ```cpp
/// struct bpf_map *map = /*...*/;
///
/// PathService ps(map);
/// ps.init("127.0.0.1:50010"):
/// ps.run();
/// ```
class PathService {
    public:
	PathService(struct bpf_map *pathCache, struct bpf_map *reqMap);

	/// Initialize the PathService
	///
	/// Throws if Host Context cannot be initialized (e.g. daemon not reachable)
	void init(std::string &sciondAddr);

	/// Run the Path Service
	///
	/// This is a blocking call, listening for new path requests
	void run();

	/// Retrieve paths for specified destination address
	///
	/// TODO
	///
	scion::PathVec getPaths(std::uint32_t daddr);

  /// Insert paths for given address
  ///
  /// TODO
  ///
  void insertPaths(std::uint32_t addr, const scion::PathVec &paths);

	/// Pre-populate path cache with hardcoded values
	///
	/// NOTE: Only used for the evaluation.
	/// FIXME: Remove this, once the update and recirculation mechanism is implemented.
	///
	//void fillPathMap();

    private:
	// Map representing the path cache
	struct bpf_map *pathCache;
  // Ring buffer for obtaining path requests
  struct ring_buffer *reqQueue;
	// host context for communication with daemon.
	// for a daemonless version we can remove this in favor of calls directly to the path server using gRPC.
	scion::HostCtx hostCtx;
};

#endif // PATH_SERVICE_HXX_GUARD_
