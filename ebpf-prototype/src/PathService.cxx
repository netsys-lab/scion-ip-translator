#include <cstddef>
#include <cstring>
#include <endian.h>
#include <iostream>
#include <memory>
#include <snet/snet.hpp>
#include <snet/snet_cdefs.h>

#include "bpf.h"
#include "libbpf.h"

#include "bpf/scion_types.h"
#include "bpf/scion.h"

#include "PathService.hxx"

using namespace std::chrono_literals;
using namespace scion;

// TODO implement TrafficClasses
//
//enum TrafficClass {
//  DefaultForwarding = 0b0,
//};
//
//const TrafficClass TrafficClasses[] = {DefaultForwarding};

/// Converts a Path object to path_map_entry for insertion to a BPF map
///
/// Returns a pointer to a dynamically allocated path_map_entry struct
static std::unique_ptr<struct path_map_entry> pathToMapEntry(Path &path)
{
	auto entry = std::make_unique<struct path_map_entry>();

	std::uint8_t headerLength = (sizeof(struct scionhdr) + (2 * 16) + path.dp.size()) / 4;

	// Common header
	entry->header = {
		.ver_qos_flow = 0, // set by BPF
		.next = 0, // set by BPF
		.len = headerLength,
		.payload = 0, // set by BPF
    .type = SC_PATH_TYPE_SCION,
		.haddr = 0, // set by BPF
		.rsv = 0, // set by BPF
		.dst = { htobe64(path.dst) },
		.src = { htobe64(path.src) },
	};

  // Intra Domain routing may have Empty path type
  // TODO OneHop?
  if(path.dp.empty()) {
    entry->header.type = SC_PATH_TYPE_EMPTY;
  }

	SC_SET_DT(&entry->header, SC_ADDR_TYPE_IP);
	SC_SET_DL(&entry->header, 0x3);
	SC_SET_ST(&entry->header, SC_ADDR_TYPE_IP);
	SC_SET_SL(&entry->header, 0x3);

	// Path Meta header and following fields
	std::memcpy(entry->path, path.dp.data(), path.dp.size());
	entry->path_len = path.dp.size() / 4;

	// Next Hop address
	std::memcpy(entry->router_addr, path.nextHop.getIPv6().data(), path.nextHop.getIPv6().size());
	entry->router_port = path.nextHop.getPort();

	return entry;
}

static int reqHandler(void *ctx, void *data, std::size_t data_sz)
{
  const auto ps = static_cast<PathService *>(ctx);
  const auto addr = *static_cast<std::uint32_t *>(data);

  auto paths = ps->getPaths(addr);
  ps->insertPaths(addr, paths);

  return 0;
}

PathService::PathService(struct bpf_map *pathCache, struct bpf_map *reqMap)
	: pathCache(pathCache)
{
  reqQueue = ring_buffer__new(bpf_map__fd(reqMap), reqHandler, this, NULL);
  if(!reqQueue) {
    // TODO should not have failable code in constructor
  }
}

void PathService::init(std::string &sciondAddr)
{
	Status status = hostCtx.init(sciondAddr.c_str(), 1s);
	if (status != Status::Success)
		throw std::runtime_error("Host context unitialization failed");
}

void PathService::run()
{
	//fillPathMap();

  while(true) {
    ring_buffer__poll(reqQueue, 100 /*ms*/);
  }
}

PathVec PathService::getPaths(std::uint32_t daddr)
{
	Status status;
	PathVec paths;

	IA dst{ (((std::uint64_t)daddr & 0xFFF00000) << 28) | (daddr & 0xFFFFF) };
	std::tie(paths, status) = hostCtx.queryPaths(dst, SC_FLAG_PATH_GET_IFACES, 100ms);
	if (status != Status::Success) {
		std::cerr << "No path for " << dst << " found (" << status << ")\n";
	}

	return paths;
}

void PathService::insertPaths(std::uint32_t addr, const scion::PathVec &paths)
{
  int err;
  //auto items = std::views::iota(0b0, 0b111111);
  if(paths.empty()) return;

    // TODO find best paths according to metric
    // for now we just use the first path
  //for(const auto &item : items) {
    //auto key = (addr << 8) | (item << 2);
    auto key = addr;
    auto path = pathToMapEntry(*paths[0]);

    err = bpf_map__update_elem(pathCache, &key, sizeof(key), path.get(), sizeof(*path), BPF_ANY);
    if(err < 0) {
      std::cerr << "Could not insert path to Path Cache\n";
    }
  //}
}

//void PathService::fillPathMap()
//{
//	// 16-64513-DCSP=0
//	// = fc10:fc01::\32
//	//std::uint32_t scion_addr = 0b0001'0000'1111'1100'0000'0001'0000'0000;
//	// 16-0:0:3
//  // clang-format off
//	std::uint32_t scion_addr = 0b0001'0000'0000'0000'0000'0011'0000'0000;
//  // clang-format on
//
//  auto paths = getPaths(scion_addr);
//	if (paths.empty()) {
//		return;
//	}
//	auto path = pathToMapEntry(*paths[0]);
//
//	bpf_map__update_elem(pathCache, &scion_addr, sizeof(scion_addr), path.get(), sizeof(*path), BPF_ANY);
//}
