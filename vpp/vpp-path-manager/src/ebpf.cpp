// Copyright (c) 2024 Lars-Christian Schulz

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "config.hpp"

#include "ebpf.hpp"
#include "bpf.h"

#include <unistd.h>
#include <utility>

// File descriptor
class FD
{
private:
    int fd = -1;

public:
    FD() = default;
    FD(int fd) : fd(fd) {}

    FD(const FD& other) = delete;
    FD(FD&& other) noexcept
        : fd(std::exchange(other.fd, -1))
    {}

    FD& operator=(const FD& other) = delete;
    FD& operator=(FD&& other) noexcept
    {
        std::swap(fd, other.fd);
        return *this;
    }
    ~FD()
    {
        if (fd >= 0) close(fd);
    }

    operator bool() const { return fd >= 0; }
    int operator*() const { return fd; }

    int get() const { return fd; }
    int release() { return std::exchange(fd, -1); }
};

static const char* SCION_IP_MAP = "/sys/fs/bpf/scion_ip";
static FD scionIpMap;

static bool updateScionIpMap(const TranslatorConfig& config)
{
    if (!scionIpMap) return false;
    bpf_map_info info = {};
    unsigned int infoLen = sizeof(info);
    if (bpf_map_get_info_by_fd(*scionIpMap, &info, &infoLen) != 0) {
        return false;
    }

    uint32_t key = 0;
    std::array<uint8_t, 20> value = {};
    if (info.max_entries != 1 || info.key_size != sizeof(key) || info.value_size != sizeof(value)) {
        return false;
    }

    auto ipv4 = config.hostAddr4->address().to_bytes();
    auto i = std::copy(ipv4.begin(), ipv4.end(), value.begin());
    auto ipv6 = config.hostAddr.address().to_bytes();
    std::copy(ipv6.begin(), ipv6.end(), i);

    if (bpf_map_update_elem(*scionIpMap, &key, value.data(), 0) != 0) {
        return false;
    }
    return true;
}

bool initScionIpMap(const TranslatorConfig& config)
{
    scionIpMap = bpf_obj_get(SCION_IP_MAP);
    if (!scionIpMap) {
        spdlog::error("cannot open pinned map {}", SCION_IP_MAP);
        return false;
    } else {
        if (!updateScionIpMap(config)) {
            spdlog::error("updating eBPF maps failed");
            return false;
        }
    }
    return true;
}

void unpinScionIpMap()
{
    if (scionIpMap) {
        spdlog::info("unpinning map {}", SCION_IP_MAP);
        try {
            std::filesystem::remove(SCION_IP_MAP);
        } catch (const std::system_error& e) {
            spdlog::error("cannot unpin map ({})", e.what());
        }
        scionIpMap.release();
    }
}
