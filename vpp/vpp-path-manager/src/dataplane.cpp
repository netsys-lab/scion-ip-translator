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

#include "dataplane.hpp"
#include <vapi/vpe.api.vapi.hpp>
DEFINE_VAPI_MSG_IDS_VPE_API_JSON
#include <vapi/interface.api.vapi.hpp>
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
#include <vapi/tapv2.api.vapi.hpp>
DEFINE_VAPI_MSG_IDS_TAPV2_API_JSON
#include <vapi/af_xdp.api.vapi.hpp>
DEFINE_VAPI_MSG_IDS_AF_XDP_API_JSON
#include <vapi/scion_ip_translator.api.vapi.hpp>
DEFINE_VAPI_MSG_IDS_SCION_IP_TRANSLATOR_API_JSON

#include <spdlog/spdlog.h>


// Size of UDP + SCION header with IPv6 addresses and empty path
constexpr std::uint32_t MIN_SCION_HDR_SIZE = 8 + 12 + 48;
constexpr std::uint32_t DEFAULT_TUN_MTU = 1500 - MIN_SCION_HDR_SIZE;

struct VapiErrorCategory : public std::error_category
{
    const char* name() const noexcept override
    {
        return "vapi";
    }

    std::string message(int code) const override
    {
        switch (code) {
        case VAPI_OK:
            return "success";
        case VAPI_EINVAL:
            return "invalid value encountered";
        case VAPI_EAGAIN:
            return "operation would block";
        case VAPI_ENOTSUP:
            return "operation not supported";
        case VAPI_ENOMEM:
            return "out of memory";
        case VAPI_ENORESP:
            return "no response to request";
        case VAPI_EMAP_FAIL:
            return "failure while mapping api";
        case VAPI_ECON_FAIL:
            return "failure while connection to vpp";
        case VAPI_EINCOMPATIBLE:
            return "fundamental incompatibility while connecting to vpp";
        case VAPI_MUTEX_FAILURE:
            return "failure manipulating internal mutex(es)";
        case VAPI_EUSER:
            return "user error";
        case VAPI_ENOTSOCK:
            return "vapi socket doesn't refer to a socket";
        case VAPI_EACCES:
            return "no write permission for socket";
        case VAPI_ECONNRESET:
            return "connection reset by peer";
        case VAPI_ESOCK_FAILURE:
            return "generic socket failure";
        default:
            return "unknown error code";
        }
    }
};

VapiErrorCategory vapiErrorCategory;

std::error_code make_error_code(vapi_error_e code)
{
    return {code, vapiErrorCategory};
}

std::string DataplaneError::formatMessage(int retval, const char* what)
{
    std::stringstream stream;
    stream << what << " (returned " << retval << ')';
    return stream.str();
}

Dataplane::Dataplane()
{
    auto err = con.connect("path-manager", nullptr, 32, 32);
    if (err != VAPI_OK) {
        throw VapiError(err, "connect");
    }
    spdlog::info("connected to dataplane");
}

Dataplane::~Dataplane()
{
    auto err = con.disconnect();
    if (err != VAPI_OK) {
        spdlog::error("VAPI disconnect failed ({})", vapiErrorCategory.message(err));
    }
}

std::uint32_t TapInterface::create(Dataplane& dp)
{
    vapi::Tap_create_v3 tap(dp.getCon(), 0);
    auto& mp = tap.get_request().get_payload();
    mp.use_random_mac = true;
    mp.num_rx_queues = 8;
    mp.num_tx_queues = 8;
    mp.host_mtu_set = true;
    mp.host_mtu_size = DEFAULT_TUN_MTU;
    mp.host_ip6_prefix_set = true;
    std::memcpy(mp.host_ip6_prefix.address, addr.address().to_bytes().data(), 16);
    mp.host_ip6_prefix.len = addr.prefix_length();
    mp.host_if_name_set = true;
    std::memcpy(mp.host_if_name, name.data(), std::min(name.size(), sizeof(mp.host_if_name) - 1));
    auto resp = dp.execAndWait(tap);
    if (resp.retval != 0)
        throw DataplaneError(resp.retval, "create tap interface");
    ifIndex = static_cast<uint32_t>(resp.sw_if_index);
    return *ifIndex;
}

void TapInterface::destroy(Dataplane& dp)
{
    if (!ifIndex.has_value()) return;
    vapi::Tap_delete_v2 tap(dp.getCon());
    auto& mp = tap.get_request().get_payload();
    mp.sw_if_index = *ifIndex;
    auto resp = dp.execAndWait(tap);
    if (resp.retval != 0)
        throw DataplaneError(resp.retval, "delete tap interface");
    ifIndex = std::nullopt;
}

uint32_t XdpInterface::create(Dataplane& dp)
{
    vapi::Af_xdp_create_v3 xdp(dp.getCon());
    auto& mp = xdp.get_request().get_payload();
    std::memcpy(mp.host_if, hostIf.data(), std::min(hostIf.size(), sizeof(mp.host_if) - 1));
    std::memcpy(mp.name, name.data(), std::min(name.size(), sizeof(mp.name) - 1));
    mp.rxq_num = rxQueues;
    std::memcpy(mp.prog, program.data(), std::min(program.size(), sizeof(mp.prog) - 1));
    auto resp = dp.execAndWait(xdp);
    if (resp.retval != 0)
        throw DataplaneError(resp.retval, "create af_xdp interface");
    ifIndex = static_cast<uint32_t>(resp.sw_if_index);
    return *ifIndex;
}

void XdpInterface::destroy(Dataplane& dp)
{
    if (!ifIndex.has_value()) return;
    vapi::Af_xdp_delete xdp(dp.getCon());
    auto& mp = xdp.get_request().get_payload();
    mp.sw_if_index = *ifIndex;
    auto resp = dp.execAndWait(xdp);
    if (resp.retval != 0)
        throw DataplaneError(resp.retval, "delete af_xdp interface");
    ifIndex = std::nullopt;
}

int setVppInterfaceUp(Dataplane& dp, std::uint32_t index)
{
    vapi::Sw_interface_set_flags flags(dp.getCon());
    auto& mp = flags.get_request().get_payload();
    mp.sw_if_index = index;
    mp.flags = IF_STATUS_API_FLAG_ADMIN_UP;
    auto resp = dp.execAndWait(flags);
    return resp.retval;
}
