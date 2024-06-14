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

#include "netlink.hpp"
#include <spdlog/spdlog.h>
#include <linux/rtnetlink.h>
#include <memory>

using asio::ip::network_v4;
using asio::ip::network_v6;

NetLinkRoute::NetLinkRoute()
    : seq(time(NULL))
{
    nl = mnl_socket_open(NETLINK_ROUTE);
    if (!nl) throw std::runtime_error("cannot netlink socket to route bus");
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        mnl_socket_close(nl);
        throw std::system_error(errno, std::generic_category(), "mnl_socket_bind");
    }
}

NetLinkRoute::~NetLinkRoute()
{
    if (nl) mnl_socket_close(nl);
}

template <typename Network>
requires std::same_as<Network, network_v4> || std::same_as<Network, network_v6>
void NetLinkRoute::addRoute(Network dst, const char* dev)
{
    using namespace std::literals;
    size_t bufsize = MNL_SOCKET_BUFFER_SIZE;
    auto buf = std::make_unique<char[]>(bufsize);
    nlmsghdr* nlh;
    rtmsg* rtm;

    spdlog::info("add route {} via {}", dst.canonical().to_string(), dev);

    int iface = if_nametoindex(dev);
    if (iface == 0) {
        throw std::runtime_error("interface not found: "s + dev);
    }

    nlh = mnl_nlmsg_put_header(buf.get());
    nlh->nlmsg_type = RTM_NEWROUTE;
    nlh->nlmsg_flags =NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    nlh->nlmsg_seq = seq;

    rtm = (rtmsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_dst_len = dst.prefix_length();
    rtm->rtm_src_len = 0;
    rtm->rtm_tos = 0;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    rtm->rtm_flags = 0;
    mnl_attr_put_u32(nlh, RTA_OIF, iface);
    // mnl_attr_put_u32(nlh, RTA_PRIORITY, metric);
    if constexpr (std::is_same_v<Network, network_v4>) {
        rtm->rtm_family = AF_INET;
        uint32_t ip = 0;
        std::memcpy(&ip, dst.canonical().address().to_bytes().data(), 4);
        mnl_attr_put_u32(nlh, RTA_DST, ip);
    }
    else {
        rtm->rtm_family = AF_INET6;
        mnl_attr_put(nlh, RTA_DST, sizeof(struct in6_addr),
            dst.canonical().address().to_bytes().data());
    }

    execute(nlh, buf.get(), bufsize);
}

template <typename Network>
requires std::same_as<Network, network_v4> || std::same_as<Network, network_v6>
void NetLinkRoute::delRoute(Network dst, const char* dev)
{
    using namespace std::literals;
    size_t bufsize = MNL_SOCKET_BUFFER_SIZE;
    auto buf = std::make_unique<char[]>(bufsize);
    nlmsghdr* nlh;
    rtmsg* rtm;

    spdlog::info("del route {} via {}", dst.canonical().to_string(), dev);

    int iface = if_nametoindex(dev);
    if (iface == 0) {
        throw std::runtime_error("interface not found: "s + dev);
    }

    nlh = mnl_nlmsg_put_header(buf.get());
    nlh->nlmsg_type = RTM_DELROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq;

    rtm = (rtmsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_dst_len = dst.prefix_length();
    rtm->rtm_src_len = 0;
    rtm->rtm_tos = 0;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_flags = 0;
    mnl_attr_put_u32(nlh, RTA_OIF, iface);
    if constexpr (std::is_same_v<Network, network_v4>) {
        rtm->rtm_family = AF_INET;
        uint32_t ip = 0;
        std::memcpy(&ip, dst.canonical().address().to_bytes().data(), 4);
        mnl_attr_put_u32(nlh, RTA_DST, ip);
    }
    else {
        rtm->rtm_family = AF_INET6;
        mnl_attr_put(nlh, RTA_DST, sizeof(struct in6_addr),
            dst.canonical().address().to_bytes().data());
    }

    execute(nlh, buf.get(), bufsize);
}

void NetLinkRoute::execute(nlmsghdr* nlh, char* buf, size_t bufsize)
{
    auto portid = mnl_socket_get_portid(nl);
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        throw std::system_error(errno, std::generic_category(), "mnl_socket_sendto");
    }
    ssize_t numbytes = mnl_socket_recvfrom(nl, buf, bufsize);
    if (numbytes < 0) {
        throw std::system_error(errno, std::generic_category(), "mnl_socket_recvfrom");
    }
    if (mnl_cb_run(buf, numbytes, seq, portid, nullptr, nullptr) < 0) {
        throw std::system_error(errno, std::generic_category(), "mnl_cb_run");
    }
}

// template void NetLinkRoute::addRoute<network_v4>(network_v4 dst, const char* dev);
template void NetLinkRoute::addRoute<network_v6>(network_v6 dst, const char* dev);
// template void NetLinkRoute::delRoute<network_v4>(network_v4 dst, const char* dev);
template void NetLinkRoute::delRoute<network_v6>(network_v6 dst, const char* dev);
