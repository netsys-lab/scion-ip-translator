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

#pragma once

#include <asio.hpp>
#include <libmnl/libmnl.h>

#include <concepts>


class NetLinkRoute
{
private:
    mnl_socket* nl = nullptr;
    uint32_t seq;

public:
    NetLinkRoute();
    NetLinkRoute(const NetLinkRoute& other) = delete;
    NetLinkRoute& operator=(const NetLinkRoute& other) = delete;

    ~NetLinkRoute();

    template <typename Network>
    requires std::same_as<Network, asio::ip::network_v4>
        || std::same_as<Network, asio::ip::network_v6>
    void addRoute(Network dst, const char* dev);

    template <typename Network>
    requires std::same_as<Network, asio::ip::network_v4>
        || std::same_as<Network, asio::ip::network_v6>
    void delRoute(Network dst, const char* dev);

private:
    void execute(nlmsghdr* nlh, char* buf, size_t bufsize);
};
