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
#include <spdlog/spdlog.h>
#include <scion/addr/isd_asn.hpp>

#include <stdexcept>
#include <filesystem>
#include <string>


class ConfigError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

struct TranslatorConfig
{
    // log
    spdlog::level::level_enum logLevel;
    // translator
    scion::IsdAsn localIA;
    asio::ip::network_v6 gatewayAddr;
    asio::ip::network_v6 hostAddr;
    std::optional<asio::ip::network_v4> gatewayAddr4;
    std::optional<asio::ip::network_v4> hostAddr4;
    // sciond_connection
    asio::ip::udp::endpoint sciondEp;
    // tap
    std::string tapName;
    // xdp
    std::string hostInterface;
    unsigned int hostIfQueues;
};

void loadConfig(const std::filesystem::path& configFile, TranslatorConfig& config);
std::string dumpConfig(const TranslatorConfig& config);
