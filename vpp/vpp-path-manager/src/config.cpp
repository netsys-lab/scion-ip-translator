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

#define TOML_EXCEPTIONS 1
#include <toml++/toml.hpp>

#include <algorithm>
#include <istream>
#include <system_error>
#include <string_view>

static const char* DEFAULT_SCIOND = "127.0.0.1:30255";
static const char* DEFAULT_TAP_NAME = "scion";

static asio::ip::udp::endpoint parseEndpoint(std::string_view raw)
{
    auto colon = std::find(raw.rbegin(), raw.rend(), ':').base() - 1;
    std::string_view addr(raw.begin(), colon), port(colon + 1, raw.end());

    if (addr.starts_with('[')) {
        if (!addr.ends_with(']'))
            throw std::invalid_argument("invalid network address");
        addr.remove_prefix(1);
        addr.remove_suffix(1);
    }

    std::uint16_t portNum = 0;
    auto res = std::from_chars(port.begin(), port.end(), portNum, 10);
    if (port.empty() || res.ptr != port.end())
        throw std::out_of_range("invalid port in network address");

    return asio::ip::udp::endpoint(asio::ip::make_address(addr), portNum);
}

void loadConfig(const std::filesystem::path& configFile, TranslatorConfig& config)
{
    using namespace asio;
    using namespace std::filesystem;

    std::ifstream stream(configFile);
    if (!stream.is_open()) {
        throw filesystem_error("file not found", configFile,
            make_error_code(std::errc::no_such_file_or_directory));
    }

    auto tab = toml::parse(stream, configFile.string());

    // Section: log
    config.logLevel = spdlog::level::from_str(tab["log"]["level"].value_or("warning"));

    // Section: translator
    {
        auto sec = tab["translator"];
        if (auto v = sec["isd_asn"].value<std::string_view>(); v.has_value()) {
            auto ia = scion::IsdAsn::Parse(*v);
            if (std::holds_alternative<std::error_code>(ia))
                throw ConfigError("invalid ISD-ASN");
            config.localIA = std::get<scion::IsdAsn>(ia);
        } else {
            throw ConfigError("isd_asn not set");
        }
        if (auto v = sec["gateway_addr"].value<std::string_view>(); v.has_value()) {
            config.gatewayAddr = ip::make_network_v6(*v);
        } else {
            throw ConfigError("gateway_addr not set");
        }
        if (auto v = sec["host_addr"].value<std::string_view>(); v.has_value()) {
            config.hostAddr = ip::make_network_v6(*v);
        } else {
            throw ConfigError("host_addr not set");
        }
        config.gatewayAddr4 = sec["gateway_addr4"].value<std::string_view>()
            .transform([](auto x) { return ip::make_network_v4(x); });
        config.hostAddr4 = sec["host_addr4"].value<std::string_view>()
            .transform([](auto x) { return ip::make_network_v4(x); });
        if (config.gatewayAddr4.has_value() != config.hostAddr4.has_value()) {
            throw ConfigError("if one og gateway_addr4 and host_addr4 is set, both must be");
        }
    }

    // Section: sciond_connection
    config.sciondEp = parseEndpoint(
        tab["sciond"]["address"].value_or<std::string_view>(DEFAULT_SCIOND));

    // Section: tap
    config.tapName = tab["tap"]["name"].value_or<std::string_view>(DEFAULT_TAP_NAME);

    // Section: xdp
    {
        auto sec = tab["xdp"];
        if (auto v = sec["interface"].value<std::string_view>(); v.has_value()) {
            config.hostInterface = *v;
        } else {
            throw ConfigError("host interface not set");
        }
        config.hostIfQueues = sec["rx_queues"].value_or(1);
    }
}

std::string dumpConfig(const TranslatorConfig& config)
{
    std::stringstream stream, ia;
    ia << config.localIA;
    toml::table tab{
        {"log", toml::table{
            {"level", fmt::format("{}", spdlog::level::to_string_view(config.logLevel))},
        }},
        {"translator", toml::table{
            {"isd_asn", ia.str()},
            {"gateway_addr", config.gatewayAddr.to_string()},
            {"host_addr", config.hostAddr.to_string()},
        }},
        {"sciond_connection", toml::table{
            {"address", "config.sciondEp"},
        }},
        {"tap", toml::table{
            {"name", config.tapName},
        }},
        {"xdp", toml::table{
            {"interface", config.hostInterface},
            {"rx_queues", config.hostIfQueues},
        }},
    };
    if (config.gatewayAddr4 && config.hostAddr4) {
        auto translator = tab["translator"].as_table();
        translator->insert_or_assign("gateway_addr4", config.gatewayAddr4->to_string());
        translator->insert_or_assign("host_addr4", config.hostAddr4->to_string());
    }
    stream << tab;
    return stream.str();
}
