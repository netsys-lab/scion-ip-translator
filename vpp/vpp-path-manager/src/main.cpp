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
#include "dataplane.hpp"
#include "netlink.hpp"
#include "ebpf.hpp"

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <memory>

std::unique_ptr<Dataplane> dp;
TapInterface tap;
XdpInterface xdp;

static struct Arguments
{
    std::filesystem::path config = "/etc/vpp/scion.toml";
} args;

void parseCommandLine(int argc, char* argv[])
{
    CLI::App app{"Control plane for SCION-IP Translator Plugin in VPP"};

    app.add_option("-c,--config", args.config, "Path to configuration file")
        ->capture_default_str();

    try {
        app.parse(argc, argv);
    }
    catch (const CLI::ParseError& e) {
        exit(app.exit(e));
    }
}

void initDataplane(const TranslatorConfig& config)
{
    namespace fs = std::filesystem;
    bool customBpf = false;
    std::error_code ec;
    auto ebpfObj = absolute(fs::path("bpf/af_xdp.c.o"), ec);
    if (ec || !exists(ebpfObj)) {
        if (spdlog::get_level() >= spdlog::level::debug)
            spdlog::warn("cannot find eBPF XDP program {}", ebpfObj.string());
    } else {
        if (spdlog::get_level() >= spdlog::level::debug)
            spdlog::debug("loading eBPF XDP program from {}", ebpfObj.string());
        xdp.setProgram(ebpfObj);
        customBpf = true;
    }

    spdlog::info("creating tap interface");
    tap.setName(config.tapName).setAddress(config.hostAddr).create(*dp);
    if (setVppInterfaceUp(*dp, tap.index())) {
        spdlog::error("error bringing tap interface up");
    }

    spdlog::info("attaching to host interface");
    xdp.setName("xdp").setHostIf(config.hostInterface).setQueueParams(config.hostIfQueues);
    xdp.create(*dp);
    if (setVppInterfaceUp(*dp, xdp.index())) {
        spdlog::error("error bringing xdp interface up");
    }

    if (customBpf) {
        initScionIpMap(config);
    }
}

void cleanDataplane()
{
    spdlog::info("detachhing from host interface");
    xdp.destroy(*dp);
    spdlog::info("deleting tap interface");
    tap.destroy(*dp);
    unpinScionIpMap();
}

void configureRoutes(const TranslatorConfig& config)
{
    NetLinkRoute nl;

    nl.addRoute(asio::ip::make_network_v6("fc00::/8"), config.tapName.c_str());

    try {
        nl.delRoute(config.hostAddr, config.hostInterface.c_str());
    }
    catch (const std::system_error& e) {
        if (e.code() == std::errc::no_such_process) {
            spdlog::warn("route does not exist (check if host_addr is correct)");
        } else {
            throw;
        }
    }
}

bool init()
{
    TranslatorConfig config;
    try {
        loadConfig(args.config, config);
    }
    catch (const std::runtime_error& e) {
        spdlog::critical(e.what());
        return false;
    }
    spdlog::set_level(config.logLevel);
    spdlog::debug("Config:\n\"\"\"\n{}\n\"\"\"", dumpConfig(config));

    try {
        dp = std::make_unique<Dataplane>();
        initDataplane(config);
        try {
            configureRoutes(config);
        }
        catch (const std::system_error& e) {
            if (e.code() == std::errc::operation_not_permitted) {
                spdlog::critical("no permission to configure routes, make sure program has CAP_NET_ADMIN");
            }
            return false;
        }
    }
    catch (std::runtime_error& e) {
        spdlog::critical(e.what());
        return false;
    }

    return true;
}

void cleanup()
{
    cleanDataplane();
}

int main(int argc, char* argv[])
{
    parseCommandLine(argc, argv);

    if (!init()) {
        cleanup();
        return -1;
    }

    return 0;
}
