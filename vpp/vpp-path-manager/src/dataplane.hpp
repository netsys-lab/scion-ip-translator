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
#include <vapi/vapi.hpp>

#include <filesystem>
#include <system_error>
#include <optional>

namespace std {
template<> struct is_error_code_enum<vapi_error_e> : true_type {};
}

std::error_code make_error_code(vapi_error_e code);

struct VapiError : public std::system_error
{
    using std::system_error::system_error;
};

class DataplaneError : public std::runtime_error
{
public:
    DataplaneError(int retval, const char* what) noexcept
        : std::runtime_error(formatMessage(retval, what)), err(retval)
    {}
    int code() const noexcept { return err; }

private:
    static std::string formatMessage(int retval, const char* what);

private:
    int err;
};

class Dataplane
{
private:
    vapi::Connection con;

public:
    Dataplane();
    ~Dataplane();

    vapi::Connection& getCon() { return con; }

    template <typename Request>
    void executeReq(Request& req)
    {
        auto err = req.execute();
        if (err != VAPI_OK)
            throw VapiError(err, "execute request");
    }

    template <typename Request>
    auto& waitForResponse(Request& req)
    {
        vapi_error_e err = VAPI_OK;
        do {
            err = con.wait_for_response(req);
        } while (err == VAPI_EAGAIN);
        if (err != VAPI_OK)
            throw VapiError(err, "wait_for_response");
        return req.get_response().get_payload();
    }

    template <typename Request>
    auto& execAndWait(Request& req)
    {
        executeReq(req);
        return waitForResponse(req);
    }
};

class TapInterface
{
private:
    std::string name;
    asio::ip::network_v6 addr;
    uint16_t rxQueues, txQueues;
    std::optional<uint32_t> ifIndex = 0;

public:
    TapInterface(std::optional<uint32_t> ifIndex = std::nullopt)
        : ifIndex(ifIndex)
    {}

    TapInterface& setName(std::string_view name)
    {
        this->name = name;
        return *this;
    }

    TapInterface& setAddress(const asio::ip::network_v6& addr)
    {
        this->addr = addr;
        return *this;
    }

    TapInterface& setNumQueues(uint16_t rx, uint16_t tx)
    {
        rxQueues = rx;
        txQueues = tx;
        return *this;
    }

    bool isOpen() const { return ifIndex.has_value(); }
    std::uint32_t index() { return ifIndex.value(); }

    std::uint32_t create(Dataplane& dp);
    void destroy(Dataplane& dp);
};

class XdpInterface
{
private:
    std::string name;
    std::string hostIf;
    std::string program;
    uint16_t rxQueues;
    std::optional<uint32_t> ifIndex = 0;

public:
    XdpInterface(std::optional<uint32_t> ifIndex = std::nullopt)
        : ifIndex(ifIndex)
    {}

    XdpInterface& setName(std::string_view name)
    {
        this->name = name;
        return *this;
    }

    XdpInterface& setHostIf(std::string_view hostIf)
    {
        this->hostIf = hostIf;
        return *this;
    }

    XdpInterface& setQueueParams(uint16_t rxQueueCount)
    {
        rxQueues = rxQueueCount;
        return *this;
    }

    XdpInterface& setProgram(const std::filesystem::path& prog)
    {
        program = prog.native();
        return *this;
    }

    bool isOpen() const { return ifIndex.has_value(); }
    std::uint32_t index() { return ifIndex.value(); }

    uint32_t create(Dataplane& dp);
    void destroy(Dataplane& dp);
};

int setVppInterfaceUp(Dataplane& dp, std::uint32_t index);
