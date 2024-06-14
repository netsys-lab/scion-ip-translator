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

#include <boost/algorithm/string.hpp>
#include <boost/io/ios_state.hpp>

#include <algorithm>
#include <bit>
#include <charconv>
#include <cassert>
#include <cstdint>
#include <iomanip>
#include <ranges>
#include <span>
#include <string_view>
#include <system_error>
#include <ostream>
#include <variant>


namespace scion {

class Isd
{
public:
    /// \brief Number of bits in ISD number.
    static constexpr std::size_t BITS = 16;
    /// \brief Maximum possible ISD number.
    static constexpr std::size_t MAX_VALUE = (1ull << BITS) - 1;
    /// \brief Size of the address when encoded in a network header.
    static constexpr std::size_t WIRE_BYTES = 2;

private:
    std::uint_fast16_t isd = 0;

public:
    constexpr Isd() = default;
    explicit constexpr Isd(std::uint_fast16_t isd) : isd(isd) { assert(isd <= MAX_VALUE); }
    constexpr operator std::uint_fast16_t() const { return isd; }

    /// \brief Check whether the ISD is unspecified (equal to zero).
    bool isUnspecified() const { return isd == 0; }

    auto operator<=>(const Isd&) const = default;

    /// \brief Parse a decimal ISD number.
    static std::variant<Isd, std::error_code> Parse(std::string_view raw)
    {
        Isd isd;
        auto res = std::from_chars(raw.begin(), raw.end(), isd.isd, 10);
        if (res.ptr == raw.begin())
            return std::make_error_code(res.ec);
        else if (res.ptr != raw.end())
            return std::make_error_code(std::errc::invalid_argument);
        else if (isd.isd > Isd::MAX_VALUE)
            return std::make_error_code(std::errc::result_out_of_range);
        else
            return isd;
    }

    friend std::ostream& operator<<(std::ostream &stream, Isd isd)
    {
        boost::io::ios_flags_saver flags(stream);
        stream << std::dec << isd.isd;
        return stream;
    }
};

class Asn
{
public:
    /// \brief Number of bits in AS number.
    static constexpr std::size_t BITS = 48;
    /// \brief Maximum possible AS number.
    static constexpr std::size_t MAX_VALUE = (1ull << BITS) - 1;
    /// \brief Largest AS number that is considered compatible with BGP.
    static constexpr std::size_t MAX_BGP_VALUE = (1ull << 32) - 1;
    /// \brief Size of the address when encoded in a network header.
    static constexpr std::size_t WIRE_BYTES = 6;

private:
    std::uint64_t asn;

public:
    constexpr Asn() = default;
    explicit constexpr Asn(std::uint64_t asn) : asn(asn) { assert(asn <= MAX_VALUE); }
    constexpr operator std::uint64_t() const { return asn; }

    /// \brief Check whether the ASN is unspecified (equal to zero).
    bool isUnspecified() const { return asn == 0; }

    auto operator<=>(const Asn&) const = default;

    /// \brief Parse a BGP or SCION AS number.
    ///
    /// Valid formats are:
    /// - A decimal non-negative integer if <= MAX_BGP_VALUE.
    /// - Three groups of 1 to 4 hexadecimal digits (upper or lower case) separated by colons.
    static std::variant<Asn, std::error_code> Parse(std::string_view raw)
    {
        static constexpr std::size_t MAX_GROUP_VALUE = (1ull << 16) - 1;
        std::uint64_t asn = 0;

        // BGP-style ASN
        auto res = std::from_chars(raw.begin(), raw.end(), asn, 10);
        if (res.ptr == raw.end() && asn <= MAX_VALUE)
            return Asn(asn);

        // SCION-style ASN
        int i = 0;
        auto finder = boost::algorithm::first_finder(":");
        boost::algorithm::split_iterator<std::string_view::iterator> end;
        for (auto group = boost::algorithm::make_split_iterator(raw, finder); group != end; ++group, ++i)
        {
            if (i > 2 || group->size() == 0) // too many groups or empty group
                return std::make_error_code(std::errc::invalid_argument);

            std::uint64_t v = 0;
            auto res = std::from_chars(group->begin(), group->end(), v, 16);
            if (res.ptr != group->end())
                return std::make_error_code(std::errc::invalid_argument);
            else if (v > MAX_GROUP_VALUE)
                return std::make_error_code(std::errc::invalid_argument);

            asn |= (v << (16 * (2 - i)));
        }
        if (i < 2) // too few groups
            return std::make_error_code(std::errc::invalid_argument);

        return Asn(asn);
    }

    friend std::ostream& operator<<(std::ostream &stream, Asn asn)
    {
        constexpr auto GROUP_BITS = 16ull;
        constexpr auto GROUP_MAX_VALUE = (1ull << GROUP_BITS) - 1;

        boost::io::ios_flags_saver flags(stream);
        if (asn.asn <= MAX_BGP_VALUE)
            stream << asn.asn;
        else
        {
            stream << std::hex
                << ((asn.asn >> 2 * GROUP_BITS) & GROUP_MAX_VALUE) << ':'
                << ((asn.asn >> GROUP_BITS) & GROUP_MAX_VALUE) << ':'
                << ((asn.asn) & GROUP_MAX_VALUE);
        }

        return stream;
    }
};

class IsdAsn
{
public:
    /// \brief Number of bits in ISD-ASN pair.
    static constexpr std::size_t BITS = 48;
    /// \brief Maximum possible ISD-ASN value.
    static constexpr std::size_t MAX_VALUE = (1ull << BITS) - 1;
    /// \brief Size of the address when encoded in a network header.
    static constexpr std::size_t WIRE_BYTES = 8;

private:
    std::uint64_t ia = 0;

public:
    constexpr IsdAsn() = default;
    explicit constexpr IsdAsn(std::uint64_t ia) : ia(ia) {}
    constexpr IsdAsn(Isd isd, Asn asn) : ia((isd << Asn::BITS) | asn) {}

    constexpr operator std::uint64_t() const { return ia; }

    Isd getIsd() const { return Isd(ia >> Asn::BITS); }
    Asn getAsn() const { return Asn(ia & ((1ull << Asn::BITS) - 1)); }

    /// \brief Check whether ISD or ASN are unspecified (equal to zero).
    bool isUnspecified() const
    {
        return getIsd().isUnspecified() || getAsn().isUnspecified();
    }

    auto operator<=>(const IsdAsn&) const = default;

    void parse(std::span<std::byte, 8> from)
    {
        if (std::endian::native == std::endian::little)
            std::copy(from.rbegin(), from.rend(), reinterpret_cast<std::byte*>(&ia));
        else
            std::copy(from.begin(), from.end(), reinterpret_cast<std::byte*>(&ia));
    }

    void emit(std::span<std::byte, 8> to) const
    {
        if (std::endian::native == std::endian::little)
            std::copy_n(reinterpret_cast<const std::byte*>(&ia), sizeof(ia), to.rbegin());
        else
            std::copy_n(reinterpret_cast<const std::byte*>(&ia), sizeof(ia), to.begin());
    }

    static std::variant<IsdAsn, std::error_code> Parse(std::string_view raw)
    {
        std::uint64_t ia = 0;

        auto i = std::find(raw.begin(), raw.end(), '-');
        if (i == raw.end()) return std::make_error_code(std::errc::invalid_argument);

        auto isd = Isd::Parse(std::string_view(raw.begin(), i));
        if (std::holds_alternative<Isd>(isd))
            ia |= (std::get<Isd>(isd) << Asn::BITS);
        else
            return std::get<std::error_code>(isd);

        auto asn = Asn::Parse(std::string_view(i + 1, raw.end()));
        if (std::holds_alternative<Asn>(asn))
            ia |= std::get<Asn>(asn);
        else
            return std::get<std::error_code>(asn);

        return IsdAsn(ia);
    }

    friend std::ostream& operator<<(std::ostream &stream, IsdAsn ia)
    {
        stream << ia.getIsd() << '-' << ia.getAsn();
        return stream;
    }
};

} // namespace scion
