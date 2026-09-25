#pragma once

// Async SOCKS5 client handshake using C++20 coroutines.
// Replaces blocking socks5_client.hpp.
// Protocol: RFC 1928 (SOCKS5), RFC 1929 (username/password), IPv4 CONNECT only.

#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <format>
#include <stdexcept>
#include <string>
#include <vector>
#include "core/log.hpp"

namespace clew {

using asio::ip::tcp;

// RFC 1928 handshake / reply violation. Inherits from std::runtime_error
// so existing catch (const std::exception&) sites (relay.hpp, async_acceptor)
// continue to work without change.
class socks5_protocol_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// SOCKS5 handshake as a coroutine.
// Establishes a SOCKS5 tunnel through `sock` to `dest_ip:dest_port`.
// dest_ip is in host byte order (WinDivert SOCKET layer native for IPv4).
// If `user`/`password` are non-empty, RFC 1929 username/password auth is
// negotiated (method 0x02); otherwise NO_AUTH as before. When both methods
// are offered and the server picks NO_AUTH, auth is skipped.
inline asio::awaitable<void>
socks5_handshake(tcp::socket& sock, uint32_t dest_ip_host, uint16_t dest_port,
                 const std::string& user = "", const std::string& password = "")
{
    const bool want_auth = !user.empty() || !password.empty();

    // Phase 1: Greeting — no auth, or both methods when creds are configured
    std::array<uint8_t, 4> greeting = {0x05, static_cast<uint8_t>(want_auth ? 0x02 : 0x01), 0x00, 0x02};
    const size_t greeting_len = want_auth ? 4 : 3;
    co_await asio::async_write(sock, asio::buffer(greeting.data(), greeting_len),
                               asio::use_awaitable);

    std::array<uint8_t, 2> greeting_reply{};
    co_await asio::async_read(sock, asio::buffer(greeting_reply), asio::use_awaitable);

    if (greeting_reply[0] != 0x05) {
        throw socks5_protocol_error("SOCKS5 greeting failed: invalid version in reply");
    }

    if (want_auth && greeting_reply[1] == 0x02) {
        // Phase 1b: RFC 1929 username/password sub-negotiation
        if (user.size() > 255 || password.size() > 255) {
            throw socks5_protocol_error("SOCKS5 auth: username/password exceed 255 bytes");
        }
        std::vector<uint8_t> auth_req;
        auth_req.reserve(3 + user.size() + password.size());
        auth_req.push_back(0x01);  // VER of sub-negotiation
        auth_req.push_back(static_cast<uint8_t>(user.size()));
        auth_req.insert(auth_req.end(), user.begin(), user.end());
        auth_req.push_back(static_cast<uint8_t>(password.size()));
        auth_req.insert(auth_req.end(), password.begin(), password.end());
        co_await asio::async_write(sock, asio::buffer(auth_req), asio::use_awaitable);

        std::array<uint8_t, 2> auth_reply{};
        co_await asio::async_read(sock, asio::buffer(auth_reply), asio::use_awaitable);

        if (auth_reply[0] != 0x01 || auth_reply[1] != 0x00) {
            PC_LOG_WARN("[SOCKS5] Auth failed: status 0x{:02X}", auth_reply[1]);
            throw socks5_protocol_error("SOCKS5 auth: username/password rejected");
        }
    } else if (greeting_reply[1] != 0x00) {
        throw socks5_protocol_error(std::format(
            "SOCKS5 greeting failed: server selected unsupported method 0x{:02X}",
            greeting_reply[1]));
    }

    // Phase 2: CONNECT request — IPv4
    std::array<uint8_t, 10> connect_req{};
    connect_req[0] = 0x05;  // VER
    connect_req[1] = 0x01;  // CMD = CONNECT
    connect_req[2] = 0x00;  // RSV
    connect_req[3] = 0x01;  // ATYP = IPv4

    // dest_ip in network byte order
    uint32_t ip_net = htonl(dest_ip_host);
    std::memcpy(&connect_req[4], &ip_net, 4);

    // dest_port in network byte order
    uint16_t port_net = htons(dest_port);
    std::memcpy(&connect_req[8], &port_net, 2);

    co_await asio::async_write(sock, asio::buffer(connect_req), asio::use_awaitable);

    // Read CONNECT reply (minimum 10 bytes for IPv4)
    std::array<uint8_t, 10> connect_reply{};
    co_await asio::async_read(sock, asio::buffer(connect_reply), asio::use_awaitable);

    if (connect_reply[0] != 0x05) {
        throw socks5_protocol_error("SOCKS5 connect: invalid version in reply");
    }
    if (connect_reply[1] != 0x00) {
        PC_LOG_WARN("[SOCKS5] Connect failed: reply code 0x{:02X}", connect_reply[1]);
        throw socks5_protocol_error(std::format("SOCKS5 connect: server returned error {}",
                                                 connect_reply[1]));
    }

    // Success — tunnel established, sock is now a transparent pipe
}

} // namespace clew
