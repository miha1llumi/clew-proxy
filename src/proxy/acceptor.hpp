#pragma once

// Asio-based TCP acceptor for redirected connections.
// Replaces blocking local_listener.hpp.
// Binds to redirect.listen_host:redirect.listen_port and accepts
// connections redirected by the NETWORK layer. The default ("0.0.0.0", 0) is
// v0.10.0 behaviour: INADDR_ANY + an ephemeral port. INADDR_ANY is not a
// convenience here -- reflect reinjects the swapped packet inbound as
// orig_dst -> app_ip:redirect_port, i.e. addressed to a real local address,
// which a socket bound to 127.0.0.1 would refuse.

#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include <atomic>
#include <format>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include "core/log.hpp"

#include "core/port_tracker.hpp"
#include "proxy/relay.hpp"

namespace clew {

using asio::ip::tcp;

class async_acceptor {
public:
    async_acceptor(asio::io_context& ioc,
                   PortTracker& tracker,
                   asio::strand<asio::io_context::executor_type>& strand,
                   std::unordered_map<uint32_t, ProxyGroupConfig>& groups)
        : ioc_(ioc)
        , tracker_(tracker)
        , strand_(strand)
        , groups_(groups)
    {}

    // Start listening on host:port (port 0 = ephemeral). Returns the bound port.
    uint16_t start(const std::string& host, uint16_t port) {
        auto ex = ioc_.get_executor();
        tcp::endpoint ep(asio::ip::make_address(host), port);
        try {
            acceptor_ = std::make_unique<tcp::acceptor>(ex, ep);
        } catch (const std::exception& e) {
            PC_LOG_ERROR("[ACCEPTOR] Cannot bind {}:{}: {}", host, port, e.what());
            throw std::runtime_error(std::format("cannot bind redirect listener on {}:{}: {}",
                                                 host, port, e.what()));
        }

        port_ = acceptor_->local_endpoint().port();
        PC_LOG_INFO("[ACCEPTOR] Listening on {}:{}", host, port_);

        // Launch accept loop as coroutine
        asio::co_spawn(ioc_, accept_loop(), asio::detached);

        return port_;
    }

    void stop() {
        running_ = false;
        if (acceptor_ && acceptor_->is_open()) {
            std::error_code ec;
            acceptor_->close(ec);
        }
        PC_LOG_INFO("[ACCEPTOR] Stopped (accepted {} connections)", accepted_count_.load());
    }

    uint16_t port() const { return port_; }
    uint64_t accepted_count() const { return accepted_count_; }

private:
    asio::io_context& ioc_;
    PortTracker& tracker_;
    asio::strand<asio::io_context::executor_type>& strand_;
    std::unordered_map<uint32_t, ProxyGroupConfig>& groups_;

    std::unique_ptr<tcp::acceptor> acceptor_;
    uint16_t port_{0};
    std::atomic<bool> running_{true};
    std::atomic<uint64_t> accepted_count_{0};

    asio::awaitable<void> accept_loop() {
        while (running_) {
            auto [ec, sock] = co_await acceptor_->async_accept(
                asio::as_tuple(asio::use_awaitable));

            if (ec) {
                if (running_)
                    PC_LOG_DEBUG("[ACCEPTOR] Accept error: {}", ec.message());
                break;
            }

            accepted_count_.fetch_add(1);

            // Spawn relay coroutine for this connection
            asio::co_spawn(ioc_,
                handle_connection(std::move(sock), tracker_, strand_, groups_),
                asio::detached);
        }
    }
};

} // namespace clew
