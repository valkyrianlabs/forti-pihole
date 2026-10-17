#include "pihole/transport.hpp"
#include "pihole/error.hpp"
#include "pihole/text.hpp"

#include <curl/curl.h>

#include <algorithm>
#include <format>

namespace fph::pihole {

    namespace {

        bool loopback_host(std::string_view host) {
            if (host == "localhost" || host == "[::1]") return true;
            // 127.0.0.0/8, written as a dotted quad
            if (!host.starts_with("127.")) return false;
            return std::ranges::all_of(host, [](char c) { return (c >= '0' && c <= '9') || c == '.'; });
        }

        // Wipes a buffer that held a secret before its memory is released.
        void wipe(std::string& text) {
            volatile char* p = text.data();
            for (std::size_t i = 0; i < text.size(); ++i) p[i] = 0;
            text.clear();
        }

    }  // namespace

    std::string_view to_string(Method method) {
        switch (method) {
            case Method::get: return "GET";
            case Method::post: return "POST";
            case Method::put: return "PUT";
            case Method::del: return "DELETE";
        }
        return "GET";
    }

    std::string validated_base_url(const Endpoint& endpoint) {
        std::string_view url = endpoint.url;
        if (endpoint.timeout_ms <= 0) throw Error("Pi-hole endpoint: timeout_ms must be positive");
        bool https = url.starts_with("https://");
        if (!https && !url.starts_with("http://"))
            throw Error("Pi-hole endpoint: the URL must start with https:// (got \"" + printable(url, 80) + "\")");
        std::string_view rest = url.substr(https ? 8 : 7);
        if (rest.find_first_of("?#") != std::string_view::npos)
            throw Error("Pi-hole endpoint: the URL must not have a query or fragment");
        std::string_view authority = rest.substr(0, rest.find('/'));
        std::string_view path = rest.substr(authority.size());
        // Credentials never go in the URL: they would end up in logs and error messages.
        if (authority.find('@') != std::string_view::npos)
            throw Error("Pi-hole endpoint: the URL must not contain credentials (user@host)");
        if (authority.empty()) throw Error("Pi-hole endpoint: the URL has no host");
        if (std::ranges::any_of(authority, [](char c) { return static_cast<unsigned char>(c) <= 0x20; }))
            throw Error("Pi-hole endpoint: the URL host contains spaces or control characters");
        std::string_view host = authority;
        if (host.starts_with('[')) {
            auto close = host.find(']');
            if (close == std::string_view::npos) throw Error("Pi-hole endpoint: unterminated [IPv6] host");
            host = host.substr(0, close + 1);
        } else {
            host = host.substr(0, host.find(':'));
        }
        if (!https && !loopback_host(host))
            throw Error("Pi-hole endpoint: plain http:// is accepted for loopback hosts only; use https:// "
                        "(the password and session ID would otherwise cross the network in clear)");

        while (path.ends_with('/')) path.remove_suffix(1);
        if (path.ends_with("/api")) path.remove_suffix(4);
        while (path.ends_with('/')) path.remove_suffix(1);
        return std::string(url.substr(0, (https ? 8 : 7) + authority.size())) + std::string(path);
    }

    std::string encode_segment(std::string_view segment) {
        static constexpr char hex[] = "0123456789ABCDEF";
        std::string out;
        for (char c: segment) {
            auto byte = static_cast<unsigned char>(c);
            bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                              c == '-' || c == '.' || c == '_' || c == '~';
            if (unreserved) {
                out += c;
            } else {
                out += '%';
                out += hex[byte >> 4];
                out += hex[byte & 0x0f];
            }
        }
        return out;
    }

    struct CurlTransport::Handle {
        CURL* curl = nullptr;
        ~Handle() {
            if (curl) curl_easy_cleanup(curl);
        }
    };

    namespace {

        struct GlobalInit {
            GlobalInit() { curl_global_init(CURL_GLOBAL_DEFAULT); }
        };

        struct Sink {
            std::string body;
            bool exceeded = false;
        };

        size_t write_body(char* data, size_t size, size_t count, void* out) {
            auto* sink = static_cast<Sink*>(out);
            std::size_t bytes = size * count;
            if (sink->body.size() + bytes > max_response_bytes) {
                sink->exceeded = true;
                return 0;   // aborts the transfer (CURLE_WRITE_ERROR)
            }
            sink->body.append(data, bytes);
            return bytes;
        }

        struct SlistDeleter {
            void operator()(curl_slist* list) const { curl_slist_free_all(list); }
        };

    }  // namespace

    CurlTransport::CurlTransport(const Endpoint& endpoint)
            : base_(validated_base_url(endpoint)), ca_bundle_(endpoint.ca_bundle), timeout_ms_(endpoint.timeout_ms),
              handle_(std::make_unique<Handle>()) {
        static GlobalInit init;
        handle_->curl = curl_easy_init();
        if (!handle_->curl) throw TransportError("Pi-hole: curl_easy_init failed");
    }

    CurlTransport::~CurlTransport() = default;

    Response CurlTransport::perform(const Request& request) {
        std::lock_guard lock(mutex_);
        CURL* curl = handle_->curl;
        // Keeps the connection, TLS session and DNS caches; clears every per-request option.
        curl_easy_reset(curl);

        std::string where = std::format("{} {}", to_string(request.method), request.path);
        bool write = request.method != Method::get;

        curl_slist* list = nullptr;
        auto add = [&list](const std::string& header) {
            curl_slist* next = curl_slist_append(list, header.c_str());
            if (!next) {
                curl_slist_free_all(list);
                throw TransportError("Pi-hole: out of memory building headers");
            }
            list = next;
        };
        std::string header_line;
        for (const auto& [name, value]: request.headers) {
            header_line = name + ": " + value;
            add(header_line);
            wipe(header_line);   // may have been the session ID
        }
        // libcurl adds "Expect: 100-continue" to large bodies; a 417 reply to it makes libcurl resend.
        if (write) add("Expect:");
        std::unique_ptr<curl_slist, SlistDeleter> headers(list);

        std::string url = base_ + request.path;
        Sink sink;
        char error[CURL_ERROR_SIZE] = {};
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_body);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms_);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, std::min(timeout_ms_, 10000L));
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
        // Verification is not configurable: there is no option that turns it off.
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
        if (ca_bundle_) curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle_->c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        // An http_proxy from the environment must never see a loopback (plain HTTP) request.
        curl_easy_setopt(curl, CURLOPT_NOPROXY, "localhost,127.0.0.1,::1");
#if LIBCURL_VERSION_NUM >= 0x075500   // 7.85: CURLOPT_PROTOCOLS_STR replaces the deprecated bitmask
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https,http");
#else
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS, static_cast<long>(CURLPROTO_HTTPS | CURLPROTO_HTTP));
#endif
        if (write) {
            curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);
            curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
            curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, static_cast<long>(CURL_HTTP_VERSION_1_1));
        }
        switch (request.method) {
            case Method::get:
                curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
                break;
            case Method::post:
            case Method::put:
                if (request.method == Method::put) curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.body.size()));
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.body.c_str());
                break;
            case Method::del:
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
                break;
        }

        CURLcode code = curl_easy_perform(curl);
        // Nothing of the request may outlive it in the handle (the body may hold the password).
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, nullptr);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, nullptr);
        if (sink.exceeded)
            throw TransportError(std::format("Pi-hole: {}: the reply exceeds {} bytes", where, max_response_bytes));
        if (code != CURLE_OK)
            // The error buffer names the host and the failure (TLS, DNS, timeout), never headers or body.
            throw TransportError(std::format("Pi-hole: {}: {}", where,
                                             printable(error[0] ? error : curl_easy_strerror(code), 300)));

        Response response;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);
        char* type = nullptr;
        if (curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &type) == CURLE_OK && type) response.content_type = type;
        response.body = std::move(sink.body);
        return response;
    }

}  // namespace fph::pihole
