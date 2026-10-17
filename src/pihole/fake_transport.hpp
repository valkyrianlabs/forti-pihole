//
// A scripted Transport for tests: each expected request (method and path) is answered with a canned
// reply, in order. An unexpected request, or one out of order, fails the test through the
// TransportError it throws, and `requests()` records everything that was sent for assertions
// (which headers, which body). `pending()` lists expectations that were never used.
//
//   auto fake = std::make_shared<FakeTransport>();
//   fake->expect(Method::post, "/api/auth", 200, R"({"session": {...}})");
//   fake->expect(Method::del, "/api/auth", 204);
//

#ifndef FORTI_PIHOLE_PIHOLE_FAKE_TRANSPORT_HPP
#define FORTI_PIHOLE_PIHOLE_FAKE_TRANSPORT_HPP

#include "pihole/error.hpp"
#include "pihole/transport.hpp"

#include <cctype>
#include <deque>
#include <format>
#include <string>
#include <vector>

namespace fph::pihole {

    class FakeTransport final : public Transport {
    public:
        struct Step {
            Method method;
            std::string path;
            Response response;
            bool fail = false;   // throw TransportError instead of answering (a dropped connection)
        };

    private:
        std::deque<Step> steps_;
        std::vector<Request> requests_;

    public:
        FakeTransport& expect(Method method, std::string path, long status, std::string body = {}) {
            steps_.push_back({method, std::move(path), Response{status, std::move(body), "application/json"}, false});
            return *this;
        }

        FakeTransport& expect_failure(Method method, std::string path) {
            steps_.push_back({method, std::move(path), Response{0, {}, {}}, true});
            return *this;
        }

        Response perform(const Request& request) override {
            requests_.push_back(request);
            std::string where = std::format("{} {}", to_string(request.method), request.path);
            if (steps_.empty()) throw TransportError("FakeTransport: unexpected request " + where);
            Step step = std::move(steps_.front());
            steps_.pop_front();
            if (step.method != request.method || step.path != request.path)
                throw TransportError(std::format("FakeTransport: expected {} {}, got {}", to_string(step.method),
                                                 step.path, where));
            if (step.fail) throw TransportError("FakeTransport: connection dropped for " + where);
            return step.response;
        }

        [[nodiscard]] const std::vector<Request>& requests() const { return requests_; }
        [[nodiscard]] std::size_t pending() const { return steps_.size(); }

        // The value of `name` in the request (case-insensitive name), or "" when it was not sent.
        [[nodiscard]] static std::string header(const Request& request, std::string_view name) {
            for (const auto& [key, value]: request.headers) {
                if (key.size() != name.size()) continue;
                bool same = true;
                for (std::size_t i = 0; i < key.size() && same; ++i)
                    same = std::tolower(static_cast<unsigned char>(key[i])) ==
                           std::tolower(static_cast<unsigned char>(name[i]));
                if (same) return value;
            }
            return {};
        }
    };

}  // namespace fph::pihole

#endif  // FORTI_PIHOLE_PIHOLE_FAKE_TRANSPORT_HPP
