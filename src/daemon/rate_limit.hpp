//
// Per-source token buckets. One config change on the FortiGate can produce dozens of webhook calls
// (one per changed attribute), and any one of them is enough to schedule a run, so dropping the excess
// with 429 loses nothing; the bucket mainly keeps a misbehaving or hostile peer from turning the
// receiver into a log and CPU sink. The periodic full reconcile covers anything dropped.
//

#ifndef FORTI_PIHOLED_RATE_LIMIT_HPP
#define FORTI_PIHOLED_RATE_LIMIT_HPP

#include <cstdint>
#include <map>
#include <string>

namespace fph::daemon {

    class RateLimiter {
        struct Bucket {
            double tokens = 0;
            std::int64_t at_ms = 0;
        };

        double burst_;
        double per_ms_;
        std::size_t max_sources_;
        std::map<std::string, Bucket> buckets_;

        void refill(Bucket& bucket, std::int64_t now_ms) const;

    public:
        // `burst` requests at once, refilled at `per_minute`. Sources beyond `max_sources` evict the
        // fullest (least recently limited) buckets, so memory stays bounded whatever the peers do.
        RateLimiter(int burst, int per_minute, std::size_t max_sources = 1024);
        void configure(int burst, int per_minute);

        // Takes one token for `source`; false (429) when its bucket is empty.
        bool allow(const std::string& source, std::int64_t now_ms);
        // Seconds until `source` has a token again (for Retry-After); 0 when it has one now.
        [[nodiscard]] std::int64_t retry_after_s(const std::string& source, std::int64_t now_ms) const;
        [[nodiscard]] std::size_t sources() const { return buckets_.size(); }
    };

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_RATE_LIMIT_HPP
