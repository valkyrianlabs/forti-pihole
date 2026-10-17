#include "rate_limit.hpp"

#include <algorithm>
#include <cmath>

namespace fph::daemon {

    RateLimiter::RateLimiter(int burst, int per_minute, std::size_t max_sources)
            : burst_(std::max(1, burst)), per_ms_(std::max(1, per_minute) / 60000.0), max_sources_(std::max<std::size_t>(1, max_sources)) {}

    void RateLimiter::configure(int burst, int per_minute) {
        burst_ = std::max(1, burst);
        per_ms_ = std::max(1, per_minute) / 60000.0;
        for (auto& [source, bucket]: buckets_) bucket.tokens = std::min(bucket.tokens, burst_);
    }

    void RateLimiter::refill(Bucket& bucket, std::int64_t now_ms) const {
        if (now_ms > bucket.at_ms) bucket.tokens = std::min(burst_, bucket.tokens + static_cast<double>(now_ms - bucket.at_ms) * per_ms_);
        bucket.at_ms = std::max(bucket.at_ms, now_ms);
    }

    bool RateLimiter::allow(const std::string& source, std::int64_t now_ms) {
        auto it = buckets_.find(source);
        if (it == buckets_.end()) {
            if (buckets_.size() >= max_sources_) {
                // A full bucket is indistinguishable from a new one, so dropping those first loses no
                // state; failing that, drop the one refilled longest ago.
                for (auto& [key, bucket]: buckets_) refill(bucket, now_ms);
                std::erase_if(buckets_, [&](const auto& entry) { return entry.second.tokens >= burst_; });
                if (buckets_.size() >= max_sources_)
                    buckets_.erase(std::ranges::min_element(buckets_, {}, [](const auto& entry) { return entry.second.at_ms; }));
            }
            it = buckets_.emplace(source, Bucket{burst_, now_ms}).first;
        }
        refill(it->second, now_ms);
        if (it->second.tokens < 1.0) return false;
        it->second.tokens -= 1.0;
        return true;
    }

    std::int64_t RateLimiter::retry_after_s(const std::string& source, std::int64_t now_ms) const {
        auto it = buckets_.find(source);
        if (it == buckets_.end()) return 0;
        Bucket bucket = it->second;
        refill(bucket, now_ms);
        if (bucket.tokens >= 1.0) return 0;
        return static_cast<std::int64_t>(std::ceil((1.0 - bucket.tokens) / per_ms_ / 1000.0));
    }

}  // namespace fph::daemon
