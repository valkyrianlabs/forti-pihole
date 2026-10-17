//
// The ownership marker, shared by everything forti-pihole writes: FortiOS address objects and Pi-hole
// client entries alike. An object is ours only when its comment contains this text; anything else is
// an administrator's and is never modified or deleted (AGENTS.md rules 2 and 3).
//
// src/config.hpp's fph::marker is an alias of it.
//

#ifndef FORTI_PIHOLE_PIHOLE_MARKER_HPP
#define FORTI_PIHOLE_PIHOLE_MARKER_HPP

#include <string_view>

namespace fph {

    inline constexpr std::string_view ownership_marker = "managed by forti-pihole";

    // Contains, not equals: a managed comment also says what the entry is for
    // ("managed by forti-pihole: segment iot").
    [[nodiscard]] constexpr bool carries_marker(std::string_view comment) {
        return comment.find(ownership_marker) != std::string_view::npos;
    }

}  // namespace fph

#endif  // FORTI_PIHOLE_PIHOLE_MARKER_HPP
