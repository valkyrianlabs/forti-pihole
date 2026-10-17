# The Pi-hole v6 API client (namespace fph::pihole). Self-contained: nlohmann/json comes with
# forti-api, and libcurl is the one forti-api already requires. Nothing here links the engine.
fph_pihole_inc = include_directories('..')
fph_pihole_deps = [dependency('forti-api')]   # brings libcurl along

fph_pihole = static_library('forti-pihole-pihole',
                            'text.cpp', 'error.cpp', 'transport.cpp', 'model.cpp', 'resolve.cpp', 'client.cpp',
                            include_directories : fph_pihole_inc,
                            dependencies : fph_pihole_deps,
                            implicit_include_directories : false)
fph_pihole_dep = declare_dependency(include_directories : fph_pihole_inc, link_with : fph_pihole,
                                    dependencies : fph_pihole_deps)
