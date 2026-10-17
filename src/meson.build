# forti_pihole_version.hpp carries the project version and what it was built from (the forti-cli
# engine revision and the forti-api version; see the top-level meson.build) into --version.
version_hpp = configure_file(output : 'forti_pihole_version.hpp',
                             configuration : {'FORTI_PIHOLE_VERSION' : '"' + meson.project_version() + '"',
                                              'FORTI_PIHOLE_BUILT_FROM' : '"engine forti-cli ' + engine_revision
                                                                            + ', forti-api ' + forti_api_version + '"'})

fph_inc = include_directories('.')

# The CIDR allocation planner for DHCP address slicing (alloc/): pure functions, no engine. Its own
# library so it builds and tests on its own; only nlohmann/json's headers come from forti-api.
fph_json_headers = dependency('forti-api').partial_dependency(compile_args : true, includes : true)
fph_alloc = static_library('forti-pihole-alloc',
                           'alloc/cidr.cpp', 'alloc/plan.cpp', 'alloc/render.cpp',
                           include_directories : fph_inc,
                           dependencies : fph_json_headers,
                           implicit_include_directories : false)
fph_alloc_dep = declare_dependency(include_directories : fph_inc, link_with : fph_alloc, dependencies : fph_json_headers)

# The Pi-hole API client library (src/pihole/meson.build defines fph_pihole_dep).
subdir('pihole')

# Everything but main(): the executable and the unit tests link the same library.
fph_core = static_library('forti-pihole-core',
                          'mac.cpp', 'config.cpp', 'inventory.cpp', 'address_match.cpp', 'classify.cpp', 'reassociate.cpp',
                          'connectivity.cpp', 'references.cpp', 'operation.cpp', 'pihole_sync.cpp', 'slicing.cpp', 'migrate.cpp', 'pihole_link.cpp', 'guard.cpp', 'reconcile.cpp', 'state.cpp', 'report.cpp', 'gateway.cpp', 'cli.cpp',
                          version_hpp,
                          include_directories : fph_inc,
                          dependencies : [forti_engine, fph_alloc_dep, fph_pihole_dep],
                          implicit_include_directories : false)
fph_core_dep = declare_dependency(include_directories : fph_inc, link_with : fph_core,
                                  dependencies : [forti_engine, fph_alloc_dep, fph_pihole_dep], sources : version_hpp)

forti_pihole_exe = executable('forti-pihole', 'main.cpp',
                                dependencies : fph_core_dep,
                                implicit_include_directories : false,
                                install : true)

# The optional runtime service (src/daemon/meson.build defines forti_piholed_exe and fphd_core_dep).
subdir('daemon')
