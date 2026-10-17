# forti_pihole_version.hpp carries the project version and what it was built from (the forti-cli
# engine revision and the forti-api version; see the top-level meson.build) into --version.
version_hpp = configure_file(output : 'forti_pihole_version.hpp',
                             configuration : {'FORTI_PIHOLE_VERSION' : '"' + meson.project_version() + '"',
                                              'FORTI_PIHOLE_BUILT_FROM' : '"engine forti-cli ' + engine_revision
                                                                            + ', forti-api ' + forti_api_version + '"'})

fph_inc = include_directories('.')

# Everything but main(): the executable and the unit tests link the same library.
fph_core = static_library('forti-pihole-core',
                          'mac.cpp', 'config.cpp', 'inventory.cpp', 'address_match.cpp', 'classify.cpp', 'reassociate.cpp',
                          'connectivity.cpp', 'guard.cpp', 'reconcile.cpp', 'state.cpp', 'report.cpp', 'gateway.cpp', 'cli.cpp',
                          version_hpp,
                          include_directories : fph_inc,
                          dependencies : forti_engine,
                          implicit_include_directories : false)
fph_core_dep = declare_dependency(include_directories : fph_inc, link_with : fph_core,
                                  dependencies : forti_engine, sources : version_hpp)

forti_pihole_exe = executable('forti-pihole', 'main.cpp',
                                dependencies : fph_core_dep,
                                implicit_include_directories : false,
                                install : true)

# The Pi-hole API client library (src/pihole/meson.build defines fph_pihole_dep).
subdir('pihole')
