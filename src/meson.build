# forti_vlan_mac_version.hpp carries the project version and what it was built from (the forti-cli
# engine revision and the forti-api version; see the top-level meson.build) into --version.
version_hpp = configure_file(output : 'forti_vlan_mac_version.hpp',
                             configuration : {'FORTI_VLAN_MAC_VERSION' : '"' + meson.project_version() + '"',
                                              'FORTI_VLAN_MAC_BUILT_FROM' : '"engine forti-cli ' + engine_revision
                                                                            + ', forti-api ' + forti_api_version + '"'})

fvm_inc = include_directories('.')

# Everything but main(): the executable and the unit tests link the same library.
fvm_core = static_library('forti-vlan-mac-core',
                          'mac.cpp', 'config.cpp', 'inventory.cpp', 'address_match.cpp', 'classify.cpp', 'reassociate.cpp',
                          'connectivity.cpp', 'guard.cpp', 'reconcile.cpp', 'state.cpp', 'report.cpp', 'gateway.cpp', 'cli.cpp',
                          version_hpp,
                          include_directories : fvm_inc,
                          dependencies : forti_engine,
                          implicit_include_directories : false)
fvm_core_dep = declare_dependency(include_directories : fvm_inc, link_with : fvm_core,
                                  dependencies : forti_engine, sources : version_hpp)

forti_vlan_mac_exe = executable('forti-vlan-mac', 'main.cpp',
                                dependencies : fvm_core_dep,
                                implicit_include_directories : false,
                                install : true)
