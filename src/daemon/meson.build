# forti-piholed: the optional runtime service (webhook receiver + scheduler around the reconcile).
# Self-contained on purpose: it needs only the engine (secret store, profiles, nlohmann::json), never
# forti-pihole-core, so the CLI's sources can move without touching it. The reconcile reaches it as a
# callback (daemon.hpp).
fphd_version_hpp = configure_file(output : 'forti_piholed_version.hpp',
                                  configuration : {'FORTI_PIHOLED_VERSION' : '"' + meson.project_version() + '"',
                                                   'FORTI_PIHOLED_BUILT_FROM' : '"engine forti-cli ' + engine_revision
                                                                                 + ', forti-api ' + forti_api_version + '"'})

fphd_inc = include_directories('.')
fphd_deps = [forti_engine, dependency('threads')]

fphd_core = static_library('forti-piholed-core',
                           'net.cpp', 'http.cpp', 'token.cpp', 'events.cpp', 'rate_limit.cpp', 'scheduler.cpp',
                           'daemon_config.cpp', 'daemon_state.cpp', 'log.cpp', 'server.cpp', 'webhook.cpp',
                           'stitch.cpp', 'daemon.cpp', 'setup.cpp',
                           include_directories : fphd_inc,
                           dependencies : fphd_deps,
                           implicit_include_directories : false)
fphd_core_dep = declare_dependency(include_directories : fphd_inc, link_with : fphd_core, dependencies : fphd_deps)

