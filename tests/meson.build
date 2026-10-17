# Network-free tests: nothing here talks to a FortiGate. The commands run against an in-memory
# FortiGate (support/fake_gateway.hpp) and a temporary forti home.
gtest_dep = dependency('gtest', main : true, required : get_option('tests'))

# Sanitizer builds leave the engine shards uninstrumented (forti-cli's engine/meson.build); see
# forti-mcp's tests/meson.build for why container-overflow is off there.
asan_options = get_option('b_sanitize').contains('address') ? 'detect_container_overflow=0' : ''
if gtest_dep.found()
    unit_tests = executable('unitTests',
                            'unit/test_basics.cpp',
                            'unit/test_classify.cpp',
                            'unit/test_reconcile.cpp',
                            'unit/test_cli.cpp',
                            include_directories : include_directories('support'),
                            dependencies : [fph_core_dep, gtest_dep],
                            implicit_include_directories : false)
    test('unit', unit_tests,
         env : asan_options != '' ? {'ASAN_OPTIONS' : asan_options} : {},
         suite : 'unit')

    # forti-piholed (src/daemon): parser, auth, scheduler, state, stitch operations, and real sockets
    # on 127.0.0.1 only. The stitch test also checks forti-api's 7.4.8 schema snapshot when a source
    # checkout of forti-api provides it (package builds use the installed SDK, which has none).
    daemon_env = asan_options != '' ? {'ASAN_OPTIONS' : asan_options} : {}
    schema_dir = meson.project_source_root() / 'subprojects' / 'forti-api' / 'codegen' / 'schema' / '7.4.8' / 'cmdb' / 'system'
    if fs.exists(schema_dir / 'automation-action.json')
        daemon_env += {'FPHD_SCHEMA_DIR' : schema_dir}
    endif
    daemon_tests = executable('daemonTests',
                              'daemon/test_http.cpp',
                              'daemon/test_auth.cpp',
                              'daemon/test_scheduler.cpp',
                              'daemon/test_state.cpp',
                              'daemon/test_stitch.cpp',
                              'daemon/test_server.cpp',
                              dependencies : [fphd_core_dep, gtest_dep],
                              implicit_include_directories : false)
    test('daemon', daemon_tests, env : daemon_env, suite : 'unit', timeout : 120)
endif
