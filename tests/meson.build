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
                            'unit/test_cli_sync.cpp',
                            'unit/test_references.cpp',
                            'unit/test_operation.cpp',
                            'unit/test_pihole_sync.cpp',
                            'unit/test_slicing.cpp',
                            'unit/test_migrate.cpp',
                            'unit/test_migration_run.cpp',
                            include_directories : include_directories('support'),
                            dependencies : [fph_core_dep, gtest_dep],
                            implicit_include_directories : false)
    test('unit', unit_tests,
         env : asan_options != '' ? {'ASAN_OPTIONS' : asan_options} : {},
         suite : 'unit')

    alloc_tests = executable('allocTests',
                             'alloc/test_cidr.cpp',
                             'alloc/test_plan.cpp',
                             'alloc/test_household.cpp',
                             dependencies : [fph_alloc_dep, gtest_dep],
                             implicit_include_directories : false)
    test('alloc', alloc_tests, suite : 'unit')
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

# The Pi-hole client's tests (tests/pihole/meson.build).
subdir('pihole')

# The real binaries end to end (tests/integration, suite 'integration'): forti-pihole and forti-piholed
# through the real engine (libcurl, verified TLS, plan/apply, audit, rollback plans) against forti-cli's
# stateful mock FortiOS, which the test extends from here, and tests/mock-pihole. forti-cli exports the
# mock's directory even with subproject_cli=false. Exit 77 (skipped) without openssl or the mock.
fph_mock_fortios_dir = forti_cli.get_variable('mock_fortios_dir', '')
fph_python = find_program('python3', required : false)
if fph_python.found() and not get_option('tests').disabled()
    test('pihole-e2e', fph_python, args : [files('integration/test_forti_pihole.py')],
         env : {'FPH_BINARY' : forti_pihole_exe.full_path(), 'FPH_DAEMON' : forti_piholed_exe.full_path(),
                'FORTI_MOCK_DIR' : fph_mock_fortios_dir, 'PYTHONDONTWRITEBYTECODE' : '1'}
              + (asan_options != '' ? {'ASAN_OPTIONS' : asan_options} : {}),
         depends : [forti_pihole_exe, forti_piholed_exe], suite : 'integration', timeout : 300)
endif
