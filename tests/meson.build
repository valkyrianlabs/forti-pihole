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
                            'unit/test_references.cpp',
                            'unit/test_operation.cpp',
                            'unit/test_pihole_sync.cpp',
                            include_directories : include_directories('support'),
                            dependencies : [fph_core_dep, gtest_dep],
                            implicit_include_directories : false)
    test('unit', unit_tests,
         env : asan_options != '' ? {'ASAN_OPTIONS' : asan_options} : {},
         suite : 'unit')
endif
