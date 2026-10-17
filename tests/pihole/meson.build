# The Pi-hole client (src/pihole): unit tests on a scripted transport (suite 'unit'), and the real
# libcurl transport against tests/mock-pihole, a stateful Python stdlib mock that harness.py starts
# on 127.0.0.1 (suite 'integration'). Nothing here reaches a real Pi-hole.
if gtest_dep.found()
    pihole_unit_tests = executable('piholeUnitTests',
                                   'test_model.cpp', 'test_resolve.cpp', 'test_transport.cpp', 'test_client.cpp',
                                   dependencies : [fph_pihole_dep, gtest_dep],
                                   implicit_include_directories : false)
    test('pihole-unit', pihole_unit_tests, suite : 'unit')

    pihole_integration_tests = executable('piholeIntegrationTests', 'test_integration.cpp',
                                          dependencies : [fph_pihole_dep, gtest_dep],
                                          implicit_include_directories : false)
    pihole_python = find_program('python3', required : false)
    if pihole_python.found()
        test('pihole-mock', pihole_python,
             args : [files('../mock-pihole/harness.py'), '--binary', pihole_integration_tests.full_path()],
             env : {'PYTHONDONTWRITEBYTECODE' : '1'},
             depends : pihole_integration_tests, suite : 'integration', timeout : 120)
        # The mock models the FTL behaviours the client depends on; this keeps it honest.
        test('pihole-mock-selftest', pihole_python, args : [files('../mock-pihole/test_mock.py')],
             env : {'PYTHONDONTWRITEBYTECODE' : '1'}, suite : 'integration', timeout : 60)
    endif
endif
