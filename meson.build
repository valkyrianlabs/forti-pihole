project('forti-vlan-mac', 'cpp',
        version : files('VERSION'),
        meson_version : '>=1.3.0',
        license : 'MIT',
        default_options : ['warning_level=3', 'cpp_std=c++23', 'buildtype=release', 'b_ndebug=if-release', 'forti-api:tests=disabled'])

# Release builds (packages, the release workflow) are buildtype=release: -O3, tested as built.
# Pull-request CI builds unoptimized (-O0) and tests that build (.github/workflows/ci.yml).
cxx = meson.get_compiler('cpp')
if not get_option('debug') and host_machine.system() != 'darwin' and cxx.has_link_argument('-Wl,--gc-sections')
    add_global_arguments('-ffunction-sections', '-fdata-sections', language : 'cpp')
    add_global_link_arguments('-Wl,--gc-sections', language : 'cpp')
endif

# Nothing here is a shared library: hidden visibility keeps forti-api's inline schema tables from
# becoming weak exported symbols that dyld coalesces on every start (~20 ms; forti-cli does the same).
add_global_arguments(cxx.get_supported_arguments('-fvisibility=hidden', '-fvisibility-inlines-hidden'), language : 'cpp')

# The command engine, built from forti-cli's source (subproject; forti-cli builds only the engine
# there). It brings forti-api, the only FortiOS implementation, with it. Unlike forti-mcp, no test
# drives the `forti` executable, so the subproject never builds it.
forti_cli = subproject('forti-cli', default_options : ['subproject_cli=false'])
forti_engine = dependency('forti-engine')

# What `forti-vlan-mac --version` reports about the engine it was built from (src/meson.build).
# Package builds (Debian, Homebrew) use forti-cli at exactly the wrap's pinned revision, from an
# unpacked archive without Git metadata, so the wrap's revision is the answer there. A Git checkout in
# subprojects/forti-cli (the wrap's own clone, or a co-development symlink) reports its actual HEAD,
# marked -dirty with uncommitted changes. Evaluated at configure time.
fs = import('fs')
forti_cli_dir = meson.project_source_root() / 'subprojects' / 'forti-cli'
engine_revision = ''
git = find_program('git', required : false, native : true)
if git.found() and fs.exists(forti_cli_dir / '.git')
    head = run_command(git, '-C', forti_cli_dir, 'rev-parse', '--short=7', 'HEAD', check : false)
    if head.returncode() == 0
        engine_revision = head.stdout().strip()
        changes = run_command(git, '-C', forti_cli_dir, 'status', '--porcelain', '--untracked-files=no', check : false)
        if changes.returncode() == 0 and changes.stdout().strip() != ''
            engine_revision += '-dirty'
        endif
    endif
endif
if engine_revision == ''
    foreach line : fs.read('subprojects/forti-cli.wrap').split('\n')
        words = line.split('=')
        if words.length() == 2 and words[0].strip() == 'revision'
            engine_revision = words[1].strip().substring(0, 7)
        endif
    endforeach
endif
if engine_revision == ''
    error('subprojects/forti-cli.wrap has no revision')
endif
forti_api_version = dependency('forti-api').version()

subdir('src')
subdir('tests')

# The periodic run: a systemd *user* timer, so the program runs as the operator who owns ~/.forti and
# never as root. Installed only, never enabled: each operator opts in with
# `systemctl --user enable --now forti-vlan-mac.timer` (debian/rules keeps debhelper from enabling it).
# The unit's ExecStart names /usr/bin/forti-vlan-mac (the package path); a source install under
# another prefix needs `systemctl --user edit forti-vlan-mac.service`. macOS has no systemd, so
# nothing is installed there.
if host_machine.system() == 'linux'
    install_data('packaging/systemd/forti-vlan-mac.service', 'packaging/systemd/forti-vlan-mac.timer',
                 install_dir : get_option('prefix') / 'lib' / 'systemd' / 'user')
endif

# A starting point for $FORTI_HOME/vlan-mac/config.json; never read from here.
install_data('packaging/config.example.json',
             install_dir : get_option('datadir') / 'forti-vlan-mac')

summary({'engine': 'forti-cli ' + engine_revision, 'forti-api': forti_api_version}, section : 'Built from')
