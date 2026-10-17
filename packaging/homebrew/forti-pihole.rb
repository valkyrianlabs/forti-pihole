# frozen_string_literal: true

# Formula template. `vlr homebrew formula` renders the release url/sha256 into
# release/homebrew/forti-pihole.rb, which `vlr homebrew publish` commits to valkyrianlabs/homebrew-tap.
class FortiPihole < Formula
  desc "FortiGate network identity and Pi-hole DNS policy synchronization"
  homepage "https://github.com/valkyrianlabs/forti-pihole"
  url "https://github.com/valkyrianlabs/forti-pihole/releases/download/v0.1.0/forti-pihole-0.1.0.tar.gz"
  sha256 "TODO_REPLACE_WITH_RELEASE_ARCHIVE_SHA256"
  license "MIT"
  head "https://github.com/valkyrianlabs/forti-pihole.git", branch: "main"

  # Header-only SDK: needed to compile, not at run time.
  depends_on "forti-api" => :build
  depends_on "meson" => :build
  depends_on "ninja" => :build
  depends_on "pkgconf" => :build

  uses_from_macos "curl"

  # The command engine, compiled in from forti-cli's source at exactly the revision
  # subprojects/forti-cli.wrap pins (packaging/forti-cli-pin.sh keeps the two in step). forti-pihole
  # needs neither the forti-cli formula nor the `forti` executable at run time; profiles are
  # usually created with `forti configure`, so install valkyrianlabs/tap/forti-cli as well.
  resource "forti-cli" do
    url "https://github.com/valkyrianlabs/forti-cli/archive/6a17b34a7b8f4aaedeee33a9f4ea71a71f73f855.tar.gz"
    sha256 "3193e73a3d8d660b821c1960f8d0bb3b29b8b10f96fb8a10f55cc4f500b14421"
  end

  def install
    # Meson uses an existing subprojects/forti-cli as is, so nothing is fetched during the build.
    resource("forti-cli").stage buildpath/"subprojects/forti-cli"

    # std_meson_args sets --buildtype=release and --wrap-mode=nofallback: forti-api always comes from
    # the forti-api formula, never from subprojects/forti-api.wrap.
    # optimization=3 is meson.build's release profile, repeated so it holds whatever the build type;
    # strip=true installs the binary without its symbol table.
    # The tests need GoogleTest and run in CI; the `test do` block exercises the installed binary.
    # meson.build installs the systemd user units only on Linux, so a macOS install has none.
    system "meson", "setup", "build", "-Dtests=disabled", "-Doptimization=3", "-Dstrip=true", *std_meson_args
    system "meson", "compile", "-C", "build"
    system "meson", "install", "-C", "build", "--skip-subprojects"
  end

  def caveats
    <<~EOS
      Configure a device profile with `forti configure` (valkyrianlabs/tap/forti-cli), then write
      ~/.forti/pihole/config.json (example: #{opt_pkgshare}/config.example.json) and start with:
        forti-pihole setup
    EOS
  end

  # `brew services start forti-pihole`: the optional receiver/scheduler under launchd (macOS) or a
  # systemd user unit (Linuxbrew), in the foreground and restarted if it crashes. It logs to stderr in
  # logfmt; without a daemon.json it listens on 127.0.0.1:8735 only and runs periodic reconciles.
  service do
    run [opt_bin/"forti-piholed", "--foreground"]
    keep_alive crashed: true
    process_type :background
    log_path var/"log/forti-piholed.log"
    error_log_path var/"log/forti-piholed.log"
  end

  test do
    # Offline: neither needs a profile, a device or the network.
    ENV["FORTI_HOME"] = (testpath/"forti").to_s
    assert_match "forti-pihole #{version} (engine forti-cli ", shell_output("#{bin}/forti-pihole --version")
    help = shell_output("#{bin}/forti-pihole --help")
    %w[setup discover devices plan sync assign status history].each do |command|
      assert_match command, help
    end
    assert_match "forti-piholed #{version} (engine forti-cli ", shell_output("#{bin}/forti-piholed --version")
    assert_match "/v1/fortigate/events", shell_output("#{bin}/forti-piholed --help")
  end
end
