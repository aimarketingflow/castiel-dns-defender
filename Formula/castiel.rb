# Homebrew Formula for Castiel
# This file is maintained by goreleaser and published to castiel/homebrew-tap

class Castiel < Formula
  desc "Real-time DNS attack detection, prevention, and alerting"
  homepage "https://github.com/aimarketingflow/castiel-dns-defender"
  url "https://github.com/aimarketingflow/castiel-dns-defender/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"
  license "Apache-2.0"
  head "https://github.com/aimarketingflow/castiel-dns-defender.git", branch: "main"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.version=#{version}", output: bin/"castiel")
    system "go", "build", "-o", bin/"attack-sim", "./cmd/attack-sim/"
    etc.install "config.yaml" => "castiel/config.yaml"
    (etc/"castiel/data").install Dir["data/*"]
  end

  def caveats
    <<~EOS
      Castiel requires root to set up PF firewall redirect.

      To run:
        sudo #{bin}/castiel -config #{etc}/castiel/config.yaml

      To install as a LaunchDaemon:
        sudo make install
    EOS
  end

  test do
    assert_match "castiel", shell_output("#{bin}/castiel -version 2>&1", 1)
  end
end
