# Homebrew formula template (live copy: github.com/deja-app/homebrew-tap/Formula/dsr-verifier-cli.rb)
#
# Install:
#   brew install deja-app/tap/dsr-verifier-cli
#
# The sha256 placeholders below are replaced by the release CI pipeline
# (release.yml → Dispatch Homebrew tap update → tap-update-workflow.yml).
# Do not hand-edit the sha256 values; they are set automatically on each tag push.

class DsrVerifierCli < Formula
  desc "Offline DSR/1.0.1 receipt and evidence bundle verifier"
  homepage "https://github.com/deja-app/dsr-verifier-cli"
  license "MIT"
  version "1.4.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/deja-app/dsr-verifier-cli/releases/download/v#{version}/dsr-verifier-cli-v#{version}-darwin-arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_DARWIN_ARM64"

      def install
        bin.install "dsr-verifier-cli"
      end
    end

    if Hardware::CPU.intel?
      url "https://github.com/deja-app/dsr-verifier-cli/releases/download/v#{version}/dsr-verifier-cli-v#{version}-darwin-amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_DARWIN_AMD64"

      def install
        bin.install "dsr-verifier-cli"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/deja-app/dsr-verifier-cli/releases/download/v#{version}/dsr-verifier-cli-v#{version}-linux-arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_LINUX_ARM64"

      def install
        bin.install "dsr-verifier-cli"
      end
    end

    if Hardware::CPU.intel?
      url "https://github.com/deja-app/dsr-verifier-cli/releases/download/v#{version}/dsr-verifier-cli-v#{version}-linux-amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_LINUX_AMD64"

      def install
        bin.install "dsr-verifier-cli"
      end
    end
  end

  test do
    assert_match "dsr-verifier-cli v#{version}", shell_output("#{bin}/dsr-verifier-cli --version")
    assert_match "offline", shell_output("#{bin}/dsr-verifier-cli --help")
  end
end
