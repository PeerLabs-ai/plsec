# Homebrew Formula for plsec
#
# To use this formula:
#   1. Create a tap: brew tap peerlabs/tap
#   2. Install: brew install peerlabs/tap/plsec
#
# Or install directly:
#   brew install --formula ./homebrew/plsec.rb
#
# For development, you can also install from local path:
#   brew install --build-from-source ./homebrew/plsec.rb

class Plsec < Formula
  include Language::Python::Virtualenv

  desc "Security tooling for AI coding assistants"
  homepage "https://github.com/peerlabs/plsec"
  url "https://github.com/peerlabs/plsec/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"  # Update with actual sha256
  license "Apache-2.0"
  head "https://github.com/peerlabs/plsec.git", branch: "main"

  depends_on "python@3.12"
  depends_on "trivy"

  # Optional dependencies
  depends_on "pipelock" => :optional
  depends_on "podman" => :optional

  resource "typer" do
    url "https://files.pythonhosted.org/packages/typer/typer-0.12.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/rich/rich-13.7.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "pyyaml" do
    url "https://files.pythonhosted.org/packages/pyyaml/PyYAML-6.0.1.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "pydantic" do
    url "https://files.pythonhosted.org/packages/pydantic/pydantic-2.6.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "pydantic-settings" do
    url "https://files.pythonhosted.org/packages/pydantic-settings/pydantic_settings-2.2.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  def install
    virtualenv_install_with_resources
  end

  def post_install
    # Create plsec home directory
    (var/"plsec").mkpath
    (var/"plsec/logs").mkpath
    (var/"plsec/configs").mkpath
  end

  def caveats
    <<~EOS
      plsec has been installed.

      To get started:
        plsec doctor        # Check dependencies
        plsec init          # Initialize a project

      Optional tools for enhanced security:
        brew install pipelock   # Runtime proxy (if available)
        brew install podman     # Container isolation
        brew install bandit     # Python security scanner
        pip install semgrep     # Multi-language scanner

      Configuration is stored in:
        ~/.plsec/

      For more information:
        plsec --help
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/plsec --version")
    assert_match "plsec", shell_output("#{bin}/plsec --help")
  end
end
