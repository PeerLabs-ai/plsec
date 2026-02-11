# Homebrew Tap Setup

This directory contains the Homebrew formula for plsec.

## Tap Repository Structure

To distribute via Homebrew, create a separate repository:

```
github.com/peerlabs/homebrew-tap/
  Formula/
    plsec.rb          # This formula
    pipelock.rb       # Optional: Pipelock formula
  README.md
```

## Creating the Tap

```bash
# 1. Create the tap repository
mkdir homebrew-tap
cd homebrew-tap
git init

# 2. Create Formula directory
mkdir Formula

# 3. Copy the formula
cp path/to/plsec.rb Formula/

# 4. Update SHA256 hashes
# After publishing a release, get the SHA256:
curl -sL https://github.com/peerlabs/plsec/archive/refs/tags/v0.1.0.tar.gz | shasum -a 256

# 5. Push to GitHub
git add .
git commit -m "Add plsec formula"
git remote add origin git@github.com:peerlabs/homebrew-tap.git
git push -u origin main
```

## User Installation

Once the tap is published:

```bash
# Add the tap
brew tap peerlabs/tap

# Install plsec
brew install plsec

# Or install directly without tapping
brew install peerlabs/tap/plsec
```

## Formula Development

```bash
# Test formula locally
brew install --build-from-source ./Formula/plsec.rb

# Audit the formula
brew audit --strict ./Formula/plsec.rb

# Test the formula
brew test ./Formula/plsec.rb

# Check style
brew style ./Formula/plsec.rb
```

## Updating the Formula

When releasing a new version:

1. Create a GitHub release with a tag (e.g., v0.2.0)
2. Get the tarball SHA256:
   ```bash
   curl -sL https://github.com/peerlabs/plsec/archive/refs/tags/v0.2.0.tar.gz | shasum -a 256
   ```
3. Update the formula:
   - Change `url` to new version
   - Update `sha256`
4. Commit and push to homebrew-tap repository

## Python Resource Hashes

To get SHA256 hashes for Python dependencies:

```bash
# Using pip
pip download typer rich pyyaml pydantic pydantic-settings --no-deps -d /tmp/deps
shasum -a 256 /tmp/deps/*.tar.gz

# Or use poet (Homebrew tool)
brew install poet
poet typer rich pyyaml pydantic pydantic-settings
```

## CI/CD Integration

Add to `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          generate_release_notes: true

      - name: Update Homebrew Formula
        env:
          HOMEBREW_TAP_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}
        run: |
          VERSION=${GITHUB_REF#refs/tags/v}
          SHA256=$(curl -sL https://github.com/${{ github.repository }}/archive/refs/tags/v${VERSION}.tar.gz | shasum -a 256 | cut -d' ' -f1)

          # Clone tap repo and update formula
          git clone https://x-access-token:${HOMEBREW_TAP_TOKEN}@github.com/peerlabs/homebrew-tap.git
          cd homebrew-tap

          sed -i "s|url \".*\"|url \"https://github.com/peerlabs/plsec/archive/refs/tags/v${VERSION}.tar.gz\"|" Formula/plsec.rb
          sed -i "s|sha256 \".*\"|sha256 \"${SHA256}\"|" Formula/plsec.rb

          git config user.name "GitHub Actions"
          git config user.email "actions@github.com"
          git add Formula/plsec.rb
          git commit -m "Update plsec to v${VERSION}"
          git push
```

## Optional: Pipelock Formula

If Pipelock is not already in Homebrew, create a formula:

```ruby
class Pipelock < Formula
  desc "Security proxy for AI coding assistants"
  homepage "https://github.com/luckyPipewrench/pipelock"
  url "https://github.com/luckyPipewrench/pipelock/archive/refs/tags/v0.1.4.tar.gz"
  sha256 "PLACEHOLDER"
  license "Apache-2.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/pipelock"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pipelock version")
  end
end
```
