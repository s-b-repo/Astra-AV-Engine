# Installation

## Requirements

| Dependency | Version | Why |
|---|---|---|
| Go | 1.24 or newer | the engine is a single Go module |
| libyara with headers | 4.3 or newer | YARA runs in-process through [go-yara](https://github.com/hillu/go-yara); the `yara` binary is not needed |
| pkg-config | any | go-yara locates libyara through it |
| a C compiler | any | cgo, for the libyara binding |

Supported targets are Linux and macOS. Windows builds work with a libyara
installation that pkg-config can find, but are not exercised by CI.

```sh
# Debian / Ubuntu / Kali
sudo apt install golang-go libyara-dev pkg-config build-essential
# Fedora
sudo dnf install golang yara-devel pkgconf-pkg-config gcc
# macOS
brew install go yara pkg-config
```

## Build from source

```sh
git clone https://github.com/s-b-repo/cau.git cau
cd cau
make build          # -> ./cau
./cau version
```

`make build` stamps the version from `git describe`. The plain `go build .`
also works and produces a binary that reports `0.4.0-dev`.

### User-local toolchain

If Go or libyara are installed under your home directory rather than
system-wide, `scripts/dev-env.sh` exports `PATH`, `PKG_CONFIG_PATH`,
`LD_LIBRARY_PATH` and `CGO_ENABLED=1` for a layout of `~/.local/go` and
`~/.local/yara`:

```sh
source scripts/dev-env.sh
make build
```

The build fails with `package yara was not found in the pkg-config search
path` when pkg-config cannot see libyara; the script, or an exported
`PKG_CONFIG_PATH`, is the fix.

## Install

```sh
sudo make install                      # PREFIX=/usr/local by default
make install PREFIX=$HOME/.local       # no root
```

This installs:

| Path | Content |
|---|---|
| `$PREFIX/bin/cau` | the binary |
| `$PREFIX/share/cau/rules/*.yar` | the bundled YARA rules |
| `$PREFIX/share/cau/signatures/hashes.txt` | the hash signature database |
| `$PREFIX/share/cau/signatures/fuzzy.txt` | the fuzzy-hash database (empty on purpose, see [Detection content](detection-content.md)) |

## Release tarballs

CI builds `cau-<tag>-linux-amd64.tar.gz` with the rules and signatures for
every `v*` tag and attaches it to the GitHub release together with
`SHA256SUMS`. No tag has been cut yet; until then, build from source.

## Resource discovery

The binary looks for its signature database, rules directory and fuzzy
database in this order and uses the first that exists:

1. the flag (`--db`, `--rules`, `--fuzzy-db`)
2. the environment (`CAU_SIGNATURES`, `CAU_RULES`, `CAU_FUZZY`)
3. next to the binary (`<dir of cau>/signatures/hashes.txt`, `<dir of cau>/rules`)
4. the share directory relative to the binary (`<dir of cau>/../share/cau/...`)
5. `/usr/local/share/cau` and `/usr/share/cau`
6. the current working directory

When nothing is found, the error lists every path that was tried. A missing
signature database is fatal; missing rules or a missing fuzzy database turn
that detector off with a message on stderr, because the README advertising a
feature that silently did not run was one of the bugs this fork fixed.

## Verify the installation

```sh
cau scan --file corpus/smoke/malicious/mimikatz_strings.bin --db corpus/smoke/hashes.txt
echo "exit $?"          # 1: a YARA rule matched
make eval               # validate the smoke corpus, run it, gate against the baseline
```
