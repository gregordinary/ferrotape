#!/usr/bin/env bash
# Installs a reference reader the harness runs, from its project's own
# release, checking the release's SHA-256 before anything is unpacked.
#
#   readers.sh install libarchive VERSION SHA256 PREFIX
#       bsdtar, built from libarchive's release tarball with ACL and extended
#       attribute support (libacl's headers are needed: libacl1-dev on
#       Debian and Ubuntu), and without the compression and cryptography
#       libraries, which a tar listing does not use, so the build does not
#       vary with what the host has installed. Fails where the built bsdtar
#       does not report libacl. PREFIX/bin/bsdtar.
#   readers.sh install gnu-tar VERSION SHA256 PREFIX
#       GNU tar, built from GNU's release tarball. PREFIX/bin/tar.
#   readers.sh install go VERSION SHA256 PREFIX
#       Go's release for Linux on x86-64, unpacked. PREFIX/go/bin/go.
#   readers.sh newest libarchive|gnu-tar|go
#       The reader's newest release and its tarball's SHA-256, as its project
#       states them: libarchive's GitHub release, Go's download index, and
#       for GNU tar, which publishes signatures rather than digests, the
#       digest of the tarball whose signature GNU's keyring verifies.
#
# Python's tarfile is the interpreter's own, and is not installed here.

set -euo pipefail

gnu_mirror=https://ftpmirror.gnu.org
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

usage() {
    sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

# Downloads URL to FILE and checks it against SHA256.
fetch() {
    local url=$1 file=$2 sha256=$3
    curl --fail --silent --show-error --location --retry 3 --output "$file" "$url"
    echo "$sha256  $file" | sha256sum --check --strict --quiet
}

install_libarchive() {
    local version=$1 sha256=$2 prefix=$3
    fetch "https://github.com/libarchive/libarchive/releases/download/v$version/libarchive-$version.tar.xz" \
        "$work/libarchive.tar.xz" "$sha256"
    tar -xJf "$work/libarchive.tar.xz" -C "$work"
    mkdir "$work/build"
    (
        cd "$work/build"
        "../libarchive-$version/configure" --prefix="$prefix" \
            --disable-shared --enable-static --enable-bsdtar=static \
            --disable-bsdcat --disable-bsdcpio --disable-bsdunzip \
            --enable-acl --enable-xattr \
            --without-zlib --without-bz2lib --without-libb2 --without-lz4 \
            --without-zstd --without-lzma --without-cng --without-openssl \
            --without-xml2 --without-expat >configure.log 2>&1 ||
            { cat configure.log >&2; exit 1; }
        make -j"$(nproc)" >make.log 2>&1 || { tail -n 50 make.log >&2; exit 1; }
        make install >/dev/null
    )
    # configure drops ACL support silently where libacl's headers are
    # missing; the version line names libacl only where it is linked.
    local reported
    reported=$("$prefix/bin/bsdtar" --version)
    case $reported in
        "bsdtar $version "*libacl/*) echo "$reported" ;;
        *) echo "bsdtar reports \`$reported\`: not $version with libacl" >&2; exit 1 ;;
    esac
}

install_gnu_tar() {
    local version=$1 sha256=$2 prefix=$3
    fetch "$gnu_mirror/tar/tar-$version.tar.xz" "$work/tar.tar.xz" "$sha256"
    tar -xJf "$work/tar.tar.xz" -C "$work"
    (
        cd "$work/tar-$version"
        ./configure --prefix="$prefix" >configure.log 2>&1 || { cat configure.log >&2; exit 1; }
        make -j"$(nproc)" >make.log 2>&1 || { tail -n 50 make.log >&2; exit 1; }
        make install >/dev/null
    )
    "$prefix/bin/tar" --version | head -n 1
}

install_go() {
    local version=$1 sha256=$2 prefix=$3
    fetch "https://go.dev/dl/go$version.linux-amd64.tar.gz" "$work/go.tar.gz" "$sha256"
    mkdir -p "$prefix"
    tar -xzf "$work/go.tar.gz" -C "$prefix"
    "$prefix/go/bin/go" version
}

newest_libarchive() {
    local auth=()
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        auth=(--header "Authorization: Bearer $GITHUB_TOKEN")
    fi
    curl --fail --silent --show-error --location "${auth[@]}" \
        https://api.github.com/repos/libarchive/libarchive/releases/latest |
        python3 -I -c '
import json, sys
release = json.load(sys.stdin)
version = release["tag_name"].removeprefix("v")
for asset in release["assets"]:
    if asset["name"] == f"libarchive-{version}.tar.xz":
        print(version, asset["digest"].removeprefix("sha256:"))
        break
else:
    sys.exit(f"libarchive {version}: no tarball with a digest")
'
}

newest_go() {
    curl --fail --silent --show-error --location 'https://go.dev/dl/?mode=json' |
        python3 -I -c '
import json, sys
release = next(r for r in json.load(sys.stdin) if r["stable"])
for file in release["files"]:
    if file["os"] == "linux" and file["arch"] == "amd64" and file["kind"] == "archive":
        print(release["version"].removeprefix("go"), file["sha256"])
        break
else:
    sys.exit(release["version"] + ": no archive for linux-amd64")
'
}

newest_gnu_tar() {
    local version
    version=$(curl --fail --silent --show-error --location "$gnu_mirror/tar/" |
        grep -oE 'tar-[0-9]+(\.[0-9]+)+\.tar\.xz"' | tr -d '"' |
        sed -e 's/^tar-//' -e 's/\.tar\.xz$//' | sort -V | tail -n 1)
    [ -n "$version" ] || { echo "no GNU tar release listed" >&2; exit 1; }
    for file in "tar/tar-$version.tar.xz" "tar/tar-$version.tar.xz.sig" gnu-keyring.gpg; do
        curl --fail --silent --show-error --location --retry 3 \
            --output "$work/$(basename "$file")" "$gnu_mirror/$file"
    done
    gpg --batch --quiet --homedir "$work" --no-default-keyring \
        --keyring "$work/gnu-keyring.gpg" \
        --verify "$work/tar-$version.tar.xz.sig" "$work/tar-$version.tar.xz" 2>/dev/null ||
        { echo "GNU tar $version: the signature does not verify" >&2; exit 1; }
    echo "$version $(sha256sum "$work/tar-$version.tar.xz" | cut -d ' ' -f 1)"
}

case ${1:-} in
    install)
        [ $# -eq 5 ] || usage
        case $2 in
            libarchive) install_libarchive "$3" "$4" "$5" ;;
            gnu-tar) install_gnu_tar "$3" "$4" "$5" ;;
            go) install_go "$3" "$4" "$5" ;;
            *) usage ;;
        esac
        ;;
    newest)
        [ $# -eq 2 ] || usage
        case $2 in
            libarchive) newest_libarchive ;;
            gnu-tar) newest_gnu_tar ;;
            go) newest_go ;;
            *) usage ;;
        esac
        ;;
    *) usage ;;
esac
