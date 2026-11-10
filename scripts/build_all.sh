#!/bin/bash
# build_all.sh — build the pinned stack from pack/fixtures/:
#   liboqs 0.16.0 reference (OQS_OPT_TARGET=generic) and optimized
#   (OQS_OPT_TARGET=auto), then oqs-provider 0.12.0 against each, and the
#   bench_liboqs harness against each liboqs.
# Usage: build_all.sh [workdir]
# workdir defaults to <pack>/../work. Skips the build when both provider
# .so files and both bench binaries already exist (set FORCE_BUILD=1 to
# rebuild). Logs go to <workdir>/build-*.log.
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$PACK/../work}"
mkdir -p "$WORK"
cd "$WORK"

if [ "${FORCE_BUILD:-0}" != "1" ] && [ -f "$WORK/oqs-ref-mod/oqsprovider.so" ] \
   && [ -f "$WORK/oqs-opt-mod/oqsprovider.so" ] \
   && [ -f "$WORK/bench_liboqs_ref" ] && [ -f "$WORK/bench_liboqs_opt" ]; then
  echo "build_all: provider .so files and bench binaries already present; skipping (FORCE_BUILD=1 to rebuild)"
  exit 0
fi

set -e
[ -d liboqs-0.16.0 ] || tar xzf "$PACK/fixtures/liboqs-0.16.0.tar.gz"
[ -d oqs-provider-0.12.0 ] || tar xzf "$PACK/fixtures/oqs-provider-0.12.0.tar.gz"

echo "=== liboqs reference build (OQS_OPT_TARGET=generic) ==="
cmake -S liboqs-0.16.0 -B build-ref \
  -DCMAKE_BUILD_TYPE=Release \
  -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DCMAKE_INSTALL_PREFIX="$WORK/install-ref" > build-ref-cmake.log 2>&1
cmake --build build-ref -j2 > build-ref-make.log 2>&1
cmake --install build-ref > build-ref-install.log 2>&1

echo "=== liboqs optimized build (OQS_OPT_TARGET=auto) ==="
cmake -S liboqs-0.16.0 -B build-opt \
  -DCMAKE_BUILD_TYPE=Release \
  -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=auto \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DCMAKE_INSTALL_PREFIX="$WORK/install-opt" > build-opt-cmake.log 2>&1
cmake --build build-opt -j2 > build-opt-make.log 2>&1
cmake --install build-opt > build-opt-install.log 2>&1

for V in ref opt; do
  echo "=== oqs-provider build ($V) ==="
  rm -rf "oqsbuild-$V"
  liboqs_DIR="$WORK/install-$V" cmake -S oqs-provider-0.12.0 -B "oqsbuild-$V" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$WORK/oqs-$V" > "build-oqs-$V-cmake.log" 2>&1
  cmake --build "oqsbuild-$V" -j2 > "build-oqs-$V-make.log" 2>&1
  # NOTE: cmake --install writes oqsprovider.so into the system OpenSSL
  # modules directory (OPENSSL_MODULES_PATH defaults to the OpenSSL lib
  # dir), not the prefix. Use the .so straight from the build tree instead.
  mkdir -p "$WORK/oqs-$V-mod"
  cp "oqsbuild-$V/lib/oqsprovider.so" "$WORK/oqs-$V-mod/oqsprovider.so"
  echo "=== oqs-provider ($V) ready: $WORK/oqs-$V-mod/oqsprovider.so ==="
done

echo "=== bench harness ==="
cc -O2 -I"$WORK/install-ref/include" "$PACK/src/bench_liboqs.c" \
  -L"$WORK/install-ref/lib" -loqs -lcrypto -o "$WORK/bench_liboqs_ref"
cc -O2 -I"$WORK/install-opt/include" "$PACK/src/bench_liboqs.c" \
  -L"$WORK/install-opt/lib" -loqs -lcrypto -o "$WORK/bench_liboqs_opt"
echo "build_all: DONE"
sha256sum "$WORK/oqs-ref-mod/oqsprovider.so" "$WORK/oqs-opt-mod/oqsprovider.so"
