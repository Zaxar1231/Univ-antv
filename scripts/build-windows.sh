#!/usr/bin/env bash
# Сборка .exe для Windows 7 и новее: 64-битная и 32-битная версии.
#
# Нужно на Linux: пакеты gcc-mingw-w64-x86-64 и gcc-mingw-w64-i686 (Ubuntu/Debian),
# rustup. Rust 1.77.2 — последняя версия с поддержкой Windows 7; новее собранный exe
# не запустится на Windows 7.
set -euo pipefail

cd "$(dirname "$0")/.."

TOOLCHAIN=1.77.2
TARGETS=(x86_64-pc-windows-gnu i686-pc-windows-gnu)

rustup toolchain install "$TOOLCHAIN" --profile minimal
rustup target add --toolchain "$TOOLCHAIN" "${TARGETS[@]}"

for target in "${TARGETS[@]}"; do
    cargo +"$TOOLCHAIN" build --release --locked --target "$target"
done

rm -rf dist
mkdir dist
cp target/x86_64-pc-windows-gnu/release/antv.exe dist/antv-x64.exe
cp target/i686-pc-windows-gnu/release/antv.exe dist/antv-x86.exe
(cd dist && sha256sum antv-x64.exe antv-x86.exe > SHA256SUMS.txt)

echo "Готово:"
ls -l dist
