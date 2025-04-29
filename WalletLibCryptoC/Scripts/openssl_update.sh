#!/bin/bash

SDK_PATH_SIM="`xcode-select --print-path`/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk"
SDK_PATH_IOS="`xcode-select --print-path`/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk"
SDK_PATH_MACOS="`xcode-select --print-path`/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"

echo $SDK_PATH_SIM
echo $SDK_PATH_IOS
echo $SDK_PATH_MACOS

OPENSSL_MVERSION="1.1.1"
OPENSSL_VERSION="1.1.1j"

rm -rf openssl-*

curl -O -L http://www.openssl.org/source/old/$OPENSSL_MVERSION/openssl-$OPENSSL_VERSION.tar.gz
tar xfz "openssl-${OPENSSL_VERSION}.tar.gz"

cd "openssl-${OPENSSL_VERSION}"

patch -f ./Configurations/10-main.conf < ../openssl_config.patch

build() {
    PLATFORM=$1

    echo building $OPENSSL_VERSION for $PLATFORM ...

    if [[ -d "./$PLATFORM" ]]
    then
        rm -rf "./$PLATFORM"
    fi

    mkdir "./$PLATFORM"

    ./Configure $PLATFORM "-fembed-bitcode" no-asm no-shared no-hw no-async 1>>/dev/null

    make -j8 1>>/dev/null
    cp libcrypto.a ./$PLATFORM/

    make clean 1>> /dev/null
}

build ios-sim-x86_64-cc
build ios-sim-arm64-cc
build ios-arm64-cc
build ios-armv7-cc
build macos-cc

mkdir -p ios-sim-fat
mkdir -p ios-fat

lipo -create \
    ios-sim-x86_64-cc/libcrypto.a \
    ios-sim-arm64-cc/libcrypto.a \
    -output ios-sim-fat/libcrypto.a
    
lipo -create \
    ios-arm64-cc/libcrypto.a \
    ios-armv7-cc/libcrypto.a \
    -output ios-fat/libcrypto.a

xcodebuild -create-xcframework \
    -library ios-sim-fat/libcrypto.a \
    -headers ../../../WalletLibCrypto/OpenSSL/Headers \
    -library ios-fat/libcrypto.a \
    -headers ../../../WalletLibCrypto/OpenSSL/Headers \
    -library macos-cc/libcrypto.a \
    -headers ../../../WalletLibCrypto/OpenSSL/Headers \
    -output ./libcrypto.xcframework

cp -r ./libcrypto.xcframework ../../../WalletLibCrypto/OpenSSL

cd ..

rm -rf openssl-*
