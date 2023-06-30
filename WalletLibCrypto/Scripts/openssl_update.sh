#!/bin/bash

SDK_PATH_SIM="`xcode-select --print-path`/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk"
SDK_PATH_IOS="`xcode-select --print-path`/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk"

echo $SDK_PATH_SIM
echo $SDK_PATH_IOS

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

build ios-sim-cc
build ios-arm64-cc
build ios-armv7-cc

echo building $OPENSSL_VERSION for macos-arm64-cc ...
./Configure macos-arm64-cc shared enable-rc5 zlib no-asm 1>>/dev/null
make -j8 1>>/dev/null
cp ./libcrypto.a ./libcrypto-osx.a

cp -r ./include/openssl ../../../OpenSSL/headers/

make clean 1>> /dev/null

lipo \
    "ios-sim-cc/libcrypto.a" \
    "ios-armv7-cc/libcrypto.a" \
    "ios-arm64-cc/libcrypto.a" \
    -create -output ./libcrypto-ios.a

lipo ./libcrypto-ios.a -info
lipo ./libcrypto-osx.a -info

cp ./libcrypto-ios.a ../../../WalletLibCrypto/OpenSSL/libraries/
cp ./libcrypto-osx.a ../../../WalletLibCrypto/OpenSSL/libraries/

cd ..

rm -rf openssl-*
