#
#  Be sure to run `pod spec lint WalletLibCrypto.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see http://docs.cocoapods.org/specification.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |s|

  s.name         = "WalletLibCrypto"
  s.version      = "1.0"
  s.summary      = "The WalletLibCrypto library is an implementation of tools for working with cryptocurrencies"
  s.homepage	 = "https://github.com/noonewallet/wallet-library-crypto-ios"

  s.license      = "MIT"
  s.author       = "WalletLibCrypto"

  s.platform     = :ios, "10.0"
  s.source       = { :git => "https://github.com/noonewallet/wallet-library-crypto-ios.git", :tag => "v#{s.version}" }
  s.swift_version = '5.0'

  s.ios.vendored_libraries = 'WalletLibCrypto/OpenSSL/libraries/libcrypto-ios.a'
  s.osx.vendored_libraries = 'WalletLibCrypto/OpenSSL/libraries/libcrypto-osx.a'

  s.ios.deployment_target = "11.0"
  s.osx.deployment_target = "11.0"

  s.source_files  = 'WalletLibCrypto/WalletLibCrypto.h', 'WalletLibCrypto/PrivateHeaders/*{h}', 'WalletLibCrypto/**/*{m,c,swift}', 'WalletLibCrypto/OpenSSL'

  s.module_map    = 'WalletLibCrypto/WalletLibCrypto.modulemap'

  s.private_header_files = 'WalletLibCrypto/PrivateHeaders/**/*{h}'

  s.pod_target_xcconfig = { 
    'SWIFT_INCLUDE_PATHS' => "#{File.join(File.dirname(__FILE__))}/WalletLibCrypto/OpenSSL/libraries/**",  
    'LIBRARY_SEARCH_PATHS' => "#{File.join(File.dirname(__FILE__))}/WalletLibCrypto/OpenSSL/libraries/**",
    'HEADER_SEARCH_PATHS' => "#{File.join(File.dirname(__FILE__))}/WalletLibCrypto/OpenSSL/headers/**"
  }

end
