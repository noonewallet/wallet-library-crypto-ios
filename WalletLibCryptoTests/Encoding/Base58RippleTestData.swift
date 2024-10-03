//
//  Base58RippleTestData.swift
//  WalletLibCryptoTests
//
//

import Foundation

let base58RippleValidTestData: [(hex: String, string: String)] = [
    (hex: "", string: ""),
    (hex: "61", string: "pg"),
    (hex: "626262", string: "2sgV"),
    (hex: "636363", string: "2PNi"),
    (hex: "73696d706c792061206c6f6e6720737472696e67", string: "pcEuFj68N1S8n9qHX1tmKpCCFLvp"),
    (hex: "00eb15231dfceb60925886b67d065299925915aeb172c06647", string: "r4Srf52g9jJgTHDrVXjvLUN8ZuQsiJDN9L"),
    (hex: "516b6fcd0f", string: "wB8LTmg"),
    (hex: "bf4f89001e670274dd", string: "sSNosLWLoP8tU"),
    (hex: "572e4794", string: "sNE7fm"),
    (hex: "ecac89cad93923c02321", string: "NJDM3diCXwauyw"),
    (hex: "10c8511e", string: "Rtnzm"),
//    (hex: "00000000000000000000", string: "rrrrrrrrrr"),
    (hex: "801184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd206ec97e", string: "nHxrnHEGyeFpUCPx1JKepCXJ1UV8nDN5yoeGGEaJZjGbTR8qC5D"),
    (hex: "003c176e659bea0f29a3e9bf7880c112b1b31b4dc826268187", string: "ra7jcY4BG9GTKhuqpCfyYNbu5CqUzoLMGS")
  ]

let base58RippleInvalidTestData: [String] = [ "ac2Flb3NoaQo", "ac2Fb3NoaQo=", "c2F b3NoaQo", "c2F0b3NoaQo", "c2Fb3N=oaQo"]
