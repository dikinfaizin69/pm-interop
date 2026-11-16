//
//  PQXDH stub — the copied PrekeyBundle.swift references PQXDH only inside
//  CryptoIdentity (identity generation), which is not on the decode path.
//  macOS always satisfies `#available(iOS 26.0, *)` via the `*` clause, so the
//  symbols must exist. Values are deterministic filler; no claim depends on them.
//

import Foundation

enum PQXDH {
    struct Keypair {
        var seed: Data
        var encapsulationKey: Data
    }

    static func generate() throws -> Keypair {
        let seed = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        return try keypair(fromSeed: seed)
    }

    static func keypair(fromSeed seed: Data) throws -> Keypair {
        Keypair(seed: seed, encapsulationKey: Data(repeating: 0xAB, count: 1216))
    }
}
