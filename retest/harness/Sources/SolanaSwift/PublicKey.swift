//
//  SolanaSwift stub — only the symbols the copied PrivaMesh files reference.
//  Base58 is implemented properly (Bitcoin alphabet) so address validation in
//  ContactCard.hasValidAddress / PrekeyBundle.isBoundTo behaves like the real SDK.
//

import Foundation

public struct PublicKey: Hashable {
    public static let numberOfBytes = 32
    public let data: Data
    public var bytes: [UInt8] { [UInt8](data) }

    public init(data: Data) throws {
        guard data.count == PublicKey.numberOfBytes else {
            throw PublicKeyError.invalidLength
        }
        self.data = data
    }

    public init(string: String) throws {
        guard let decoded = Base58.decode(string), decoded.count == PublicKey.numberOfBytes else {
            throw PublicKeyError.invalidBase58
        }
        self.data = decoded
    }

    public var base58EncodedString: String { Base58.encode(data) }
}

public enum PublicKeyError: Error {
    case invalidLength
    case invalidBase58
}

/// Ed25519 keypair shape used by `PrekeyBundle.walletSigned(address:keypair:)`.
public struct KeyPair {
    /// 64-byte Ed25519 secret key (seed ‖ public key), same shape as TweetNacl's.
    public let secretKey: Data
    public init(secretKey: Data) { self.secretKey = secretKey }
}

public enum SolanaAddress {
    /// base58 of a 32-byte key, the form the app stores in `ContactCard.address`.
    public static func string(from bytes: Data) -> String { Base58.encode(bytes) }
}

enum Base58 {
    static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

    static func encode(_ data: Data) -> String {
        var digits: [UInt8] = [0]
        for byte in data {
            var carry = Int(byte)
            for i in 0..<digits.count {
                carry += Int(digits[i]) << 8
                digits[i] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }
        var out = ""
        for byte in data.prefix(while: { $0 == 0 }) where byte == 0 {
            out.append("1")
        }
        for d in digits.reversed() where !(out.isEmpty && d == 0) {
            out.append(alphabet[Int(d)])
        }
        return out.isEmpty ? "1" : out
    }

    static func decode(_ string: String) -> Data? {
        var bytes: [UInt8] = []
        for ch in string {
            guard let idx = alphabet.firstIndex(of: ch) else { return nil }
            var carry = Int(idx)
            for i in 0..<bytes.count {
                carry += Int(bytes[i]) * 58
                bytes[i] = UInt8(carry & 0xff)
                carry >>= 8
            }
            while carry > 0 {
                bytes.append(UInt8(carry & 0xff))
                carry >>= 8
            }
        }
        let leadingZeros = string.prefix(while: { $0 == "1" }).count
        var out = Data(repeating: 0, count: leadingZeros)
        out.append(contentsOf: bytes.reversed())
        return out.isEmpty ? Data([0]) : out
    }
}
