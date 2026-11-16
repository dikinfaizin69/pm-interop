// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "PMInterop",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/bitmark-inc/tweetnacl-swiftwrap.git", branch: "master")
    ],
    targets: [
        // Minimal stand-in for the SolanaSwift symbols the copied app files touch
        // (PublicKey, KeyPair). Only base58 + a 64-byte Ed25519 secret key.
        .target(name: "SolanaSwift"),

        .executableTarget(
            name: "PMInterop",
            dependencies: [
                "SolanaSwift",
                .product(name: "TweetNacl", package: "tweetnacl-swiftwrap"),
            ],
            swiftSettings: [.unsafeFlags(["-warnings-as-errors", "NO"])]
        ),
    ]
)
