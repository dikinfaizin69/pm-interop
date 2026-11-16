# r415-privamesh interop harness

Runs PrivaMesh's own source on Apple Foundation + CryptoKit to check whether an
invite link can bind a victim's wallet address to an attacker's X3DH keys.

Files in `Sources/PMInterop/` are copied **byte-identical** from
`github.com/Makomest/PrivaMesh` @ `afb5ef9`:

| file | origin |
|---|---|
| `ContactCard.swift` | `privamesh/Core/ContactCard.swift` |
| `PrekeyBundle.swift` | `privamesh/Core/PrekeyBundle.swift` |
| `InviteLink.swift` | `privamesh/Core/InviteLink.swift` |
| `CryptoBox.swift` | `privamesh/Core/CryptoBox.swift` |
| `ProfileSnapshot.swift` | lines 14-41 of `privamesh/Core/UserProfileService.swift` |

Not from the app: `SolanaSwift` (base58 + KeyPair stub), `PQXDHStub.swift`,
`main.swift`. Real TweetNacl is pulled from SPM, so Ed25519 sign/verify is the
same library the app uses.
