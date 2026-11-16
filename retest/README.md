# PrivaMesh retest

Two independent runs against `github.com/Makomest/PrivaMesh` at revision `afb5ef9`.

| Job | What it proves | How |
|---|---|---|
| `harness` | The invite card is accepted, and messages sent over the stored bundle are readable by the attacker — through the app's **real** `DoubleRatchet`, `MessagePadding` and `MessageEnvelope` | Byte-identical copies of 7 app source files compiled on Apple Foundation + CryptoKit |
| `ios-e2e` | The **unmodified app** on an iOS Simulator accepts the invite and persists a contact whose `id` is the impersonated wallet | The app's own DEBUG hooks `-demoImport` and `-inviteURL`, plus one UI test dropped into the existing UI test target |

Nothing in the vendor repository is edited. The vendor tree is cloned at run time and the only added file is a test case inside `privameshUITests/`.

## Identities

Three disjoint wallets, so there is no ambiguity about who is who:

| Role | Who | Note |
|---|---|---|
| user | opens the link, sends the traffic | demo wallet restored by `-demoImport` |
| impersonated | the contact the invite claims to be | `GqTokf3PYKjTzkTJrahA8AY47eBVe9fyrun9CfLg6JEp`, key never used |
| attacker | owns the messaging keys inside the invite | card carries no `walletAddress` |

## Ownership guard

`harness/scripts/slice_guard.py` cuts lines 601–605 out of
`privamesh/Views/Chat/AddContactView.swift` and compiles them verbatim, so the
assertion executes the vendor's own condition:

```
sha256(block) = 4c509af9d9a4efbc3632c432ec4eba214f7139a72ee04fd8271986651daf1227
```

## Artifacts

`harness-output`: `harness-run.log`, `guard-slice.log`, `GuardSlice.swift.txt`, `SHA256-MANIFEST.txt`
`ios-e2e-output`: `xcodebuild.log`, `store-dump.log`, `e2e.xcresult` (screenshots attached by the test)

## Reading the result

Harness: every line is `[PASS]`/`[FAIL]`; the last line is `failures: 0`.
E2E: `TEST SUCCEEDED`, then `store-dump.log` shows the `ZCONTACT` row whose id is the impersonated address.
