//
//  AttackE2ETests.swift
//
//  Runs against the unmodified PrivaMesh app on an iOS Simulator, using the
//  app's own DEBUG verification hooks — the same ones its shipped UI tests use:
//
//      -demoImport                restores the App Review demo wallet, lands on main
//      -inviteURL <url>           feeds the same InviteInbox the OS deep link feeds
//      -privamesh.onboardingDone  skips onboarding
//      -AppleLanguages (en)       forces English so labels are stable
//
//  Nothing in the app is patched. Each test delivers an invite the way a victim
//  receives it, taps the single button the screen asks for, and then asserts on
//  what the app actually did.
//
//  Placeholders substituted by CI from e2e/scripts/gen_attack_link.py:
//      link A  unsigned card, address of the impersonated wallet
//      link B  wallet-signed card, address the signer really owns
//      link C  claims the impersonated address, signed by another wallet
//      plus the impersonated address itself
//

import XCTest

final class AttackE2ETests: XCTestCase {

    let impersonatedAddress = "__IMPERSONATED_ADDRESS__"

    let attackLink = "__LINK_ATTACK__"
    let legitLink  = "__LINK_LEGIT__"
    let forgedLink = "__LINK_FORGED__"

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    private func launch(with link: String) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments += [
            "-demoImport",
            "-inviteURL", link,
            "-privamesh.onboardingDone", "YES",
            "-AppleLanguages", "(en)", "-AppleLocale", "en_US",
        ]
        app.launch()
        return app
    }

    private func attach(_ app: XCUIApplication, _ name: String) {
        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = name
        shot.lifetime = .keepAlways
        add(shot)
    }

    /// The name field on the QR tab. Matched loosely because the shipped UI is
    /// authored in another language and rendered through the string catalogue,
    /// so the placeholder carries a trailing ellipsis we should not depend on.
    private func nameField(_ app: XCUIApplication) -> XCUIElement {
        app.textFields
            .matching(NSPredicate(format: "placeholderValue CONTAINS[c] 'name'"))
            .firstMatch
    }

    /// The sheet's own confirm button. The previous run reached it by its exact
    /// label, so keep the exact match and avoid tapping an "add" button from the
    /// screen underneath the sheet.
    private func saveButton(_ app: XCUIApplication) -> XCUIElement {
        app.buttons["Add contact"]
    }

    private func sheetIsOpen(_ app: XCUIApplication) -> Bool {
        app.buttons["Cancel"].exists
    }

    /// Step 1 — the invite opens the add-contact sheet on its own, already on the
    /// QR tab, with the sender's chosen nickname in the name field. No hunting.
    @MainActor
    func test1InviteOpensPrefilledAddContactSheet() throws {
        let app = launch(with: attackLink)

        XCTAssertTrue(app.buttons["Cancel"].waitForExistence(timeout: 120),
                      "Invite did not open the add-contact sheet.\n\(app.debugDescription)")
        attach(app, "01-sheet-auto-opened")

        let field = nameField(app)
        XCTAssertTrue(field.waitForExistence(timeout: 60),
                      "Name field missing on the QR tab.\n\(app.debugDescription)")
        let prefilled = (field.value as? String) ?? ""
        attach(app, "02-name-prefilled")
        XCTAssertEqual(prefilled, "Alice",
                       "Nickname from the card was not prefilled; field held '\(prefilled)'")
    }

    /// Step 2 — exactly one tap on the sheet's own save button persists the
    /// contact. This is the whole attack: open a link, tap once.
    @MainActor
    func test2OneTapPersistsContactBoundToImpersonatedAddress() throws {
        let app = launch(with: attackLink)

        XCTAssertTrue(app.buttons["Cancel"].waitForExistence(timeout: 120),
                      "Invite did not open the add-contact sheet.\n\(app.debugDescription)")

        let save = saveButton(app)
        XCTAssertTrue(save.waitForExistence(timeout: 60),
                      "Save button not found on the QR tab.\n\(app.debugDescription)")
        save.tap()

        // The decisive signal: the card was accepted, so the sheet closes on its
        // own instead of raising the "signature does not match" alert.
        let closed = app.buttons["Cancel"].waitForNonExistence(timeout: 90)
        attach(app, "03-after-save")

        XCTAssertFalse(app.alerts.element.exists,
                       "An error alert appeared — the card was rejected.\n\(app.debugDescription)")
        XCTAssertTrue(closed,
                      "The sheet stayed open after one tap — the card was rejected.\n\(app.debugDescription)")

        // Persistence itself is not asserted from the UI: the contact list is a
        // separate screen with its own ordering, and a missing row there says
        // nothing about what was written. The workflow dumps the app's SwiftData
        // store after the run and verify_store.py checks the row's identifier and
        // the stored bundle against this exact attack card.
    }

    /// Control — a wallet-signed card for an address the signer really owns must
    /// still be accepted, so step 2 is not measuring a blanket rejection.
    @MainActor
    func test3ControlWalletSignedInviteIsAccepted() throws {
        let app = launch(with: legitLink)

        XCTAssertTrue(app.buttons["Cancel"].waitForExistence(timeout: 120),
                      "Control invite did not open the sheet.\n\(app.debugDescription)")
        let save = saveButton(app)
        XCTAssertTrue(save.waitForExistence(timeout: 60),
                      "Control invite did not reach the save button.\n\(app.debugDescription)")
        save.tap()

        let closed = app.buttons["Cancel"].waitForNonExistence(timeout: 90)
        attach(app, "04-control-legit-saved")
        XCTAssertFalse(app.alerts.element.exists,
                       "The wallet-signed control card was rejected.\n\(app.debugDescription)")
        XCTAssertTrue(closed,
                      "Control contact was not saved — the sheet stayed open.\n\(app.debugDescription)")
    }

    /// Control — a card that claims the impersonated address but is signed by a
    /// different wallet must be rejected. Proves the guard actually runs; the
    /// bypass in step 2 is the missing field, not a dead check.
    @MainActor
    func test4ControlForgedSignatureIsRejected() throws {
        let app = launch(with: forgedLink)

        XCTAssertTrue(app.buttons["Cancel"].waitForExistence(timeout: 120),
                      "Forged invite did not open the sheet.\n\(app.debugDescription)")

        let save = saveButton(app)
        XCTAssertTrue(save.waitForExistence(timeout: 60),
                      "Forged invite never reached the save button, so the guard was never asked.\n\(app.debugDescription)")
        save.tap()

        // The guard's own rejection signal: an alert, with the sheet still open.
        let alert = app.alerts.element.waitForExistence(timeout: 60)
        attach(app, "05-control-forged-rejected")
        XCTAssertTrue(alert,
                      "Forged signature was not rejected — no alert appeared.\n\(app.debugDescription)")
        XCTAssertTrue(sheetIsOpen(app),
                      "Forged signature was not rejected — the sheet closed, so the contact may have been saved.\n\(app.debugDescription)")
    }
}
