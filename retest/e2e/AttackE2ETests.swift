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
//  what the app actually persisted.
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

    /// Step 1 — the invite opens the add-contact sheet on its own, already on the
    /// QR tab, with the sender's chosen nickname in the name field. No hunting.
    @MainActor
    func test1InviteOpensPrefilledAddContactSheet() throws {
        let app = launch(with: attackLink)

        XCTAssertTrue(app.buttons["Cancel"].waitForExistence(timeout: 120),
                      "Invite did not open the add-contact sheet.\n\(app.debugDescription)")
        attach(app, "01-sheet-auto-opened")

        let nameField = app.textFields["Contact name"]
        XCTAssertTrue(nameField.waitForExistence(timeout: 30),
                      "Name field missing on the QR tab.\n\(app.debugDescription)")
        let prefilled = (nameField.value as? String) ?? ""
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

        let save = app.buttons["Add contact"]
        XCTAssertTrue(save.waitForExistence(timeout: 30),
                      "Save button not found on the QR tab.\n\(app.debugDescription)")
        save.tap()

        let row = app.staticTexts["Alice"]
        let persisted = row.waitForExistence(timeout: 90)
        attach(app, "03-after-save")
        XCTAssertTrue(persisted,
                      "Contact was not added after one tap.\n\(app.debugDescription)")

        XCTAssertFalse(app.alerts.element.exists,
                       "An error alert appeared — the card was rejected.")
        XCTAssertFalse(app.buttons["Cancel"].exists,
                       "The sheet stayed open — the card was rejected.")
    }

    /// Control — a wallet-signed card for an address the signer really owns must
    /// still be accepted, so step 2 is not measuring a blanket rejection.
    @MainActor
    func test3ControlWalletSignedInviteIsAccepted() throws {
        let app = launch(with: legitLink)

        XCTAssertTrue(app.buttons["Cancel"].waitForExistence(timeout: 120),
                      "Control invite did not open the sheet.\n\(app.debugDescription)")
        let save = app.buttons["Add contact"]
        XCTAssertTrue(save.waitForExistence(timeout: 30),
                      "Control invite did not reach the save button.\n\(app.debugDescription)")
        save.tap()

        let row = app.staticTexts["Alice"]
        attach(app, "04-control-legit-saved")
        XCTAssertTrue(row.waitForExistence(timeout: 90),
                      "Control contact was not saved.\n\(app.debugDescription)")
    }

    /// Control — a card that claims the impersonated address but is signed by a
    /// different wallet must be rejected. Proves the guard actually runs; the
    /// bypass in step 2 is the missing field, not a dead check.
    @MainActor
    func test4ControlForgedSignatureIsRejected() throws {
        let app = launch(with: forgedLink)

        XCTAssertTrue(app.buttons["Cancel"].waitForExistence(timeout: 120),
                      "Forged invite did not open the sheet.\n\(app.debugDescription)")

        let save = app.buttons["Add contact"]
        if save.exists { save.tap() }

        let rejected = app.alerts.element.waitForExistence(timeout: 30)
                        || save.exists
        attach(app, "05-control-forged-rejected")
        XCTAssertTrue(rejected,
                      "Forged signature was not rejected.\n\(app.debugDescription)")
    }
}
