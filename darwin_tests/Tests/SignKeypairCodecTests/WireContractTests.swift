import XCTest

@testable import SignKeypairCodec

/// The wire contract, pinned on the Swift side.
///
/// The same vectors are asserted in `tests/wire_contract.rs` and
/// `android/src/test/.../WireContractTest.kt`. The mapping is necessarily
/// duplicated once per language, and duplication is what drifts — these tests
/// turn a drift into a red build on the side that moved, instead of a runtime
/// failure on one platform only.
///
/// `Wire.swift` is pure Foundation, so this runs in the standalone SwiftPM
/// package with no simulator and no Tauri runtime.
final class WireContractTests: XCTestCase {

  // MARK: - commands

  func testCommandNamesMatchTheRustSideVerbatim() {
    let expected: [String: SignerCommand] = [
      "capabilities": .capabilities,
      "generateKey": .generateKey,
      "getKey": .getKey,
      "sign": .sign,
      "deleteKey": .deleteKey,
    ]
    for (wire, command) in expected {
      XCTAssertEqual(command.rawValue, wire)
      XCTAssertEqual(SignerCommand(rawValue: wire), command)
    }
    XCTAssertEqual(
      Set(expected.values), Set(SignerCommand.allCases),
      "a SignerCommand was added without a wire vector — update Wire.swift, Wire.kt, "
        + "src/mobile.rs and every test suite")
  }

  /// The command name is also the `@objc` method name Tauri dispatches to by
  /// selector, so a mismatch here is a runtime "no command found", not a
  /// compile error.
  func testCommandNamesAreCamelCase() {
    for command in SignerCommand.allCases {
      XCTAssertFalse(
        command.rawValue.contains("_"),
        "\(command.rawValue) must be the camelCase selector name, not the snake_case "
          + "IPC command name Rust exposes to the frontend")
    }
  }

  // MARK: - backing

  func testBackingWireNamesMatchTheRustSideVerbatim() {
    XCTAssertEqual(KeyBacking.secureEnclave.rawValue, "secure_enclave")
    XCTAssertEqual(KeyBacking.keychain.rawValue, "keychain")
  }

  func testEveryBackingRoundTrips() {
    for backing in KeyBacking.allCases {
      XCTAssertEqual(KeyBacking(rawValue: backing.rawValue), backing)
    }
  }

  /// The classification callers act on. Getting a member on the wrong side of
  /// this line is a false security claim, not a cosmetic bug. `keychain` is
  /// deliberately false: OS-protected, but not held by a secure element.
  func testHardwareBackingClassification() {
    XCTAssertTrue(KeyBacking.secureEnclave.isHardwareBacked)
    XCTAssertFalse(KeyBacking.keychain.isHardwareBacked)
  }

  // MARK: - protection

  func testProtectionWireNamesMatchTheRustSideVerbatim() {
    XCTAssertEqual(KeyProtection.ambient.rawValue, "ambient")
    XCTAssertEqual(KeyProtection.userPresent.rawValue, "user_present")
  }

  func testEveryProtectionRoundTrips() {
    for protection in KeyProtection.allCases {
      XCTAssertEqual(KeyProtection(rawValue: protection.rawValue), protection)
    }
  }

  /// No default, unlike the backing tag. Guessing `ambient` would hand a caller
  /// who asked for prompted protection a key that signs silently; guessing
  /// `userPresent` would make a background signer prompt on every poll.
  func testUnknownProtectionHasNoDefault() {
    XCTAssertNil(KeyProtection(rawValue: "elevated"))
    XCTAssertNil(KeyProtection(rawValue: ""))
    XCTAssertNil(KeyProtection(rawValue: "AMBIENT"))
  }

  func testProtectionPresenceClassification() {
    XCTAssertFalse(KeyProtection.ambient.requiresUserPresence)
    XCTAssertTrue(KeyProtection.userPresent.requiresUserPresence)
  }

  // MARK: - error codes

  func testErrorCodeWireNamesMatchTheRustSideVerbatim() {
    let expected: [String: SignerErrorCode] = [
      "key_not_found": .keyNotFound,
      "key_already_exists": .keyAlreadyExists,
      "hardware_unavailable": .hardwareUnavailable,
      "keystore_failure": .keystoreFailure,
      "user_authentication_required": .userAuthenticationRequired,
      "user_authentication_cancelled": .userAuthenticationCancelled,
      "key_invalidated": .keyInvalidated,
    ]
    for (wire, code) in expected {
      XCTAssertEqual(code.rawValue, wire)
      XCTAssertEqual(SignerErrorCode(rawValue: wire), code)
    }
    XCTAssertEqual(
      Set(expected.values), Set(SignerErrorCode.allCases),
      "a SignerErrorCode was added without a wire vector")
  }

  /// British spelling on `cancelled`, American on nothing else. It is an odd
  /// mix, and it is pinned precisely because it is odd: an editor's "fix" to
  /// `canceled` compiles on every side and breaks the mapping on all of them.
  func testCancelledKeepsItsDoubleL() {
    XCTAssertEqual(SignerErrorCode.userAuthenticationCancelled.rawValue.contains("cancelled"), true)
  }
}
