import Foundation

/// The wire vocabulary shared with the Rust side, as enums.
///
/// The Tauri IPC can only carry JSON, so strings do cross the wire. What this
/// file buys is that each string is written in exactly **one** place and parsed
/// in exactly one place; every comparison in the rest of the module is on an
/// enum. Swift `switch` over an enum is exhaustive by default, so adding a
/// member here is a compile error at each switch rather than a silent
/// fallthrough.
///
/// `CaseIterable` is for the wire-contract tests: it lets them assert that
/// EVERY member round-trips, so a member added without a vector fails the suite
/// instead of shipping unmapped.
///
/// These must stay in step with `src/models.rs`, `src/error.rs`,
/// `android/.../Wire.kt` and `guest-js/index.ts`. `WireContractTests` pins the
/// exact strings so a rename on one side cannot drift past review.

/// A command the plugin answers. Each maps to a `@objc` method of the same name.
enum SignerCommand: String, CaseIterable {
  case capabilities
  case generateKey
  case getKey
  case sign
  case deleteKey
}

/// Where a private key lives, strongest first.
///
/// `software` is the floor and the safe default: under-reporting strength is
/// harmless, over-reporting is a false security claim. It has no case here
/// because iOS never produces one — the Security framework always gives at
/// least a keychain item — but the Rust side maps anything it does not
/// recognise down to it.
enum KeyBacking: String, CaseIterable {
  case secureEnclave = "secure_enclave"
  case keychain

  /// True when the key cannot be read out of the device.
  ///
  /// `keychain` is deliberately false: a keychain item is OS-protected but is
  /// not held by a secure element, and the scalar can in principle be exported.
  var isHardwareBacked: Bool {
    switch self {
    case .secureEnclave: return true
    case .keychain: return false
    }
  }
}

/// What the Secure Enclave demands before it signs.
///
/// Unlike `KeyBacking` this has **no safe default**: answering `ambient` for an
/// unrecognised tag would hand a caller who asked for prompted protection a key
/// that signs silently, and answering `userPresent` would make a background
/// request signer prompt on every poll. The parse therefore returns nil and the
/// call fails.
enum KeyProtection: String, CaseIterable {
  case ambient
  case userPresent = "user_present"

  /// Whether the Security framework will demand authentication before signing.
  var requiresUserPresence: Bool {
    switch self {
    case .ambient: return false
    case .userPresent: return true
    }
  }
}

/// Why an operation failed. Becomes the `code` on the rejected invoke, which
/// `src/mobile.rs` maps straight back onto its own enum.
enum SignerErrorCode: String, CaseIterable {
  case keyNotFound = "key_not_found"
  case keyAlreadyExists = "key_already_exists"
  case hardwareUnavailable = "hardware_unavailable"
  case keystoreFailure = "keystore_failure"
  case userAuthenticationRequired = "user_authentication_required"
  case userAuthenticationCancelled = "user_authentication_cancelled"
  case keyInvalidated = "key_invalidated"
}

/// A typed failure carrying a `SignerErrorCode` rather than a bare string.
struct SignerError: Error {
  let code: SignerErrorCode
  let message: String

  init(_ code: SignerErrorCode, _ message: String) {
    self.code = code
    self.message = message
  }
}
