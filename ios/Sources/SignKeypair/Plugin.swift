import Foundation
import LocalAuthentication
import Security
import SwiftRs
import Tauri
import UIKit
import WebKit

/// Secure Enclave / keychain-backed ES256 signer for iOS.
///
/// The Secure Enclave supports exactly one curve — NIST P-256 — which is also
/// the curve JWS ES256 requires, so the enclave path needs no protocol change
/// on top of it. When the enclave is unavailable (a simulator), the key is
/// created as an ordinary keychain item and reported as `keychain`, which this
/// plugin does **not** count as hardware-backed.
///
/// Errors are caught and re-rejected with their code here rather than thrown.
/// Tauri's `throws` bridge rejects with `"\(error)"` and no `code`, and a
/// frontend that cannot tell `user_authentication_cancelled` from
/// `key_invalidated` will handle both wrongly — the first needs nothing done,
/// the second needs a fresh key registered with the backend.
class SignKeypairPlugin: Plugin {

  private static let tagPrefix = "app.vaam.signkeypair."
  private static let coordinateLength = 32

  // MARK: - arguments

  struct KeyIdArgs: Decodable {
    let keyId: String
  }

  struct GenerateKeyArgs: Decodable {
    let keyId: String
    let requireHardware: Bool?
    let overwrite: Bool?
    let protection: String?
  }

  struct SignArgs: Decodable {
    let keyId: String
    /// base64url of the raw signing input.
    let payload: String
    let reason: String?
  }

  // MARK: - responses

  struct CapabilitiesResponse: Encodable {
    let platform: String
    let bestAvailableBacking: String
    let hardwareBacked: Bool
  }

  struct JwkResponse: Encodable {
    let crv: String
    let kty: String
    let x: String
    let y: String
  }

  struct SecureKeyResponse: Encodable {
    let keyId: String
    let publicKey: JwkResponse
    let backing: String
    let hardwareBacked: Bool
  }

  struct GetKeyResponse: Encodable {
    let key: SecureKeyResponse?
  }

  struct SignResponse: Encodable {
    /// base64url of the 64-byte IEEE P1363 signature.
    let signature: String
  }

  struct EmptyResponse: Encodable {}

  // MARK: - commands

  @objc public func capabilities(_ invoke: Invoke) {
    let backing: KeyBacking = isSecureEnclaveAvailable() ? .secureEnclave : .keychain
    invoke.resolve(
      CapabilitiesResponse(
        platform: "ios",
        bestAvailableBacking: backing.rawValue,
        hardwareBacked: backing.isHardwareBacked))
  }

  @objc public func generateKey(_ invoke: Invoke) {
    respond(invoke) {
      let args = try invoke.parseArgs(GenerateKeyArgs.self)
      return try self.generate(
        keyId: args.keyId,
        requireHardware: args.requireHardware ?? false,
        overwrite: args.overwrite ?? false,
        protection: try self.requireProtection(args.protection))
    }
  }

  @objc public func getKey(_ invoke: Invoke) {
    respond(invoke) {
      let args = try invoke.parseArgs(KeyIdArgs.self)
      return GetKeyResponse(key: try self.describeKey(keyId: args.keyId))
    }
  }

  @objc public func sign(_ invoke: Invoke) {
    respond(invoke) {
      let args = try invoke.parseArgs(SignArgs.self)
      guard let payload = Self.base64UrlDecode(args.payload) else {
        throw SignerError(.keystoreFailure, "Argument \"payload\" is not valid base64url")
      }
      let signature = try self.sign(
        keyId: args.keyId, payload: payload, reason: args.reason)
      return SignResponse(signature: Self.base64Url(signature))
    }
  }

  @objc public func deleteKey(_ invoke: Invoke) {
    respond(invoke) {
      let args = try invoke.parseArgs(KeyIdArgs.self)
      try self.delete(keyId: args.keyId)
      return EmptyResponse()
    }
  }

  /// Run `body`, resolving with what it returns and rejecting *with the code*
  /// when it throws. The one place an error crosses back to Rust.
  private func respond<T: Encodable>(_ invoke: Invoke, _ body: () throws -> T) {
    do {
      invoke.resolve(try body())
    } catch let error as SignerError {
      invoke.reject(error.message, code: error.code.rawValue)
    } catch let error as EcdsaSignatureCodec.DecodingError {
      // A malformed DER signature is the Security framework contradicting its
      // own documented output, not a user-recoverable condition — but it must
      // still arrive as a typed keystore failure rather than a bare string.
      invoke.reject(
        "The platform produced a signature this codec could not decode: \(error)",
        code: SignerErrorCode.keystoreFailure.rawValue)
    } catch {
      invoke.reject(
        error.localizedDescription, code: SignerErrorCode.keystoreFailure.rawValue)
    }
  }

  // MARK: - operations

  private func generate(
    keyId: String, requireHardware: Bool, overwrite: Bool, protection: KeyProtection
  ) throws -> SecureKeyResponse {
    // Capability checks FIRST, before anything destructive.
    //
    // `overwrite = true` deletes the incumbent key below, so a rejection after
    // that point would leave the device with no credential at all — unable to
    // authenticate and unable to sign its way through re-enrolment. That is far
    // worse than the failure the caller asked for.
    let useEnclave = isSecureEnclaveAvailable()
    if requireHardware && !useEnclave {
      throw SignerError(
        .hardwareUnavailable,
        "The Secure Enclave is unavailable on this device and requireHardware was set")
    }

    // A user-present key on a device with no passcode and no biometric cannot
    // be created — `SecAccessControlCreateWithFlags` fails, and it fails *after*
    // the delete below unless we check here. Checking up front also lets the
    // caller distinguish "set a screen lock" (recoverable in Settings) from
    // "this device has no secure element" (not recoverable at all), which a
    // single hardware_unavailable code could not express.
    if protection.requiresUserPresence && !isUserAuthenticationAvailable() {
      throw SignerError(
        .userAuthenticationRequired,
        "A user-present key needs a device passcode or an enrolled biometric, "
          + "and this device has neither")
    }

    if try loadPrivateKey(keyId: keyId) != nil {
      guard overwrite else {
        throw SignerError(.keyAlreadyExists, "A key already exists under \"\(keyId)\"")
      }
      try delete(keyId: keyId)
    }

    var error: Unmanaged<CFError>?
    guard
      let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        accessibility(for: protection),
        accessControlFlags(for: protection, useEnclave: useEnclave),
        &error)
    else {
      throw SignerError(
        .keystoreFailure, "SecAccessControlCreateWithFlags failed: \(describe(error))")
    }

    let privateAttributes: [String: Any] = [
      kSecAttrIsPermanent as String: true,
      kSecAttrApplicationTag as String: tagData(keyId),
      kSecAttrAccessControl as String: access,
    ]

    var attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecPrivateKeyAttrs as String: privateAttributes,
    ]
    if useEnclave {
      attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    }

    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      throw SignerError(.keystoreFailure, "SecKeyCreateRandomKey failed: \(describe(error))")
    }

    return try describe(keyId: keyId, privateKey: privateKey, isEnclave: isEnclaveKey(privateKey))
  }

  private func describeKey(keyId: String) throws -> SecureKeyResponse? {
    guard let privateKey = try loadPrivateKey(keyId: keyId) else { return nil }
    return try describe(keyId: keyId, privateKey: privateKey, isEnclave: isEnclaveKey(privateKey))
  }

  private func sign(keyId: String, payload: Data, reason: String?) throws -> Data {
    // The prompt, when there is one, is raised by the Security framework during
    // `SecKeyCreateSignature` — not here. All this does is caption it: without
    // an LAContext carrying `localizedReason`, iOS falls back to its own generic
    // system string.
    //
    // Attaching a context to an ambient key is harmless (nothing consults it),
    // so this needs no branch on protection — which is just as well, because the
    // access control an existing key was created with cannot be read back.
    let context = LAContext()
    if let reason = reason, !reason.isEmpty {
      context.localizedReason = reason
    }

    guard let privateKey = try loadPrivateKey(keyId: keyId, context: context) else {
      throw SignerError(.keyNotFound, "No key stored under \"\(keyId)\"")
    }
    var error: Unmanaged<CFError>?
    // `...MessageX962SHA256` digests the message for us, matching
    // java.security's "SHA256withECDSA" and p256's `Signer` impl.
    guard
      let signature = SecKeyCreateSignature(
        privateKey, .ecdsaSignatureMessageX962SHA256, payload as CFData, &error) as Data?
    else {
      throw signingError(from: error)
    }
    // The Security framework emits ASN.1 DER; JWS ES256 needs IEEE P1363 r‖s.
    return try EcdsaSignatureCodec.derToP1363(signature)
  }

  private func delete(keyId: String) throws {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tagData(keyId),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    ]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw SignerError(.keystoreFailure, "SecItemDelete failed with status \(status)")
    }
  }

  // MARK: - access control policy (the two-key model)

  /// When the keychain will let the item be read at all.
  ///
  /// **Ambient — `afterFirstUnlockThisDeviceOnly`.** A caller that signs
  /// background requests on a timer needs this key readable while the screen is
  /// locked, since polling keeps running after the user last unlocked the
  /// device. `whenUnlocked` would fail all of that traffic.
  ///
  /// **User-present — `whenUnlockedThisDeviceOnly`.** This key only ever signs a
  /// deliberate action, so by construction the screen is unlocked and a human is
  /// looking at it. Narrowing the window costs nothing here and removes the
  /// class of attack where a locked-but-booted phone is compelled to sign.
  ///
  /// `ThisDeviceOnly` on both: it keeps the key out of iCloud Keychain and out
  /// of encrypted backups, so a device-bound credential stays bound to *this*
  /// device rather than restoring onto a new one.
  private func accessibility(for protection: KeyProtection) -> CFString {
    switch protection {
    case .ambient: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    case .userPresent: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }
  }

  /// What the Secure Enclave demands before it performs the signature.
  ///
  /// `.privateKeyUsage` is what makes an enclave key usable for signing at all,
  /// and on its own it prompts for nothing — that is the ambient key.
  ///
  /// The user-present key adds `[.biometryCurrentSet, .or, .devicePasscode]`:
  /// "a biometric from the enrolment set that existed when this key was made, OR
  /// the device passcode". Both halves are deliberate — `.biometryCurrentSet`
  /// rather than `.biometryAny` so a newly enrolled fingerprint does not inherit
  /// this key's authority, and `.or .devicePasscode` because a meaningful share
  /// of real hardware has no working biometric sensor and requiring one would
  /// lock those users out entirely.
  ///
  /// Worth being precise about what the combination does, because it is narrower
  /// than it first reads: re-enrolling a biometric invalidates only the biometry
  /// branch, and the passcode branch survives. That does not open a hole — iOS
  /// requires the passcode before it will accept a new biometric enrolment, so
  /// an attacker who can enrol one already holds what the surviving branch asks
  /// for.
  private func accessControlFlags(for protection: KeyProtection, useEnclave: Bool)
    -> SecAccessControlCreateFlags
  {
    var flags: SecAccessControlCreateFlags = useEnclave ? [.privateKeyUsage] : []
    if protection.requiresUserPresence {
      flags.formUnion([.biometryCurrentSet, .or, .devicePasscode])
    }
    return flags
  }

  /// Whether this device can authenticate a human at all.
  ///
  /// `.deviceOwnerAuthentication` (not `...WithBiometrics`) is the policy that
  /// matches the access control above: it answers yes when there is a passcode,
  /// a biometric, or both — the same disjunction the key will be created with.
  private func isUserAuthenticationAvailable() -> Bool {
    LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
  }

  /// Map a signing failure onto a code the Rust and JS sides can act on.
  ///
  /// The distinction that matters is cancelled-by-the-user versus anything else:
  /// a dismissed prompt is someone changing their mind at a confirmation screen,
  /// and treating it as an auth failure would trigger re-enrolment or logout for
  /// a routine interaction.
  private func signingError(from error: Unmanaged<CFError>?) -> SignerError {
    let message = describe(error)
    guard let cfError = error?.takeUnretainedValue() else {
      return SignerError(.keystoreFailure, "SecKeyCreateSignature failed: \(message)")
    }
    let nsError = cfError as Error as NSError

    if nsError.domain == LAErrorDomain {
      switch LAError.Code(rawValue: nsError.code) {
      case .userCancel, .appCancel, .systemCancel, .userFallback:
        return SignerError(.userAuthenticationCancelled, message)
      case .passcodeNotSet, .biometryNotEnrolled, .biometryNotAvailable, .biometryLockout:
        return SignerError(.userAuthenticationRequired, message)
      default:
        return SignerError(.keystoreFailure, message)
      }
    }

    // OSStatus codes come back on NSOSStatusErrorDomain. `errSecUserCanceled` is
    // what the keychain reports when the prompt is dismissed before
    // LocalAuthentication gets involved.
    switch nsError.code {
    case Int(errSecUserCanceled):
      return SignerError(.userAuthenticationCancelled, message)
    case Int(errSecInteractionNotAllowed):
      // The item exists but is unreadable right now — a user-present key reached
      // from a background context, which is a caller bug rather than a device
      // problem.
      return SignerError(
        .userAuthenticationRequired,
        "This key requires user presence and cannot be used from the background: \(message)")
    case Int(errSecAuthFailed):
      // The enclave refuses a key whose biometry set has changed since creation
      // — `.biometryCurrentSet` firing as designed. Recovery is narrow: generate
      // a fresh user-present key and register its thumbprint. The ambient key is
      // untouched, so the device can still authenticate itself while doing so.
      return SignerError(
        .keyInvalidated,
        "The key was invalidated by a change to this device's biometric "
          + "enrolment or passcode: \(message)")
    default:
      return SignerError(.keystoreFailure, "SecKeyCreateSignature failed: \(message)")
    }
  }

  // MARK: - helpers

  private func describe(keyId: String, privateKey: SecKey, isEnclave: Bool) throws
    -> SecureKeyResponse
  {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw SignerError(.keystoreFailure, "Could not derive the public key")
    }
    var error: Unmanaged<CFError>?
    guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      throw SignerError(
        .keystoreFailure, "SecKeyCopyExternalRepresentation failed: \(describe(error))")
    }
    // X9.63 uncompressed point: 0x04 || X (32) || Y (32).
    guard raw.count == 1 + Self.coordinateLength * 2, raw.first == 0x04 else {
      throw SignerError(.keystoreFailure, "Unexpected public key encoding (\(raw.count) bytes)")
    }
    let x = raw.subdata(in: 1..<(1 + Self.coordinateLength))
    let y = raw.subdata(in: (1 + Self.coordinateLength)..<raw.count)
    let backing: KeyBacking = isEnclave ? .secureEnclave : .keychain

    return SecureKeyResponse(
      keyId: keyId,
      publicKey: JwkResponse(
        crv: "P-256", kty: "EC", x: Self.base64Url(x), y: Self.base64Url(y)),
      backing: backing.rawValue,
      hardwareBacked: backing.isHardwareBacked)
  }

  private func loadPrivateKey(keyId: String, context: LAContext? = nil) throws -> SecKey? {
    var query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tagData(keyId),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
    ]
    if let context = context {
      query[kSecUseAuthenticationContext as String] = context
    }

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    switch status {
    case errSecSuccess:
      guard let result = item else { return nil }
      return (result as! SecKey)
    case errSecItemNotFound:
      return nil
    default:
      throw SignerError(.keystoreFailure, "SecItemCopyMatching failed with status \(status)")
    }
  }

  /// Whether a live key is held by the Secure Enclave.
  ///
  /// Read back from the key's own attributes rather than inferred from how it
  /// was requested, so a silent fallback inside the Security framework cannot be
  /// reported as enclave-backed.
  private func isEnclaveKey(_ key: SecKey) -> Bool {
    guard let attributes = SecKeyCopyAttributes(key) as? [String: Any] else { return false }
    guard let tokenID = attributes[kSecAttrTokenID as String] as? String else { return false }
    return tokenID == (kSecAttrTokenIDSecureEnclave as String)
  }

  /// Probe the enclave by creating and immediately discarding a non-permanent key.
  ///
  /// `LAContext.canEvaluatePolicy` is not a valid proxy: it reports biometric
  /// enrolment, not enclave presence, and the two diverge on a simulator and on
  /// a device with no passcode set.
  private func isSecureEnclaveAvailable() -> Bool {
    var error: Unmanaged<CFError>?
    guard
      let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        [.privateKeyUsage],
        &error)
    else { return false }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: false,
        kSecAttrAccessControl as String: access,
      ],
    ]
    guard let probe = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      return false
    }
    return isEnclaveKey(probe)
  }

  private func tagData(_ keyId: String) -> Data {
    Data((Self.tagPrefix + keyId).utf8)
  }

  /// The one wire → enum boundary for the protection tag.
  ///
  /// Absent means ambient, which is the documented default. Unrecognised is a
  /// hard failure with no default: guessing `ambient` would hand a caller who
  /// asked for prompted protection a key that signs silently, and guessing
  /// `userPresent` would make a background signer prompt on every poll. The
  /// policy is baked into the key permanently at creation, so a mismatched
  /// pairing fails at the call instead.
  private func requireProtection(_ raw: String?) throws -> KeyProtection {
    guard let raw = raw else { return .ambient }
    guard let protection = KeyProtection(rawValue: raw) else {
      throw SignerError(.keystoreFailure, "Unknown key protection \"\(raw)\"")
    }
    return protection
  }

  private func describe(_ error: Unmanaged<CFError>?) -> String {
    guard let error = error?.takeRetainedValue() else { return "unknown error" }
    return CFErrorCopyDescription(error) as String? ?? "unknown error"
  }

  static func base64Url(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  static func base64UrlDecode(_ value: String) -> Data? {
    var s = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    // Restore the padding `base64EncodedString` requires and base64url drops.
    while s.count % 4 != 0 { s.append("=") }
    return Data(base64Encoded: s)
  }
}

@_cdecl("init_plugin_sign_keypair")
func initPlugin() -> Plugin {
  return SignKeypairPlugin()
}
