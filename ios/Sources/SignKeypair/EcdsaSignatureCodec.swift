import Foundation

/// ASN.1 DER <-> IEEE P1363 conversion for P-256 ECDSA signatures.
///
/// Deliberately free of any Tauri or Security-framework import: this type is
/// pure `Foundation`, so it can be unit-tested by a plain SwiftPM package with
/// no simulator, no Tauri runtime and no keychain. See `darwin_tests/`.
///
/// `SecKeyCreateSignature` emits **ASN.1 DER** `SEQUENCE { INTEGER r, INTEGER s }`.
/// JWS ES256 (RFC 7515 §3.4 / RFC 7518 §3.4) requires **IEEE P1363** — the two
/// integers as fixed-width 32-byte big-endian values, concatenated, unwrapped.
///
/// Getting this wrong is silent and intermittent. DER encodes integers minimally,
/// so a component whose top byte happens to be zero is one byte shorter — which
/// happens for roughly 1 signature in 256 per component. Code that copies the
/// magnitude without left-padding produces a signature that is valid ECDSA and
/// that a JWS verifier rejects, days or weeks after it shipped.
public enum EcdsaSignatureCodec {

  /// Byte width of one P-256 coordinate.
  public static let coordinateLength = 32

  /// Total length of a P-256 P1363 signature.
  public static let p1363Length = coordinateLength * 2

  /// Why a DER signature could not be decoded. Never carries key material.
  public enum DecodingError: Error, Equatable {
    /// The input ended before the structure did.
    case truncated(String)
    /// A tag byte was not the one DER requires here.
    case unexpectedTag(expected: UInt8, actual: UInt8)
    /// A declared length does not agree with the buffer.
    case lengthMismatch(String)
    /// An integer was wider than a P-256 coordinate.
    case integerTooLong(Int)
    /// A length encoding this codec deliberately does not accept.
    case unsupportedLengthForm(String)
  }

  /// Convert an ASN.1 DER ECDSA signature to IEEE P1363 `r‖s`.
  ///
  /// The result is **always** exactly ``p1363Length`` bytes, or the call throws.
  public static func derToP1363(_ der: Data) throws -> Data {
    // Index through a contiguous copy: `Data` slices keep their parent's
    // indices, and an off-by-one there is exactly the kind of out-of-bounds
    // read this codec must not have.
    let bytes = [UInt8](der)
    var offset = 0

    func readByte(_ what: String) throws -> Int {
      guard offset < bytes.count else {
        throw DecodingError.truncated("expected \(what) at offset \(offset)")
      }
      defer { offset += 1 }
      return Int(bytes[offset])
    }

    let tag = try UInt8(readByte("SEQUENCE tag"))
    guard tag == 0x30 else {
      throw DecodingError.unexpectedTag(expected: 0x30, actual: tag)
    }

    var sequenceLength = try readByte("SEQUENCE length")
    if sequenceLength & 0x80 != 0 {
      let lengthOctets = sequenceLength & 0x7f
      guard lengthOctets >= 1, lengthOctets <= 2 else {
        throw DecodingError.unsupportedLengthForm(
          "SEQUENCE length uses \(lengthOctets) octets")
      }
      sequenceLength = 0
      for _ in 0..<lengthOctets {
        sequenceLength = (sequenceLength << 8) | (try readByte("SEQUENCE length octet"))
      }
    }
    guard offset + sequenceLength == bytes.count else {
      throw DecodingError.lengthMismatch(
        "SEQUENCE declares \(sequenceLength) bytes, buffer has \(bytes.count - offset)")
    }

    func readInteger(_ what: String) throws -> ArraySlice<UInt8> {
      let tag = try UInt8(readByte("\(what) INTEGER tag"))
      guard tag == 0x02 else {
        throw DecodingError.unexpectedTag(expected: 0x02, actual: tag)
      }
      let length = try readByte("\(what) INTEGER length")
      guard length & 0x80 == 0 else {
        throw DecodingError.unsupportedLengthForm("\(what) INTEGER uses long-form length")
      }
      guard length > 0 else {
        throw DecodingError.lengthMismatch("\(what) INTEGER has zero length")
      }
      guard offset + length <= bytes.count else {
        throw DecodingError.truncated(
          "\(what) INTEGER declares \(length) bytes, only \(bytes.count - offset) remain")
      }
      defer { offset += length }
      return bytes[offset..<(offset + length)]
    }

    /// Strip DER's minimal-encoding leading zeros, then left-pad to 32 bytes.
    ///
    /// Both halves matter: a high-bit component carries a 0x00 sign byte that
    /// must NOT survive into P1363, and a short component must be padded on the
    /// LEFT — right-alignment silently multiplies the value by 256^n.
    func normalise(_ value: ArraySlice<UInt8>, _ what: String) throws -> [UInt8] {
      var start = value.startIndex
      while start < value.endIndex - 1 && value[start] == 0 {
        start += 1
      }
      let magnitude = value[start...]
      guard magnitude.count <= coordinateLength else {
        throw DecodingError.integerTooLong(magnitude.count)
      }
      var out = [UInt8](repeating: 0, count: coordinateLength)
      out.replaceSubrange((coordinateLength - magnitude.count)..<coordinateLength, with: magnitude)
      return out
    }

    let r = try normalise(try readInteger("r"), "r")
    let s = try normalise(try readInteger("s"), "s")

    // r and s must account for the entire SEQUENCE. Without this, trailing
    // bytes are silently ignored, which makes the encoding malleable: an
    // attacker can append junk and get a different byte string that this codec
    // maps to the same signature.
    guard offset == bytes.count else {
      throw DecodingError.lengthMismatch(
        "\(bytes.count - offset) trailing byte(s) after s")
    }

    let result = Data(r + s)
    // Unreachable by construction — `normalise` always returns exactly
    // `coordinateLength` bytes — and mutation testing confirms it: deleting
    // this guard fails no test. It stays as an invariant against a future edit
    // to `normalise`, because the caller ships this straight into a JWS where a
    // wrong length is a 401 with no useful diagnostics. Recorded here so the
    // next person does not mistake "untested" for "untestable".
    guard result.count == p1363Length else {
      throw DecodingError.lengthMismatch("produced \(result.count) bytes, expected \(p1363Length)")
    }
    return result
  }

  /// Convert an IEEE P1363 `r‖s` signature to ASN.1 DER.
  ///
  /// Not used on the signing path — the platform already gives us DER — but it
  /// is what lets a test round-trip against a DER-only verifier.
  public static func p1363ToDer(_ p1363: Data) throws -> Data {
    guard p1363.count == p1363Length else {
      throw DecodingError.lengthMismatch(
        "expected \(p1363Length) bytes, got \(p1363.count)")
    }
    let bytes = [UInt8](p1363)
    let body =
      derInteger(Array(bytes[0..<coordinateLength]))
      + derInteger(Array(bytes[coordinateLength..<p1363Length]))
    return Data([0x30, UInt8(body.count)] + body)
  }

  private static func derInteger(_ value: [UInt8]) -> [UInt8] {
    var start = 0
    while start < value.count - 1 && value[start] == 0 {
      start += 1
    }
    var magnitude = Array(value[start...])
    // DER INTEGERs are signed: prepend 0x00 so a high top bit is not negative.
    if magnitude[0] & 0x80 != 0 {
      magnitude.insert(0, at: 0)
    }
    return [0x02, UInt8(magnitude.count)] + magnitude
  }
}
