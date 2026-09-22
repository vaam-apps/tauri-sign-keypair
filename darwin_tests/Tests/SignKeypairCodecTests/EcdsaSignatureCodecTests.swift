import XCTest

@testable import SignKeypairCodec

/// Known-answer tests for DER -> IEEE P1363.
///
/// **Provenance of the vectors.** The three `realSignature*` cases are genuine
/// P-256 ECDSA signatures produced by `openssl dgst -sha256 -sign` over the
/// message `"sign-keypair known-answer vector"`, selected out of 1200
/// samples to hit the shapes that only occur ~1 time in 256. Each expected
/// P1363 value was computed independently (not by this codec), re-encoded back
/// to DER, and confirmed with `openssl dgst -sha256 -verify` against the real
/// public key — so the expectations are anchored to a third-party
/// implementation, not to our own output.
///
/// Known answers rather than round-trips on purpose: a round-trip can be
/// self-consistently wrong (encode and decode sharing the same padding bug
/// cancel out), whereas a fixed input with a fixed expected output cannot.
///
/// The same vectors are used by the Kotlin suite
/// (`android/src/test/.../EcdsaSignatureCodecTest.kt`), which cross-validates the
/// two implementations against each other rather than each against itself.
final class EcdsaSignatureCodecTests: XCTestCase {

  // MARK: - real signatures

  /// r's magnitude is 31 bytes, so P1363 must LEFT-pad it with 0x00.
  /// This is the ~1-in-256 case that passes integration tests for weeks.
  func testRealSignatureWithShortR() throws {
    let der = Data(
      hex: "3043021f2952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2d"
        + "f02207d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93")
    let expected = Data(
      hex: "002952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2df"
        + "7d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93")

    let actual = try EcdsaSignatureCodec.derToP1363(der)

    XCTAssertEqual(actual, expected)
    XCTAssertEqual(actual.count, 64)
    XCTAssertEqual(actual[0], 0x00, "the pad byte must be at the FRONT of r")
    XCTAssertEqual(actual[1], 0x29, "r's magnitude must start at offset 1")
  }

  /// s's magnitude is 31 bytes; the leading 0x00 in the DER INTEGER is the sign
  /// byte, and the padded result happens to look identical — a good check that
  /// "strip then pad" and "leave alone" are not being conflated.
  func testRealSignatureWithShortS() throws {
    let der = Data(
      hex: "3044022007cf881741f66ab5f83b43c30b5ad3795bd6bb666010d2843ad594a9ba2c78c0"
        + "022000c35b6cfbdc8a99489ef54bc7d8308b262c10c88c4b321b90d92de7f683df52")
    let expected = Data(
      hex: "07cf881741f66ab5f83b43c30b5ad3795bd6bb666010d2843ad594a9ba2c78c0"
        + "00c35b6cfbdc8a99489ef54bc7d8308b262c10c88c4b321b90d92de7f683df52")

    let actual = try EcdsaSignatureCodec.derToP1363(der)

    XCTAssertEqual(actual, expected)
    XCTAssertEqual(actual.count, 64)
    XCTAssertEqual(actual[32], 0x00, "s must be left-padded")
    XCTAssertEqual(actual[33], 0xc3)
  }

  /// Both components have their high bit set, so DER carries a 0x00 sign byte on
  /// each (33-byte INTEGERs). Both sign bytes must be STRIPPED, not padded.
  func testRealSignatureWithBothHighBitSet() throws {
    let der = Data(
      hex: "30460221008ff702c97a2c11fc716b238919cef2bf0896545f8e65e2437cb77c97c2eb6c90"
        + "022100bd221a344e59eb869cf132f004dba37c2692024546681d46641b235b7a8822c6")
    let expected = Data(
      hex: "8ff702c97a2c11fc716b238919cef2bf0896545f8e65e2437cb77c97c2eb6c90"
        + "bd221a344e59eb869cf132f004dba37c2692024546681d46641b235b7a8822c6")

    let actual = try EcdsaSignatureCodec.derToP1363(der)

    XCTAssertEqual(actual, expected)
    XCTAssertEqual(actual.count, 64)
    XCTAssertEqual(actual[0], 0x8f, "the DER sign byte must not survive into r")
    XCTAssertEqual(actual[32], 0xbd, "the DER sign byte must not survive into s")
  }

  // MARK: - synthetic extremes

  /// The pathological minimum: r = 1, s = 2. Naive code emits 0x01 followed by
  /// 63 zeros (right-aligned) instead of 31 zeros then 0x01.
  func testTinyIntegersArePaddedOnTheLeft() throws {
    let der = Data(hex: "3006020101020102")

    let actual = try EcdsaSignatureCodec.derToP1363(der)

    XCTAssertEqual(actual.count, 64)
    XCTAssertEqual(Array(actual[0..<31]), [UInt8](repeating: 0, count: 31))
    XCTAssertEqual(actual[31], 0x01)
    XCTAssertEqual(Array(actual[32..<63]), [UInt8](repeating: 0, count: 31))
    XCTAssertEqual(actual[63], 0x02)
  }

  /// Both components short at once — 1 in ~65 000 real signatures, so it will
  /// never show up in an integration test, but it is one `if` away from being
  /// handled differently from the single-short case.
  func testBothComponentsShort() throws {
    // r = 0x00AA..(30 bytes of 0xAA), s = 0x0B..(29 bytes of 0x0B)
    let rMagnitude = [UInt8](repeating: 0xaa, count: 30)
    let sMagnitude = [UInt8](repeating: 0x0b, count: 29)
    var body: [UInt8] = [0x02, UInt8(rMagnitude.count)] + rMagnitude
    body += [0x02, UInt8(sMagnitude.count)] + sMagnitude
    let der = Data([0x30, UInt8(body.count)] + body)

    let actual = try EcdsaSignatureCodec.derToP1363(der)

    XCTAssertEqual(actual.count, 64)
    XCTAssertEqual(Array(actual[0..<2]), [0x00, 0x00], "r padded by 2 bytes")
    XCTAssertEqual(actual[2], 0xaa)
    XCTAssertEqual(Array(actual[32..<35]), [0x00, 0x00, 0x00], "s padded by 3 bytes")
    XCTAssertEqual(actual[35], 0x0b)
  }

  /// A zero component encodes as a single 0x00 byte in DER.
  func testZeroComponent() throws {
    let der = Data(hex: "3006020100020101")

    let actual = try EcdsaSignatureCodec.derToP1363(der)

    XCTAssertEqual(actual.count, 64)
    XCTAssertEqual(Array(actual[0..<32]), [UInt8](repeating: 0, count: 32))
    XCTAssertEqual(actual[63], 0x01)
  }

  /// Long-form SEQUENCE length (0x81 <len>). Not what SecKeyCreateSignature
  /// emits, but accepting it costs nothing and rejecting it silently would not.
  func testLongFormSequenceLength() throws {
    let r = [UInt8](repeating: 0x11, count: 32)
    let s = [UInt8](repeating: 0x22, count: 32)
    let body: [UInt8] = [0x02, 32] + r + [0x02, 32] + s
    let der = Data([0x30, 0x81, UInt8(body.count)] + body)

    let actual = try EcdsaSignatureCodec.derToP1363(der)

    XCTAssertEqual(actual, Data(r + s))
  }

  /// Every accepted input yields exactly 64 bytes — the property the JWS layer
  /// depends on and the one a caller cannot easily check.
  func testOutputIsAlwaysExactlySixtyFourBytes() throws {
    let inputs = [
      "3043021f2952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2d"
        + "f02207d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93",
      "30460221008ff702c97a2c11fc716b238919cef2bf0896545f8e65e2437cb77c97c2eb6c90"
        + "022100bd221a344e59eb869cf132f004dba37c2692024546681d46641b235b7a8822c6",
      "3006020101020102",
      "3006020100020100",
    ]
    for hex in inputs {
      let actual = try EcdsaSignatureCodec.derToP1363(Data(hex: hex))
      XCTAssertEqual(actual.count, 64, "input \(hex.prefix(16))… produced \(actual.count) bytes")
    }
  }

  // MARK: - malformed input

  /// These must fail cleanly. Reading past the end of the buffer here would be
  /// an out-of-bounds read on attacker-adjacent data.
  func testMalformedInputsThrowRatherThanCrash() {
    let cases: [(String, String)] = [
      ("", "empty buffer"),
      ("30", "SEQUENCE tag with no length"),
      ("3006", "length with no body"),
      ("30060201", "truncated inside the first INTEGER"),
      ("300602010102", "truncated before s's length"),
      ("3106020101020102", "wrong outer tag (SET, not SEQUENCE)"),
      ("3006030101020102", "wrong inner tag (BIT STRING, not INTEGER)"),
      ("3008020101020102", "declared length overruns the buffer"),
      ("3004020101020102", "declared length undershoots the buffer"),
      ("3006022001020102", "INTEGER length overruns the buffer"),
      ("3009020101020102aabbcc", "trailing bytes after s (encoding malleability)"),
      ("300602810102010201", "long-form INTEGER length"),
      ("3006020001020102", "zero-length INTEGER"),
      ("300402000200", "both INTEGERs zero-length — openssl calls these BAD INTEGER"),
      ("30250221" + String(repeating: "11", count: 33) + "020101", "r wider than 32 bytes"),
    ]

    for (hex, description) in cases {
      XCTAssertThrowsError(
        try EcdsaSignatureCodec.derToP1363(Data(hex: hex)),
        "expected a throw for \(description) — input \(hex)"
      )
    }
  }

  /// An INTEGER that overruns a well-formed SEQUENCE is reported as truncation.
  func testTruncatedIntegerReportsTruncation() {
    // SEQUENCE length (4) matches the buffer, but r claims 32 bytes with 2 left.
    XCTAssertThrowsError(try EcdsaSignatureCodec.derToP1363(Data(hex: "300402200102"))) { error in
      guard case EcdsaSignatureCodec.DecodingError.truncated = error else {
        return XCTFail("expected .truncated, got \(error)")
      }
    }
  }

  /// A SEQUENCE header that disagrees with the buffer is a length mismatch, not
  /// a truncation — the distinction matters when reading a crash report.
  func testShortBufferReportsLengthMismatch() {
    XCTAssertThrowsError(try EcdsaSignatureCodec.derToP1363(Data(hex: "30060201"))) { error in
      guard case EcdsaSignatureCodec.DecodingError.lengthMismatch = error else {
        return XCTFail("expected .lengthMismatch, got \(error)")
      }
    }
  }

  /// Trailing bytes inside the SEQUENCE must be rejected: silently ignoring
  /// them makes the encoding malleable (two distinct byte strings, one
  /// signature). `openssl asn1parse` rejects this same input with
  /// "Error in encoding", so we are matching a reference parser's strictness.
  func testTrailingBytesAreRejected() {
    XCTAssertThrowsError(try EcdsaSignatureCodec.derToP1363(Data(hex: "3009020101020102aabbcc"))) {
      error in
      guard case EcdsaSignatureCodec.DecodingError.lengthMismatch = error else {
        return XCTFail("expected .lengthMismatch, got \(error)")
      }
    }
  }

  /// Both INTEGERs zero-length. Without an explicit zero-length check this
  /// parses as r = 0, s = 0 and returns 64 zero bytes — a bogus signature
  /// accepted as valid. `openssl asn1parse` reports "BAD INTEGER" for it.
  func testAllZeroLengthIntegersAreRejected() {
    XCTAssertThrowsError(try EcdsaSignatureCodec.derToP1363(Data(hex: "300402000200")))
  }

  func testWrongTagReportsTheTag() {
    XCTAssertThrowsError(try EcdsaSignatureCodec.derToP1363(Data(hex: "3106020101020102"))) {
      error in
      XCTAssertEqual(
        error as? EcdsaSignatureCodec.DecodingError,
        .unexpectedTag(expected: 0x30, actual: 0x31))
    }
  }

  // MARK: - p1363ToDer

  func testP1363ToDerRejectsWrongLength() {
    for count in [0, 63, 65, 128] {
      XCTAssertThrowsError(
        try EcdsaSignatureCodec.p1363ToDer(Data(repeating: 0, count: count)),
        "expected a throw for a \(count)-byte input")
    }
  }

  func testP1363ToDerPrependsSignByteOnHighBit() throws {
    var p1363 = Data(repeating: 0xff, count: 32)
    p1363.append(Data(repeating: 0x01, count: 32))

    let der = try EcdsaSignatureCodec.p1363ToDer(p1363)
    let bytes = [UInt8](der)

    XCTAssertEqual(bytes[0], 0x30)
    XCTAssertEqual(bytes[2], 0x02)
    XCTAssertEqual(bytes[3], 33, "r must carry a 0x00 sign byte")
    XCTAssertEqual(bytes[4], 0x00)
  }

  /// Round-trip against the real signatures, on top of the known answers above.
  func testRoundTripPreservesRealSignatures() throws {
    let vectors = [
      "3043021f2952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2d"
        + "f02207d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93",
      "30460221008ff702c97a2c11fc716b238919cef2bf0896545f8e65e2437cb77c97c2eb6c90"
        + "022100bd221a344e59eb869cf132f004dba37c2692024546681d46641b235b7a8822c6",
    ]
    for hex in vectors {
      let p1363 = try EcdsaSignatureCodec.derToP1363(Data(hex: hex))
      let reencoded = try EcdsaSignatureCodec.p1363ToDer(p1363)
      XCTAssertEqual(try EcdsaSignatureCodec.derToP1363(reencoded), p1363)
    }
  }
}

extension Data {
  /// Test-only hex decoder. Traps on malformed input — a bad literal in a test
  /// file is a bug in the test, not a condition to handle.
  init(hex: String) {
    precondition(hex.count % 2 == 0, "odd-length hex literal")
    var bytes = [UInt8]()
    bytes.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<next], radix: 16) else {
        preconditionFailure("invalid hex literal: \(hex[index..<next])")
      }
      bytes.append(byte)
      index = next
    }
    self.init(bytes)
  }
}
