// swift-tools-version: 5.9
import PackageDescription

/// Standalone test harness for the plugin's pure-Swift code.
///
/// Why this exists as its own package rather than an Xcode test target: the
/// DER -> IEEE P1363 conversion and the wire vocabulary have no Tauri and no
/// Security-framework dependency, so testing them should not require booting a
/// simulator or building a Tauri app. `swift test` here takes seconds.
///
/// The two files under `Sources/SignKeypairCodec/` are **symlinks** to the
/// files the plugin actually ships — the tests exercise the real source, not a
/// copy that could drift.
let package = Package(
  name: "SignKeypairCodec",
  platforms: [.macOS(.v10_15)],
  targets: [
    .target(name: "SignKeypairCodec"),
    .testTarget(name: "SignKeypairCodecTests", dependencies: ["SignKeypairCodec"]),
  ]
)
