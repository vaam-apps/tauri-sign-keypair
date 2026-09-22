// swift-tools-version:5.3
import PackageDescription

let package = Package(
  name: "tauri-plugin-sign-keypair",
  platforms: [
    // The Secure Enclave and `.biometryCurrentSet` both predate this, so the
    // floor is Tauri's own iOS minimum rather than anything this plugin needs.
    .iOS(.v13)
  ],
  products: [
    .library(
      name: "tauri-plugin-sign-keypair",
      type: .static,
      targets: ["tauri-plugin-sign-keypair"])
  ],
  dependencies: [
    .package(name: "Tauri", path: "../.tauri/tauri-api")
  ],
  targets: [
    .target(
      name: "tauri-plugin-sign-keypair",
      dependencies: [
        .byName(name: "Tauri")
      ],
      path: "Sources")
  ]
)
