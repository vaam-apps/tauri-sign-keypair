//! The example's Tauri setup.
//!
//! This lives in a library rather than in `main.rs` because Tauri's mobile
//! targets do not run a `main`: Android loads the app as a shared object and
//! calls the `#[tauri::mobile_entry_point]` symbol from Kotlin, and iOS links
//! the same code as a static library. `main.rs` is then a thin desktop shim
//! that calls the same `run()`, so all three platforms share one builder.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_sign_keypair::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
