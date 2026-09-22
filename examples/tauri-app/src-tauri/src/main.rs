// Hides the console window on a Windows release build.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_sign_keypair::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
