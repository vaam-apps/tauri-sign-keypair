// Hides the console window on a Windows release build.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri_sign_keypair_example_lib::run()
}
