// scredmgr GUI — architecture rule (from the kickoff brief): the GUI
// never owns a secret and never touches the keychain directly. One engine
// (the CLI), two front-ends. This backend does nothing but spawn
// `scredmgr <cmd> --json` and relay the envelope to the WebView.
//
// Deliberately NO dependency on Security.framework, keychain crates, or any
// secret-handling code. Audit `cargo tree` to confirm.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

/// Locate the scredmgr CLI. Order: $SCREDMGR_BIN, ~/.local/bin,
/// Homebrew paths, then $PATH.
fn resolve_bin() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("SCREDMGR_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Ok(pb);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let pb = PathBuf::from(home).join(".local/bin/scredmgr");
        if pb.is_file() {
            return Ok(pb);
        }
    }
    for p in ["/opt/homebrew/bin/scredmgr", "/usr/local/bin/scredmgr"] {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Ok(pb);
        }
    }
    // Fall back to $PATH resolution by the OS.
    if Command::new("scredmgr").arg("--help").output().is_ok() {
        return Ok(PathBuf::from("scredmgr"));
    }
    Err("scredmgr CLI not found — install it with `make install` or set SCREDMGR_BIN".into())
}

/// Reject arguments that could be misparsed as flags or contain unexpected
/// characters. Ids share the CLI's charset; a leading '-' is never valid.
fn safe_arg(s: &str, what: &str) -> Result<(), String> {
    if s.is_empty() || s.starts_with('-') {
        return Err(format!("invalid {what}"));
    }
    Ok(())
}

/// Run the CLI with `--json` and return the schemaVersion-1 envelope. The
/// envelope's `ok`/`error` fields are relayed as-is; stderr (already
/// redacted by the CLI) is attached for context on parse failures.
fn cli_json(args: &[&str]) -> Result<Value, String> {
    let bin = resolve_bin()?;
    let out = Command::new(&bin)
        .args(args)
        .arg("--json")
        .output()
        .map_err(|e| format!("spawn {}: {e}", bin.display()))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    match serde_json::from_str::<Value>(&stdout) {
        Ok(v) => Ok(v),
        Err(_) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(format!(
                "CLI returned no JSON (exit {:?}): {}",
                out.status.code(),
                stderr.trim()
            ))
        }
    }
}

#[tauri::command]
fn gui_status() -> Result<Value, String> {
    cli_json(&["status"])
}

#[tauri::command]
fn gui_services() -> Result<Value, String> {
    cli_json(&["services"])
}

#[tauri::command]
fn gui_ls() -> Result<Value, String> {
    cli_json(&["ls"])
}

#[tauri::command]
fn gui_rm(id: String) -> Result<Value, String> {
    safe_arg(&id, "id")?;
    cli_json(&["rm", &id])
}

/// Login can block for minutes (clipboard watch / device-code approval), so
/// it runs async on a blocking thread. The GUI passes clipboard=true for
/// services without a deviceFlow; the CLI auto-selects the device flow when
/// the manifest configures one.
#[tauri::command]
async fn gui_login(id: String, clipboard: bool) -> Result<Value, String> {
    safe_arg(&id, "id")?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut args = vec!["login", id.as_str()];
        if clipboard {
            args.push("--clipboard");
        }
        cli_json(&args)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn gui_check(id: String) -> Result<Value, String> {
    safe_arg(&id, "id")?;
    tauri::async_runtime::spawn_blocking(move || cli_json(&["check", &id]))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn gui_import(path: String) -> Result<Value, String> {
    safe_arg(&path, "path")?;
    // Expand a leading ~ — the CLI does not.
    let expanded = if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
        format!("{home}/{rest}")
    } else {
        path
    };
    tauri::async_runtime::spawn_blocking(move || cli_json(&["import", &expanded]))
        .await
        .map_err(|e| e.to_string())?
}

/// Post the native expiry notification via the CLI's own osascript path —
/// keeps notification logic in one place (and can replace the launchd job).
#[tauri::command]
fn gui_notify() -> Result<(), String> {
    let bin = resolve_bin()?;
    Command::new(bin)
        .args(["status", "--quiet", "--notify"])
        .output()
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            gui_status,
            gui_services,
            gui_ls,
            gui_rm,
            gui_login,
            gui_check,
            gui_import,
            gui_notify
        ])
        .run(tauri::generate_context!())
        .expect("error while running scredmgr GUI");
}
