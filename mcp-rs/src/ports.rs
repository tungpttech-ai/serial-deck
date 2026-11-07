//! Serial port discovery from sysfs, never opening a UART (uart_client.py).

use serde_json::{Map, Value, json};
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

fn text(p: &Path) -> String {
    fs::read_to_string(p).map(|s| s.trim().to_string()).unwrap_or_default()
}

fn ancestors(parent: &Path) -> impl Iterator<Item = &Path> {
    parent.ancestors().take(5)
}

/// pyserial's Linux candidates: same globs, minus `platform` subsystem ttys.
fn candidates() -> Vec<String> {
    let prefixes = ["ttyS", "ttyUSB", "ttyXRUSB", "ttyACM", "ttyAMA", "rfcomm", "ttyAP"];
    let mut out = Vec::new();
    for prefix in prefixes {
        let mut found: Vec<String> = fs::read_dir("/dev").into_iter().flatten().flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(prefix))
            .collect();
        found.sort();
        for name in found {
            let device = format!("/sys/class/tty/{name}/device");
            let subsystem = fs::canonicalize(format!("{device}/subsystem")).ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
            if subsystem.as_deref() != Some("platform") {
                out.push(format!("/dev/{name}"));
            }
        }
    }
    out
}

/// Accessible, configured serial candidates with names (serial_port_details).
pub fn discover() -> Vec<Map<String, Value>> {
    let mut result: Vec<Map<String, Value>> = Vec::new();
    for device in candidates() {
        let Ok(meta) = fs::metadata(&device) else { continue };
        if !meta.file_type().is_char_device() {
            continue;
        }
        let c = std::ffi::CString::new(device.clone()).unwrap();
        if unsafe { libc::access(c.as_ptr(), libc::R_OK | libc::W_OK) } != 0 {
            continue;
        }
        let tty = PathBuf::from("/sys/class/tty").join(Path::new(&device).file_name().unwrap());
        let uart_type = text(&tty.join("type"));
        if uart_type == "0" {
            continue;
        }
        let parent = fs::canonicalize(tty.join("device")).unwrap_or_else(|_| tty.join("device"));
        if uart_type.is_empty() && parent.to_string_lossy().contains("serial8250") {
            continue;
        }
        let mut interface = text(&parent.join("interface"));
        let number = text(&parent.join("bInterfaceNumber"));
        if interface.is_empty() && !number.is_empty() {
            interface = format!("Interface {number}");
        }
        let (mut description, mut manufacturer) = (String::new(), String::new());
        for a in ancestors(&parent) {
            let product = text(&a.join("product"));
            if !product.is_empty() {
                description = product;
                manufacturer = text(&a.join("manufacturer"));
                break;
            }
        }
        if description.is_empty() || description == "n/a" {
            description = "Serial port".into();
        }
        let mut parts = vec![description];
        for item in [manufacturer, interface] {
            if !item.is_empty() && !parts.join(" ").to_lowercase().contains(&item.to_lowercase()) {
                parts.push(item);
            }
        }
        let name = parts.join(" - ");
        result.push(crate::util::obj(json!({"device": device, "description": name, "label": format!("{device} - {name}")})));
    }
    result.sort_by(|a, b| a["device"].as_str().cmp(&b["device"].as_str()));
    result
}

/// USB vid:pid, serial and interface number for a tty from sysfs.
pub fn usb_identity(device: &str) -> Map<String, Value> {
    let mut out = Map::new();
    if !device.starts_with("/dev/") {
        return out;
    }
    let real = crate::util::realpath(Path::new(device));
    let Some(name) = real.file_name() else { return out };
    let Ok(parent) = fs::canonicalize(PathBuf::from("/sys/class/tty").join(name).join("device")) else { return out };
    let mut interface = String::new();
    for a in ancestors(&parent) {
        if interface.is_empty() {
            let v = text(&a.join("bInterfaceNumber")).to_lowercase();
            if v.len() == 2 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                interface = v;
            }
        }
        let (Ok(vid), Ok(pid)) = (fs::read_to_string(a.join("idVendor")), fs::read_to_string(a.join("idProduct"))) else { continue };
        out.insert("usb_vid_pid".into(), json!(format!("{}:{}", vid.trim(), pid.trim())));
        out.insert("usb_serial".into(), json!(text(&a.join("serial"))));
        out.insert("usb_interface".into(), json!(interface));
        return out;
    }
    out
}
