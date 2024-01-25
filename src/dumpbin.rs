use std::path::{Path, PathBuf};
use forensic_rs::{prelude::RegistryReader, traits::registry::{RegHiveKey, RegValue}};
use frnsc_liveregistry_rs::LiveRegistryReader;

use crate::err::DumpBinError;
use forensic_rs::prelude::RegHiveKey::*;

const INSTALLED_VC: &str = r"SOFTWARE\WOW6432Node\Microsoft\VisualStudio\VC";

pub struct DumpBin {
    dumpbin_path: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct Dependents {
    pub libraries : Vec<String>,
    pub summary : Vec<(u32, String)>
}

impl DumpBin {
    pub fn new() -> Result<DumpBin, DumpBinError> {
        Ok(DumpBin {
            dumpbin_path: locate_dumpbin()?,
        })
    }
    /**
     * Instantiate DumpBin for a VC version. Ex: 19.0 = Visual Studio 14.0
     */
    pub fn for_kit(version : &str) -> Result<DumpBin, DumpBinError> {
        Ok(DumpBin {
            dumpbin_path: locate_dumpbin_for_vc(version)?,
        })
    }
    pub fn vc19() -> Result<DumpBin, DumpBinError> {
        Ok(DumpBin {
            dumpbin_path: locate_dumpbin_for_vc("19.0")?,
        })
    }

    pub fn dependents(&self, pth : &PathBuf) -> Result<Dependents, DumpBinError> {
        let mut command = std::process::Command::new(&self.dumpbin_path);
        let output = match command.arg("/DEPENDENTS").arg(pth.as_os_str()).output() {
            Ok(v) => v,
            Err(e) => return Err(DumpBinError::Io(e))
        };
        let output = match String::from_utf8(output.stdout.clone()) {
            Ok(v) => v,
            Err(_) => String::from_utf8_lossy(&output.stdout).to_string()
        };
        let mut ret = Dependents::default();
        let dll_regex = regex::RegexBuilder::new("Image has the following dependencies:").case_insensitive(true).build().unwrap();
        let dll_matched = match dll_regex.find(&output) {
            Some(v) => v,
            None => return Err(DumpBinError::Other(format!("Cannot find dependencies: {}", output)))
        };
        let dll_regex = regex::RegexBuilder::new("Summary").case_insensitive(true).build().unwrap();
        let sum_matched = match dll_regex.find(&output) {
            Some(v) => v,
            None => return Err(DumpBinError::Other(format!("Cannot find summary: {}", output)))
        };
        let dependencies = output[dll_matched.end()..sum_matched.start()].trim();
        
        for library in dependencies.split(" ").filter(|v| !v.trim().is_empty()) {
            ret.libraries.push(library.trim().to_string());
        }

        let summary = output[sum_matched.end()..].trim();
        for library in summary.split("\n").filter(|v| !v.trim().is_empty()) {
            let mut splited = library.trim().split(" ").filter(|v| !v.trim().is_empty());
            let first = match splited.next() {
                Some(v) => v,
                None => continue
            };
            let second = match splited.next() {
                Some(v) => v,
                None => continue
            };

            ret.summary.push((first.parse().unwrap_or_default(), second.to_string()));
        }
        Ok(ret)
    }
}

fn get_vcs(reg_reader : &LiveRegistryReader, installed_vcs_key : RegHiveKey) -> Result<Vec<String>, DumpBinError> {
    let kits = reg_reader.enumerate_keys(installed_vcs_key)?.into_iter().collect();
    Ok(kits)
}

fn locate_dumpbin() -> Result<PathBuf, DumpBinError> {
    let reg_reader = frnsc_liveregistry_rs::LiveRegistryReader::new();
    let installed_vcs_key = reg_reader.open_key(HkeyLocalMachine, INSTALLED_VC)?;
    let vc_list = match get_vcs(&reg_reader, installed_vcs_key) {
        Ok(v) => v,
        Err(e) => {
            reg_reader.close_key(installed_vcs_key);
            return Err(e)
        }
    };
    let mut selected_vc = None;
    let arch = current_arch();
    for vc in vc_list {
        let subkey = format!("{}\\{}\\{}",vc, arch, arch);
        let vc_compiler_key = match reg_reader.open_key(installed_vcs_key, subkey.as_str()) {
            Ok(v) => v,
            Err(_) => continue
        };
        let vc_compiler_path = match reg_reader.read_value(vc_compiler_key, "Compiler") {
            Ok(RegValue::SZ(v)) => v,
            _ => {
                reg_reader.close_key(vc_compiler_key);
                continue;
            }
        };
        let compiler_path = Path::new(&vc_compiler_path);
        let tool_folder = match compiler_path.parent() {
            Some(v) => v,
            None => {
                reg_reader.close_key(vc_compiler_key);
                continue;
            }
        };
        let dumpbin = tool_folder.join("dumpbin.exe");
        if dumpbin.exists() {
            selected_vc = Some(dumpbin);
        }
        reg_reader.close_key(vc_compiler_key);
    }
    match selected_vc {
        Some(v) => Ok(v),
        None => Err(DumpBinError::Other("No DumpBin found!".into()))
    }
}

fn locate_dumpbin_for_vc(vc : &str) -> Result<PathBuf, DumpBinError> {
    let reg_reader = frnsc_liveregistry_rs::LiveRegistryReader::new();
    let installed_vcs_key = reg_reader.open_key(HkeyLocalMachine, INSTALLED_VC)?;
    let vc_list = vec![vc];
    let mut selected_vc = None;
    let arch = current_arch();
    for vc in vc_list {
        let subkey = format!("{}\\{}\\{}",vc, arch, arch);
        let vc_compiler_key = match reg_reader.open_key(installed_vcs_key, subkey.as_str()) {
            Ok(v) => v,
            Err(_) => continue
        };
        let vc_compiler_path = match reg_reader.read_value(vc_compiler_key, "Compiler") {
            Ok(RegValue::SZ(v)) => v,
            _ => {
                reg_reader.close_key(vc_compiler_key);
                continue;
            }
        };
        let compiler_path = Path::new(&vc_compiler_path);
        let tool_folder = match compiler_path.parent() {
            Some(v) => v,
            None => {
                reg_reader.close_key(vc_compiler_key);
                continue;
            }
        };
        let dumpbin = tool_folder.join("dumpbin.exe");
        if dumpbin.exists() {
            selected_vc = Some(dumpbin);
        }
        reg_reader.close_key(vc_compiler_key);
    }
    match selected_vc {
        Some(v) => Ok(v),
        None => Err(DumpBinError::Other("No DumpBin found!".into()))
    }
}

fn current_arch() -> &'static str {
    #[cfg(target_arch = "x86")]
    let arch_dir = "x86";
    #[cfg(target_arch = "x86_64")]
    let arch_dir = "x64";
    #[cfg(target_arch = "aarch64")]
    let arch_dir = "arm64";
    #[cfg(target_arch = "arm")]
    let arch_dir = "arm";
    arch_dir
}


#[test]
fn should_validate_cargo_command() {
    let current_exe = std::env::current_exe().unwrap();
    let result = DumpBin::new().unwrap().dependents(&current_exe).unwrap();
    assert!(result.libraries.iter().find(|v| v.to_lowercase() == "kernel32.dll").is_some());
}