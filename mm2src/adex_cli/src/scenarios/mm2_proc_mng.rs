use common::log::{error, info};
use std::path::PathBuf;
use std::{env, u32};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};

#[cfg(windows)]
mod reexport {
    pub use std::ffi::CString;
    pub use std::mem;
    pub use std::mem::size_of;
    pub use std::ptr::null;
    pub use winapi::um::processthreadsapi::{CreateProcessA, OpenProcess, TerminateProcess, PROCESS_INFORMATION,
                                            STARTUPINFOA};
    pub use winapi::um::winnt::{PROCESS_TERMINATE, SYNCHRONIZE};

    pub const MM2_BINARY: &str = "mm2.exe";
}

#[cfg(unix)]
mod reexport {
    pub use fork::{daemon, Fork};
    pub use std::ffi::OsStr;
    pub use std::process::{Command, Stdio};

    pub const MM2_BINARY: &str = "mm2";
    pub const KILL_CMD: &str = "kill";
}

use reexport::*;

pub fn get_status() {
    let pids = find_proc_by_name(MM2_BINARY);
    if pids.is_empty() {
        info!("Process not found: {MM2_BINARY}");
    }
    pids.iter().map(u32::to_string).for_each(|pid| {
        info!("Found {MM2_BINARY} is running, pid: {pid}");
    });
}

fn find_proc_by_name(pname: &'_ str) -> Vec<u32> {
    let s = System::new_all();

    s.processes()
        .iter()
        .filter(|(_, process)| process.name() == pname)
        .map(|(pid, _)| pid.as_u32())
        .collect()
}

fn get_mm2_binary_path() -> Result<PathBuf, ()> {
    let mut dir = env::current_exe().map_err(|error| {
        error!("Failed to get current binary dir: {error}");
    })?;
    dir.pop();
    dir.push(MM2_BINARY);
    Ok(dir)
}

pub fn start_process(mm2_cfg_file: &Option<String>, coins_file: &Option<String>, log_file: &Option<String>) {
    let mm2_binary = match get_mm2_binary_path() {
        Err(_) => return,
        Ok(path) => path,
    };

    if let Some(mm2_cfg_file) = mm2_cfg_file {
        info!("Set env MM_CONF_PATH as: {mm2_cfg_file}");
        env::set_var("MM_CONF_PATH", mm2_cfg_file);
    }
    if let Some(coins_file) = coins_file {
        info!("Set env MM_COINS_PATH as: {coins_file}");
        env::set_var("MM_COINS_PATH", coins_file);
    }
    if let Some(log_file) = log_file {
        info!("Set env MM_LOG as: {log_file}");
        env::set_var("MM_LOG", log_file);
    }
    start_process_impl(mm2_binary);
}

#[cfg(unix)]
pub fn start_process_impl(mm2_binary: PathBuf) {
    let mut command = Command::new(&mm2_binary);
    let program = mm2_binary
        .file_name()
        .map_or("Undefined", |name: &OsStr| name.to_str().unwrap_or("Undefined"));

    match daemon(true, true) {
        Ok(Fork::Child) => {
            command.output().expect("failed to execute process");
        },
        Ok(Fork::Parent(pid)) => {
            info!("Successfully started: {program:?}, forked pid: {pid}");
        },
        Err(error) => error!("Failed to fork a process: {error}"),
    }
}

#[cfg(windows)]
pub fn start_process_impl(mm2_binary: PathBuf) {
    let program = mm2_binary.to_str();
    if program.is_none() {
        error!("Failed to cast mm2_binary to &str");
        return;
    }
    let program = CString::new(program.unwrap());
    if let Err(error) = program {
        error!("Failed to construct CString program path: {error}");
        return;
    }

    let mut startup_info: STARTUPINFOA = unsafe { mem::zeroed() };
    startup_info.cb = size_of::<STARTUPINFOA>() as u32;
    let mut process_info: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    let result = unsafe {
        CreateProcessA(
            null(),
            program.unwrap().into_raw() as *mut i8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut startup_info as &mut STARTUPINFOA,
            &mut process_info as *mut PROCESS_INFORMATION,
        )
    };

    match result {
        0 => error!("Failed to start: {MM2_BINARY}"),
        _ => {
            info!("Successfully started: {MM2_BINARY}");
        },
    }
}

#[cfg(unix)]
pub fn stop_process() {
    let pids = find_proc_by_name(MM2_BINARY);
    if pids.is_empty() {
        info!("Process not found: {MM2_BINARY}");
    }
    pids.iter().map(u32::to_string).for_each(|pid| {
        match Command::new(KILL_CMD)
            .arg(&pid)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) => {
                if status.success() {
                    info!("Process killed: {MM2_BINARY}:{pid}")
                } else {
                    error!("Failed to kill process: {MM2_BINARY}:{pid}")
                }
            },
            Err(e) => error!("Failed to kill process: {MM2_BINARY}:{pid}. Error: {e}"),
        };
    });
}

#[cfg(windows)]
pub fn stop_process() {
    let processes = find_proc_by_name(MM2_BINARY);
    for pid in processes {
        info!("Terminate process: {}", pid);
        unsafe {
            let handy = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, true as i32, pid);
            TerminateProcess(handy, 1);
        }
    }
}
