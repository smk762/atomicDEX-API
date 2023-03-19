use fork::{daemon, Fork};
use log::{error, info};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::{env, u32};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};

const MM2_BINARY: &str = "mm2";
const KILL_CMD: &str = "kill";

fn find_proc_by_name(pname: &'_ str) -> Vec<u32> {
    let s = System::new_all();

    s.processes()
        .iter()
        .filter(|(_, process)| process.name() == pname)
        .map(|(pid, _)| pid.as_u32())
        .collect()
}

fn get_mm2_binary_dir() -> Result<PathBuf, ()> {
    let mut dir = env::current_exe().map_err(|error| {
        error!("Failed to get current binary dir: {error}");
    })?;
    dir.pop();
    dir.push(MM2_BINARY);
    Ok(dir)
}

pub fn start_process(mm2_cfg_file: &Option<String>, coins_file: &Option<String>, log_file: &Option<String>) {
    let mm2_binary = match get_mm2_binary_dir() {
        Err(_) => return,
        Ok(path) => path,
    };

    let mut command = Command::new(mm2_binary);
    if let Some(mm2_cfg_file) = mm2_cfg_file {
        info!("Set env MM_CONF_PATH as: {mm2_cfg_file}");
        command.env("MM_CONF_PATH", mm2_cfg_file);
    }
    if let Some(coins_file) = coins_file {
        info!("Set env MM_COINS_PATH as: {coins_file}");
        command.env("MM_COINS_PATH", coins_file);
    }
    if let Some(log_file) = log_file {
        info!("Set env MM_LOG as: {log_file}");
        command.env("MM_LOG", log_file);
    }

    let program = command.get_program();
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

pub fn get_status() {
    let pids = find_proc_by_name(MM2_BINARY);
    if pids.is_empty() {
        info!("Process not found: {MM2_BINARY}");
    }
    pids.iter().map(u32::to_string).for_each(|pid| {
        info!("Found {MM2_BINARY} is running, pid: {pid}");
    });
}
