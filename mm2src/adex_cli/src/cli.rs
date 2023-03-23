use clap::{Parser, Subcommand};

use crate::scenarios::{get_status, init, start_process, stop_process};

#[derive(Subcommand)]
enum Command {
    #[command(about = "Initialize predefined mm2 coin set and configuration")]
    Init {
        #[arg(long, help = "coin set file path", default_value = "coins")]
        mm_coins_path: String,
        #[arg(long, help = "mm2 configuration file path", default_value = "MM2.json")]
        mm_conf_path: String,
    },
    #[command(about = "Start mm2 service")]
    Start {
        #[arg(long, help = "mm2 configuration file path")]
        mm_conf_path: Option<String>,
        #[arg(long, help = "coin set file path")]
        mm_coins_path: Option<String>,
        #[arg(long, help = "log file path")]
        mm_log: Option<String>,
    },
    #[command(about = "Stop mm2 service")]
    Stop,
    #[command(about = "Get mm2 running status")]
    Status,
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub fn execute() {
        let parsed_cli = Self::parse();
        match &parsed_cli.command {
            Command::Init {
                mm_coins_path: coins_file,
                mm_conf_path: mm2_cfg_file,
            } => init(mm2_cfg_file, coins_file),
            Command::Start {
                mm_conf_path: mm2_cfg_file,
                mm_coins_path: coins_file,
                mm_log: log_file,
            } => start_process(mm2_cfg_file, coins_file, log_file),
            Command::Stop => stop_process(),
            Command::Status => get_status(),
        }
    }
}
