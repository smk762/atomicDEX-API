mod cli;
mod log;
mod scenarios;

fn main() {
    log::init_logging();
    cli::process_cli();
}
