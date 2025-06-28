mod ssh2pgp;
mod pgp2ssh;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(name = "pgp2ssh")]
    Pgp2Ssh(pgp2ssh::cli::Cli),
    #[command(name = "ssh2pgp")]
    Ssh2Pgp(ssh2pgp::cli::Cli),
}

fn main() {
    let cli = Cli::parse();
  
    match &cli.cmd {
        Commands::Pgp2Ssh(cli) => { cli.run() },
        Commands::Ssh2Pgp(cli) => { cli.run() },
    }
}
