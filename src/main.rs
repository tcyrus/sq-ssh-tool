mod ssh2pgp;
mod pgp2ssh;

use std::path::PathBuf;
use std::fs::File;

use clap::{Parser, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;
use openpgp::parse::Parse;

use ssh_key;


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    #[command(name = "ssh2pgp")]
    Ssh2Pgp {
        ssh_key: PathBuf,
        #[arg(long)]
        v6: bool,
        #[arg(long)]
        userid: Option<openpgp::packet::UserID>,
        //time: Option<SystemTime>,
        pgp_file: PathBuf,
    },
    #[command(name = "pgp2ssh")]
    Pgp2Ssh {
        pgp_file: PathBuf,
        #[arg(long)]
        key: Option<openpgp::KeyHandle>,
        #[arg(long)]
        ignore_auth_check: bool,
        #[arg(long)]
        comment: Option<String>,
        ssh_key: PathBuf,
    }
}

fn main() {
    let cli = Cli::parse();
  
    match &cli.cmd {
        Commands::Ssh2Pgp { ssh_key, v6, userid, pgp_file } => {
            let _ssh_kfile = File::options().read(true).open(ssh_key).expect("SSH Key should be readable");
            // TODO: ssh_key::private::PrivateKey::read_openssh_file should support std::fs::File (std::io::Read)
            let ssh_key = ssh_key::PrivateKey::read_openssh_file(&ssh_key).expect("SSH Key should be readable");
            let pgp_cert = ssh2pgp::ssh2pgp(&ssh_key, userid.clone(), None, *v6);
            let pgp_cert = pgp_cert.expect("SSH Key should be converted");
            let mut pgp_file = File::options().write(true).create_new(true).open(pgp_file).expect("PGP File should be writable");
            pgp_cert.as_tsk().armored().serialize(&mut pgp_file).expect("PGP Cert should be exported");
        },
        Commands::Pgp2Ssh { pgp_file, key, ignore_auth_check, comment, ssh_key } => {
            let pgp_file = File::options().read(true).open(pgp_file).expect("PGP Cert should be readable");
            let pgp_cert = openpgp::Cert::from_reader(pgp_file).expect("PGP Cert should be parsed");
            let ssh_skey = pgp2ssh::pgp2ssh(pgp_cert, key.clone(), *ignore_auth_check, comment.as_deref()).expect("SSH Key should be converted");
            // TODO: ssh_key::private::PrivateKey::write_openssh_file should support std::fs::File (std::io::Write)
            let mut _ssh_kfile = File::options().write(true).create_new(true).open(ssh_key).expect("SSH Key should be writable");
            ssh_skey.write_openssh_file(ssh_key, Default::default()).expect("SSH Key should be encoded to PEM");
        }
    }
}
