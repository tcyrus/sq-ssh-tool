use std::path::PathBuf;
use std::fs::File;

use clap::{Parser, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

use super::pgp2ssh;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub(crate) struct Cli {
    #[command(subcommand)]
    cmd: Commands
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(name = "sec")]
    Sec {
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

impl Cli {
    pub fn run(&self) {
        self.cmd.run()
    }
}

impl Commands {
    fn run(&self) {
        match &self {
            Self::Sec { pgp_file, key, ignore_auth_check, comment, ssh_key } => {
                let pgp_file = File::options().read(true).open(pgp_file).expect("PGP Cert should be readable");
                let pgp_cert = openpgp::Cert::from_reader(pgp_file).expect("PGP Cert should be parsed");
                let ssh_skey = pgp2ssh(pgp_cert, key.clone(), *ignore_auth_check, comment.as_deref()).expect("SSH Key should be converted");
                // TODO: ssh_key::private::PrivateKey::write_openssh_file should support std::fs::File (std::io::Write)
                let mut _ssh_kfile = File::options().write(true).create_new(true).open(ssh_key).expect("SSH Key should be writable");
                ssh_skey.write_openssh_file(ssh_key, Default::default()).expect("SSH Key should be encoded to PEM");
            }
        }
    }
}
