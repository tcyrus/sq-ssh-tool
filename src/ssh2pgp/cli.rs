use std::path::PathBuf;
use std::fs::File;

use clap::{Parser, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;

use ssh_key::PrivateKey as SshPrivateKey;

use super::ssh2pgp;

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
        ssh_key: PathBuf,
        #[arg(long)]
        v6: bool,
        #[arg(long)]
        userid: Option<openpgp::packet::UserID>,
        //time: Option<SystemTime>,
        pgp_file: PathBuf,
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
            Self::Sec { ssh_key, v6, userid, pgp_file } => {
                let _ssh_kfile = File::options().read(true).open(ssh_key).expect("SSH Key should be readable");
                // TODO: ssh_key::private::PrivateKey::read_openssh_file should support std::fs::File (std::io::Read)
                let ssh_key = SshPrivateKey::read_openssh_file(&ssh_key).expect("SSH Key should be readable");
                let pgp_cert = ssh2pgp(&ssh_key, userid.clone(), None, *v6);
                let pgp_cert = pgp_cert.expect("SSH Key should be converted");
                let mut pgp_file = File::options().write(true).create_new(true).open(pgp_file).expect("PGP File should be writable");
                pgp_cert.as_tsk().armored().serialize(&mut pgp_file).expect("PGP Cert should be exported");
            }
        }
    }
}
