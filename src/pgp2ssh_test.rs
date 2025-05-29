use std::str::FromStr;

use sequoia_openpgp as openpgp;
use openpgp::Cert as PgpCert;

//use rpassword;

use crate::pgp2ssh::pgp2ssh;

/// Ed25519 OpenPGP private key
const OPENPGP_ED25519_V4_EXAMPLE: &str = include_str!("../tests/examples/ed25519_v4.pgp");
const OPENPGP_ED25519_V6_EXAMPLE: &str = include_str!("../tests/examples/ed25519_v6.pgp");

#[test]
fn test_v4() {
    let pgp_cert = PgpCert::from_str(OPENPGP_ED25519_V4_EXAMPLE).expect("PGP Cert should be parsed");

    let ssh_private_key = pgp2ssh(pgp_cert, None, false, None).expect("SSH Key should be converted");

    let ssh_private_pem = ssh_private_key.to_openssh(Default::default()).expect("SSH Key should be encoded to PEM");

    println!("{}", ssh_private_pem.trim_end());
}

#[test]
fn test_v6() {
    let pgp_cert = PgpCert::from_str(OPENPGP_ED25519_V6_EXAMPLE).expect("PGP Cert should be parsed");

    let ssh_private_key = pgp2ssh(pgp_cert, None, false, None).expect("SSH Key should be converted");

    let ssh_private_pem = ssh_private_key.to_openssh(Default::default()).expect("SSH Key should be encoded to PEM");

    println!("{}", ssh_private_pem.trim_end());
}
