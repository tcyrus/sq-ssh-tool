use std::str::FromStr;

use ssh_key;

use sequoia_openpgp as openpgp;
use openpgp::Cert as PgpCert;

use crate::pgp2ssh::pgp2ssh;

/// OpenPGP private key
const OPENPGP_RFC9580_A4: &str = include_str!("../../tests/examples/rfc9580_a4.pgp");
const OPENPGP_RFC9580_A4_V4: &str = include_str!("../../tests/examples/rfc9580_a4_v4.pgp");
const OPENPGP_RFC9580_A4_V6: &str = include_str!("../../tests/examples/rfc9580_a4_v6.pgp");


#[test]
fn test_rfc9580_a4() {
    let pgp_cert = PgpCert::from_str(OPENPGP_RFC9580_A4).expect("PGP Cert should be parsed");

    let ssh_skey = pgp2ssh(pgp_cert, None, true, None).expect("SSH Key should be converted");

    assert_eq!(ssh_skey.algorithm(), ssh_key::Algorithm::Ed25519);
    assert!(ssh_skey.comment().is_empty());

    let ssh_pem = ssh_skey.to_openssh(Default::default()).expect("SSH Key should be encoded to PEM");
    println!("{}", ssh_pem.trim_end());

    let ssh_psig = ssh_skey.public_key().to_openssh().expect("SSH Key should be encoded to Pubkey format");
    println!("{}", ssh_psig.trim_end());
}

#[test]
fn test_rfc9580_a4_v4() {
    let pgp_cert = PgpCert::from_str(OPENPGP_RFC9580_A4_V4).expect("PGP Cert should be parsed");

    let ssh_skey = pgp2ssh(pgp_cert, None, true, None).expect("SSH Key should be converted");

    assert_eq!(ssh_skey.algorithm(), ssh_key::Algorithm::Ed25519);
    assert_eq!(ssh_skey.comment(), "user@example.com");

    let ssh_pem = ssh_skey.to_openssh(Default::default()).expect("SSH Key should be encoded to PEM");
    println!("{}", ssh_pem.trim_end());

    let ssh_psig = ssh_skey.public_key().to_openssh().expect("SSH Key should be encoded to Pubkey format");
    println!("{}", ssh_psig.trim_end());
}

#[test]
fn test_rfc9580_a4_v6() {
    let pgp_cert = PgpCert::from_str(OPENPGP_RFC9580_A4_V6).expect("PGP Cert should be parsed");

    let ssh_skey = pgp2ssh(pgp_cert, None, true, None).expect("SSH Key should be converted");

    assert_eq!(ssh_skey.algorithm(), ssh_key::Algorithm::Ed25519);
    assert_eq!(ssh_skey.comment(), "user@example.com");

    // Note: Output file should end with a newline.
    // Otherwise ssh-keygen will return "invalid format" with no explanation (verbose does nothing)
    let ssh_pem = ssh_skey.to_openssh(Default::default()).expect("SSH Key should be encoded to PEM");
    println!("{}", ssh_pem.trim_end());

    let ssh_psig = ssh_skey.public_key().to_openssh().expect("SSH Key should be encoded to Pubkey format");
    println!("{}", ssh_psig.trim_end());
}
