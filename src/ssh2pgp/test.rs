use std::time::{SystemTime, Duration};

use ssh_key;
use ssh_key::PrivateKey as SshPrivateKey;

use sequoia_openpgp as openpgp;
use openpgp::serialize::SerializeInto;

use crate::ssh2pgp::ssh2pgp;

/// Ed25519 OpenSSH-formatted private key
const OPENSSH_RFC9580_A4: &str = include_str!("../../tests/examples/rfc9580_a4.pem");

#[test]
fn test_v4() {
    let ssh_private_key = SshPrivateKey::from_openssh(OPENSSH_RFC9580_A4).expect("SSH Key should be parsed");

    assert!(!ssh_private_key.is_encrypted(), "SSH Key is not decrypted");

    // Key attributes
    assert_eq!(ssh_private_key.algorithm(), ssh_key::Algorithm::Ed25519);
    assert!(ssh_private_key.comment().is_empty());

    let ctime = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(1669824483));

    let pgp_cert = ssh2pgp(&ssh_private_key, Some("user@example.com".into()), ctime, false).expect("SSH Key should be converted");

    let pgp_cert_str = String::from_utf8(pgp_cert.as_tsk().armored().to_vec().unwrap()).unwrap();

    // Note: Sequoia automatically adds a "salt@notations.sequoia-pgp.org" Notation to all signatures
    // I can't figure out a way around this behavior as of now

    println!("{}", pgp_cert_str);
}

#[test]
fn test_v6() {
    let ssh_private_key = SshPrivateKey::from_openssh(OPENSSH_RFC9580_A4).expect("SSH Key should be parsed");

    assert!(!ssh_private_key.is_encrypted(), "SSH Key is not decrypted");

    assert_eq!(ssh_private_key.algorithm(), ssh_key::Algorithm::Ed25519);
    assert!(ssh_private_key.comment().is_empty());

    let ctime = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(1669824483));

    let pgp_cert = ssh2pgp(&ssh_private_key, Some("user@example.com".into()), ctime, true).expect("SSH Key should be converted");

    let pgp_cert_str = String::from_utf8(pgp_cert.as_tsk().armored().to_vec().unwrap()).unwrap();

    println!("{}", pgp_cert_str);
}
