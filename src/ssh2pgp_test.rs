use std::time::SystemTime;

use ssh_key;
use ssh_key::PrivateKey as SshPrivateKey;

use sequoia_openpgp as openpgp;
use openpgp::serialize::SerializeInto;

//use rpassword;

use crate::ssh2pgp::ssh2pgp;

/// Ed25519 OpenSSH-formatted private key
const OPENSSH_ED25519_EXAMPLE: &str = include_str!("../tests/examples/id_ed25519");

const PGP_UNIX_EPOCH: SystemTime = SystemTime::UNIX_EPOCH;

#[test]
fn test_v4() {
    let ssh_private_key = SshPrivateKey::from_openssh(OPENSSH_ED25519_EXAMPLE).expect("SSH Key should be parsed");

    // TODO: Properly map out errors and stuff
    /*
    let ssh_private_key = if ssh_private_key.is_encrypted() {
        let password = rpassword::prompt_password("Please enter the SSH Key Password");
        password.ok().and_then(|pass| ssh_private_key.decrypt(pass).ok()).expect("SSH Key should be decrypted")
    } else {
        ssh_private_key
    };
    */

    assert!(!ssh_private_key.is_encrypted(), "SSH Key is not decrypted");

    // Key attributes
    assert_eq!(ssh_private_key.algorithm(), ssh_key::Algorithm::Ed25519);
    assert_eq!(ssh_private_key.comment(), "user@example.com");

    let pgp_cert = ssh2pgp(&ssh_private_key, None, Some(PGP_UNIX_EPOCH), false).expect("SSH Key should be converted");

    let pgp_cert_str = String::from_utf8(pgp_cert.as_tsk().armored().to_vec().unwrap()).unwrap();

    // Note: Sequoia automatically adds a "salt@notations.sequoia-pgp.org" Notation to all signatures
    // I can't figure out a way around this behavior as of now

    println!("{}", pgp_cert_str);
}

#[test]
fn test_v6() {
    let ssh_private_key = SshPrivateKey::from_openssh(OPENSSH_ED25519_EXAMPLE).expect("SSH Key should be parsed");

    assert!(!ssh_private_key.is_encrypted(), "SSH Key is not decrypted");

    assert_eq!(ssh_private_key.algorithm(), ssh_key::Algorithm::Ed25519);
    assert_eq!(ssh_private_key.comment(), "user@example.com");

    let pgp_cert = ssh2pgp(&ssh_private_key, None, Some(PGP_UNIX_EPOCH), true).expect("SSH Key should be converted");

    let pgp_cert_str = String::from_utf8(pgp_cert.as_tsk().armored().to_vec().unwrap()).unwrap();

    println!("{}", pgp_cert_str);
}
