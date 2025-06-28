use ssh_key;
use ssh_key::PrivateKey as SshPrivateKey;
use ssh_key::Mpint as SshMpint;
use ssh_key::public as sshpublic;
use ssh_key::private as sshprivate;

use sshpublic::KeyData as SshKeyData;
use sshprivate::KeypairData as SshKeypairData;

use ssh_key::sec1 as sec1;
use sec1::consts::{U32, U48, U66};

//use ssh_key::encoding::Decode;
use ssh_encoding::Decode;

use sequoia_openpgp as openpgp;
use openpgp::packet::{
    Key as PgpKey,
    key::PublicParts as PgpKeyPublicParts,
    key::UnspecifiedRole as PgpKeyUnspecifiedRole,
    key::SecretKeyMaterial as PgpSecretKeyMaterial,
    key::Unencrypted as PgpUnencrypted,
};
use openpgp::Cert as PgpCert;
use openpgp::KeyHandle as PgpKeyHandle;
use openpgp::crypto as pgpcrypto;
use openpgp::crypto::mpi as pgpmpi;

use openpgp::policy::NullPolicy as PgpNullPolicy;

fn try_pgp_pubkey_into_ssh_keydata(
    pgp_key: PgpKey<PgpKeyPublicParts, PgpKeyUnspecifiedRole>,
) -> Result<SshKeyData, ()> {
    match pgp_key.mpis() {
        pgpmpi::PublicKey::DSA { p, q, g, y } => {
            match (
                SshMpint::from_bytes(p.value()),
                SshMpint::from_bytes(q.value()),
                SshMpint::from_bytes(g.value()),
                SshMpint::from_bytes(y.value()),
            ) {
                (Ok(p), Ok(q), Ok(g), Ok(y)) => {
                    Some(
                        sshpublic::DsaPublicKey { p, q, g, y }
                    )
                },
                _ => None,
            }.map(SshKeyData::from)
        },
        pgpmpi::PublicKey::EdDSA { curve, q } => {
            match curve {
                pgpcrypto::Curve::Ed25519 => {
                    // q has a leading byte of 0x40 (64) when using the EdDSA type
                    // See RFC for more details:
                    // https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07#section-13.3

                    let q = q.value();
                    if q.get(0).is_some_and(|&b| b == 0x40) {
                        let q = &q[1..sshpublic::Ed25519PublicKey::BYTE_SIZE+1];
                        <[u8; sshpublic::Ed25519PublicKey::BYTE_SIZE]>::try_from(q).ok().map(|p| {
                            sshpublic::Ed25519PublicKey(p)
                        })
                    } else { None }.map(SshKeyData::from)
                },
                c @ (pgpcrypto::Curve::NistP256 | pgpcrypto::Curve::NistP384 | pgpcrypto::Curve::NistP521) => {
                    // NOTE: Points are (probably) stored in uncompressed forms in both ssh and pgp.
                    match c {
                        pgpcrypto::Curve::NistP256 => {
                            Some(
                                sshpublic::EcdsaPublicKey::NistP256(
                                    sec1::EncodedPoint::<U32>::from_untagged_bytes(q.value().into())
                                )
                            )
                        },
                        pgpcrypto::Curve::NistP384 => {
                            Some(
                                sshpublic::EcdsaPublicKey::NistP384(
                                    sec1::EncodedPoint::<U48>::from_untagged_bytes(q.value().into())
                                )
                            )
                        },
                        pgpcrypto::Curve::NistP521 => {
                            Some(
                                sshpublic::EcdsaPublicKey::NistP521(
                                    sec1::EncodedPoint::<U66>::from_untagged_bytes(q.value().into())
                                )
                            )
                        },
                        _ => { /*unreachable!()*/ None },
                    }.map(SshKeyData::from)
                },
                _ => None,
            }
        },
        pgpmpi::PublicKey::Ed25519 { a } => {
            Some(SshKeyData::from(sshpublic::Ed25519PublicKey(*a)))
        },
        pgpmpi::PublicKey::RSA { e, n } => {
            match (
                SshMpint::from_bytes(e.value()),
                SshMpint::from_bytes(n.value()),
            ) {
                (Ok(e), Ok(n)) => {
                    Some(
                        sshpublic::RsaPublicKey { e, n }
                    )
                },
                _ => None,
            }.map(SshKeyData::from)
        },
        _ => None,
    }.ok_or(())
}

fn try_pgp_sec_into_ssh_keypairdata(
    ssh_keydata: SshKeyData,
    pgp_sec: PgpUnencrypted,
) -> Result<SshKeypairData, ()> {
    // PgpSecretKeyMaterial is encrypted in memory and only decrypted when necessary.
    // The old workaround was:
    // let pgp_sec = pgp_sec.map(|pgp_sec| { pgp_sec.clone() });
    // Now we're only decrypting the secret if/when we use it.

    match ssh_keydata {
        SshKeyData::Dsa(public) => {
            let ssh_private = pgp_sec.map(|pgp_sec| {
                match pgp_sec {
                    pgpmpi::SecretKeyMaterial::DSA { x } => {
                        // TODO: DsaPrivateKey::new is introduced in ssh-key v0.7.0-pre.1
                        // ssh-key v0.7.0-pre.1 currently fails to build (for me) because of an issue with
                        // ssh-cipher v0.3.0-pre.2
                        /*
                        match (
                            SshMpint::from_bytes(x.value()),
                        ) {
                            (Ok(x)) => sshprivate::DsaPrivateKey::new(x).ok(),
                            _ => None,
                        }
                        */
                        // decode shouldn't work, but it does for some reason
                        sshprivate::DsaPrivateKey::decode(&mut x.value()).ok()
                    },
                    _ => None,
                }
            });

            ssh_private.map(|private| SshKeypairData::Dsa(
                sshprivate::DsaKeypair {
                    public,
                    private
                }
            )).ok_or(())
        },
    
        SshKeyData::Ecdsa(sshpublic::EcdsaPublicKey::NistP256(public)) => {
            let ssh_private = pgp_sec.map(|pgp_sec| {
                match pgp_sec {
                    pgpmpi::SecretKeyMaterial::EdDSA { scalar } => {
                        // decode shouldn't work, but it does for some reason
                        sshprivate::EcdsaPrivateKey::<32>::decode(&mut scalar.value()).ok()
                    },
                    _ => None,
                }
            });

            ssh_private.map(|private| SshKeypairData::Ecdsa(
                sshprivate::EcdsaKeypair::NistP256 {
                    public,
                    private
                }
            )).ok_or(())
        },

        SshKeyData::Ecdsa(sshpublic::EcdsaPublicKey::NistP384(public)) => {
            let ssh_private = pgp_sec.map(|pgp_sec| {
                match pgp_sec {
                    pgpmpi::SecretKeyMaterial::EdDSA { scalar } => {
                        // decode shouldn't work, but it does for some reason
                        sshprivate::EcdsaPrivateKey::<48>::decode(&mut scalar.value()).ok()
                    },
                    _ => None,
                }
            });

            ssh_private.map(|private| SshKeypairData::Ecdsa(
                sshprivate::EcdsaKeypair::NistP384 {
                    public,
                    private
                }
            )).ok_or(())
        },

        SshKeyData::Ecdsa(sshpublic::EcdsaPublicKey::NistP521(public)) => {
            let ssh_private = pgp_sec.map(|pgp_sec| {
                match pgp_sec {
                    pgpmpi::SecretKeyMaterial::EdDSA { scalar } => {
                        // decode shouldn't work, but it does for some reason
                        sshprivate::EcdsaPrivateKey::<66>::decode(&mut scalar.value()).ok()
                    },
                    _ => None,
                }
            });

            ssh_private.map(|private| SshKeypairData::Ecdsa(
                sshprivate::EcdsaKeypair::NistP521 {
                    public,
                    private
                }
            )).ok_or(())
        },

        SshKeyData::Ed25519(public) => {
            let ssh_private = pgp_sec.map(|pgp_sec| {
                match pgp_sec {
                    pgpmpi::SecretKeyMaterial::EdDSA { scalar } => {
                        let scalar = &scalar.value()[..sshprivate::Ed25519PrivateKey::BYTE_SIZE];
                        <&[u8; sshprivate::Ed25519PrivateKey::BYTE_SIZE]>::try_from(scalar).ok().map(|s| {
                            sshprivate::Ed25519PrivateKey::from_bytes(s)
                        })
                    },
                    pgpmpi::SecretKeyMaterial::Ed25519 { x } => {
                        // NOTE: Protected can't be read. This is a workaround.
                        let x = &x.as_ref()[..sshprivate::Ed25519PrivateKey::BYTE_SIZE];
                        <&[u8; sshprivate::Ed25519PrivateKey::BYTE_SIZE]>::try_from(x).ok().map(|s| {
                            sshprivate::Ed25519PrivateKey::from_bytes(s)
                        })
                    },
                    _ => None,
                }
            });

            ssh_private.map(|private| SshKeypairData::Ed25519(
                sshprivate::Ed25519Keypair {
                    public,
                    private
                }
            )).ok_or(())
        },

        SshKeyData::Rsa(public) => {
            let ssh_private = pgp_sec.map(|pgp_sec| {
                match pgp_sec {
                    pgpmpi::SecretKeyMaterial::RSA { d, p, q, u } => {
                        match (
                            SshMpint::from_bytes(d.value()),
                            SshMpint::from_bytes(p.value()),
                            SshMpint::from_bytes(q.value()),
                            SshMpint::from_bytes(u.value()),
                        ) {
                            (Ok(d), Ok(p), Ok(q), Ok(iqmp)) => {
                                Some(sshprivate::RsaPrivateKey {
                                    d,
                                    iqmp,
                                    p,
                                    q,
                                })
                            },
                            _ => None,
                        }
                    },
                    _ => None,
                }
            });

            ssh_private.map(|private| SshKeypairData::Rsa(
                sshprivate::RsaKeypair {
                    public,
                    private
                }
            )).ok_or(())
        },
        _ => Err(()),
    }
}

pub fn pgp2ssh(
    pgp_cert: PgpCert,
    pgp_keyhandle: Option<PgpKeyHandle>,
    pgp_ignore_auth_flag: bool,
    ssh_comment: Option<&str>,
) -> Result<SshPrivateKey, ()> {
    // We aren't validating the PGP cert. Our only goal is to extract
    // data.

    let p = unsafe { PgpNullPolicy::new() };
    let pgp_valid_cert = pgp_cert.with_policy(&p, None).map_err(|_| ())?;

    let ssh_comment = ssh_comment.or_else(|| {
        pgp_valid_cert.primary_userid().ok()
            .map(|a| a.userid())
            .and_then(|u| str::from_utf8(u.value()).ok())
    }).filter(|c| !c.is_empty());

    let pgp_keyiter = pgp_valid_cert.keys().secret();

    let pgp_keyiter = match pgp_keyhandle {
        Some(keyhandle) => pgp_keyiter.key_handle(keyhandle),
        None => pgp_keyiter,
    };

    // size_hint doesn't work for ValidKeyAmalgamationIter
    // We need to choose between enforcing the authentication flag or
    // rejecting a key matching the keyhandle. We're gonna use a bool to decide.

    let mut pgp_keyiter = match pgp_ignore_auth_flag {
        true => pgp_keyiter,
        false => pgp_keyiter.for_authentication(),
    };

    let pgp_key = pgp_keyiter.next().ok_or(())?.key();

    // Separate PGP Public Key and Secret
    let (pgp_pub_key, pgp_sec) = pgp_key.clone().take_secret();

    // Converting the PGP Public Key to an SSH Public KeyData allows us to
    // handle some PGP (v4/v6) edge cases early on.
    let ssh_pubdata = try_pgp_pubkey_into_ssh_keydata(pgp_pub_key)?;

    let pgp_sec = match pgp_sec {
        PgpSecretKeyMaterial::Unencrypted(k) => Ok(k),
        PgpSecretKeyMaterial::Encrypted(_k) => {
            // TODO: Decrypt Key Here
            // Look into decrypt_key
            // https://sequoia-pgp.gitlab.io/sequoia-sq/impl/sq/sq/struct.Sq.html#method.decrypt_key
            Err(())
        },
    }?;

    let ssh_keydata = try_pgp_sec_into_ssh_keypairdata(
        ssh_pubdata,
        pgp_sec,
    )?;

    let mut ssh_key = SshPrivateKey::try_from(ssh_keydata).map_err(|_| ())?;

    if let Some(ssh_comment) = ssh_comment {
        ssh_key.set_comment(ssh_comment);
    }

    Ok(ssh_key)
}
