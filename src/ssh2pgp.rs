use std::time::SystemTime;

use ssh_key;
use ssh_key::EcdsaCurve as SshEcdsaCurve;
use ssh_key::PrivateKey as SshPrivateKey;
use ssh_key::private::KeypairData as SshKeypairData;

use sequoia_openpgp as openpgp;
use openpgp::Packet as PgpPacket;
use openpgp::packet::{
    UserID as PgpUserID,
    Key as PgpKey,
    key::Key4 as PgpKey4,
    key::Key6 as PgpKey6,
    key::SecretParts as PgpKeySecretParts,
    key::UnspecifiedRole as PgpKeyUnspecifiedRole,
    signature::SignatureBuilder as PgpSignatureBuilder,
};
use openpgp::Cert as PgpCert;
use openpgp::types::{
    KeyFlags as PgpKeyFlags,
    SignatureType as PgpSignatureType,
};
use openpgp::crypto as pgpcrypto;
use openpgp::crypto::mpi as pgpmpi;

fn try_ssh_keypair_data_into_pgp_v4_key(
    ssh_keypair_data: &SshKeypairData,
    pgp_ctime: Option<SystemTime>,
) -> Result<PgpKey4<PgpKeySecretParts, PgpKeyUnspecifiedRole>, ()> {
    // If I can't implement TryInto/TryFrom here
    // then this is what I'm gonna do

    match ssh_keypair_data {
        SshKeypairData::Dsa(key) => {
            // There is no import_secret_dsa function
            // This is based on generate_dsa
            let public_mpis = pgpmpi::PublicKey::DSA {
                p: pgpmpi::MPI::new(key.public.p.as_bytes()),
                q: pgpmpi::MPI::new(key.public.q.as_bytes()),
                g: pgpmpi::MPI::new(key.public.g.as_bytes()),
                y: pgpmpi::MPI::new(key.public.y.as_bytes())
            };
            let private_mpis = pgpmpi::SecretKeyMaterial::DSA {
                x: pgpmpi::ProtectedMPI::from(key.private.as_bytes())
            };

            PgpKey4::with_secret(
                pgp_ctime.unwrap_or(SystemTime::now()),
                #[allow(deprecated)]
                pgpcrypto::PublicKeyAlgorithm::DSA,
                public_mpis,
                private_mpis.into()
            ).map_err(|_| ())
        },

        SshKeypairData::Ecdsa(key) => {
            let public_mpis = pgpmpi::PublicKey::ECDSA {
                curve: match key.curve() {
                    SshEcdsaCurve::NistP256 => pgpcrypto::Curve::NistP256,
                    SshEcdsaCurve::NistP384 => pgpcrypto::Curve::NistP384,
                    SshEcdsaCurve::NistP521 => pgpcrypto::Curve::NistP521,
                },
                q: pgpmpi::MPI::new(key.public_key_bytes()),
            };
            let private_mpis = pgpmpi::SecretKeyMaterial::ECDSA {
                scalar: pgpmpi::ProtectedMPI::from(key.private_key_bytes()),
            };
            PgpKey4::with_secret(
                pgp_ctime.unwrap_or(SystemTime::now()),
                pgpcrypto::PublicKeyAlgorithm::ECDSA,
                public_mpis,
                private_mpis.into()
            ).map_err(|_| ())
        },

        SshKeypairData::Ed25519(key) => {
            PgpKey4::import_secret_ed25519(
                key.private.as_ref(),
                pgp_ctime
            ).map_err(|_| ())
        },

        SshKeypairData::Rsa(key) => {
            PgpKey4::import_secret_rsa(
                key.private.d.as_bytes(),
                key.private.p.as_bytes(),
                key.private.q.as_bytes(),
                pgp_ctime
            ).map_err(|_| ())
        },

        // ssh_key doesn't give us any secret data
        // Sk stands for Security Key (no private key file)
        SshKeypairData::SkEcdsaSha2NistP256(_) | SshKeypairData::SkEd25519(_) => Err(()),

        // I don't believe there's any way to convert an encrypted key
        // Both of them don't share any S2K / KDF's for starters
        SshKeypairData::Encrypted(_) => Err(()),

        _ => Err(()),
    }
}

fn try_ssh_keypair_data_into_pgp_key(
    ssh_keypair_data: &SshKeypairData,
    pgp_ctime: Option<SystemTime>,
    pgp_v6: bool,
) -> Result<PgpKey<PgpKeySecretParts, PgpKeyUnspecifiedRole>, ()> {
    match (ssh_keypair_data, pgp_v6) {
        // Handling v6 edge cases
        (SshKeypairData::Ed25519(key), true) => {
            // Ed25519 v6 Keys are very different from Ed25519 v4 Keys
            PgpKey6::<PgpKeySecretParts, PgpKeyUnspecifiedRole>::import_secret_ed25519(
                key.private.as_ref(),
                pgp_ctime
            ).map_err(|_| ()).map(PgpKey::from)
        },
        (SshKeypairData::Dsa(_), true) => {
            // DSA isn't supported by PGP v6
            Err(())
        },
        (_, _) => {
            let pgp_v4_key = try_ssh_keypair_data_into_pgp_v4_key(ssh_keypair_data, pgp_ctime);

            if pgp_v6 {
                // We can't access PgpKey6::from_common
                // So I'm trying the next best thing

                let (pgp_v4_key, pgp_sec) = pgp_v4_key?.take_secret();

                // We are cloning the MPIs because of ownership

                PgpKey6::<PgpKeySecretParts, PgpKeyUnspecifiedRole>::with_secret(
                    pgp_v4_key.creation_time(),
                    pgp_v4_key.pk_algo(),
                    pgp_v4_key.mpis().clone(),
                    pgp_sec,
                ).map_err(|_| ()).map(PgpKey::from)
            } else {
                pgp_v4_key.map(PgpKey::from)
            }
        }
    }
}

fn make_pgp_cert(
    pgp_key: PgpKey<PgpKeySecretParts, PgpKeyUnspecifiedRole>,
    pgp_userid: Option<PgpUserID>,
    pgp_ctime: Option<SystemTime>,
) -> Result<PgpCert, ()> {
    // Note: The resulting Cert is different than something
    // that would be generated by GnuPG.

    // GnuPG Structure:
    // - {Public,Private}-Key Packet
    // - User ID Packet
    // - Signature Packet (PositiveCertification)
    // -- Key flags: CA

    // Sequoia Structure:
    // - {Public,Private}-Key Packet
    // - Signature Packet (DirectKey)
    // -- Key flags: CA
    // - User ID Packet
    // - Signature Packet (PositiveCertification)
    // -- Primary User ID: true

    // GnuPG will still accept this cert.

    let pgp_primary_key = pgp_key.role_into_primary();

    let cert = PgpCert::try_from(vec![
        PgpPacket::SecretKey(
            pgp_primary_key.clone()
        ),
    ]).map_err(|_| ())?;

    // PacketPile doesn't support insert for some reason.
    // We're using a vec because we need to insert packets
    let mut acc = Vec::<PgpPacket>::new();

    let mut signer = pgp_primary_key.clone().into_keypair().map_err(|_| ())?;

    // Make DirectKey Signature Packet
    // - Set KEY_FLAG_CERTIFY and KEY_FLAG_AUTHENTICATE
    let sigbuilder =
        PgpSignatureBuilder::new(PgpSignatureType::DirectKey)
        .set_key_flags(PgpKeyFlags::certification().set_authentication()).map_err(|_| ())?;

    let sigbuilder = match pgp_ctime {
        Some(ctime) => sigbuilder.set_signature_creation_time(ctime),
        None => Ok(sigbuilder),
    }.map_err(|_| ())?;

    let signature = sigbuilder.sign_direct_key(&mut signer, pgp_primary_key.parts_as_public())
                              .map_err(|_| ())?;

    acc.push(signature.into());

    if let Some(pgp_userid) = pgp_userid {
        // Add UserID
        acc.push(PgpPacket::from(pgp_userid.clone()));

        // Make PositiveCertification Signature Packet
        // - Sign (primary) UserID
        let sigbuilder =
            PgpSignatureBuilder::new(PgpSignatureType::PositiveCertification)
            .set_primary_userid(true).map_err(|_| ())?;

        let sigbuilder = match pgp_ctime {
            Some(ctime) => sigbuilder.set_signature_creation_time(ctime),
            None => Ok(sigbuilder),
        }.map_err(|_| ())?;

        let signature = pgp_userid.bind(&mut signer, &cert, sigbuilder).map_err(|_| ())?;
        acc.push(signature.into());
    }

    // Add all packets to cert
    let cert = cert.insert_packets(acc).map_err(|_| ())?.0;

    Ok(cert)
}

pub fn ssh2pgp(
    ssh_private_key: &SshPrivateKey,
    pgp_userid: Option<PgpUserID>,
    pgp_ctime: Option<SystemTime>,
    pgp_v6: bool,
) -> Result<PgpCert, ()> {
    if ssh_private_key.is_encrypted() {
        return Err(());
    }

    let pgp_userid = match pgp_userid {
        Some(uid) => {
            if uid.value().is_empty() {
                None
            } else {
                Some(uid)
            }
        },
        None => {
            let ssh_comment = ssh_private_key.comment();
            if ssh_comment.is_empty() {
                None
            } else {
                Some(PgpUserID::from(ssh_private_key.comment()))
            }
        },
    };

    let pgp_key = try_ssh_keypair_data_into_pgp_key(
        ssh_private_key.key_data(),
        pgp_ctime,
        pgp_v6,
    )?;

    let pgp_cert = make_pgp_cert(
        pgp_key,
        pgp_userid,
        pgp_ctime,
    );
    
    pgp_cert
}

#[cfg(test)]
#[path = "./ssh2pgp_test.rs"]
mod ssh2pgp_test;