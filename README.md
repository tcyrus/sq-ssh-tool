# `sq-ssh-tool`

### Note

This is a work in progress. The output seems to have some variation (encoding quirks + sequoia signature salts), but the public key of a round trip conversion matches.

You can attach the converted key to your existing primary key / cert using either [GnuPG](https://security.stackexchange.com/a/160847) or [Sequoia](https://book.sequoia-pgp.org/sq_subkey.html#generating-new-subkeys).

This does work on Windows, but you should probably build it with the appropriate crypto backend:

```
cargo build --no-default-features --features crypto-cng
```

More info can be found [here](https://gitlab.com/sequoia-pgp/sequoia/-/tree/main/openpgp?ref_type=heads#crypto-backends).


## `ssh2pgp`

```
sq-ssh-tool ssh2pgp sec
./id_ed25519
--userid="Alice <alice@example.org>"
[--v6]
./alice-secret.pgp
```

Take SSH Private Key as input and output PGP Private Key / Cert

PGP Key Modes: Certify and Auth

SSH Passphrase: Prompt

Version:
- Default to V4

UserID:
- Default to SSH Comment
- Empty UserID will not be included

## `pgp2ssh`

```
sq-ssh-tool pgp2ssh sec
./alice-secret.pgp
--key=0D45C6A756A038670FDFD85CB1C82E8D27DB23A1
[--ignore-auth-check]
--comment="alice@example.org"
./id_ed25519
```

Take PGP Cert (with Auth Secret Key / SubKey) as input and output SSH Private Key

PGP Passphrase: Prompt (Sequoia doesn't handle password prompts)

Key(Handle):
- Default to First Key with Auth Mode
- Use first key that matches keyhandle
- See sequoia_openpgp::KeyHandle

Comment:
- Default to Primary UserID
- Don't set comment if comment arg is empty string

### Notes

#### CLI

Look into following deps:
- sequoia-cert-store
- sequoia-keystore

Look at [sequoia-sq](https://gitlab.com/sequoia-pgp/sequoia-sq/) for reference

#### MPI

MPI's are Multiprecision integers.

OpenPGP calls these "MPI"s in [RFC9580 § 3.2](https://www.rfc-editor.org/rfc/rfc9580.html#section-3.2). OpenSSH calls these "mpint"s in [RFC4251 § 5](https://datatracker.ietf.org/doc/html/rfc4251#section-5)

Converting between the two seems to work. The main difference is that OpenPGP uses 2 bytes for the length while OpenSSH uses 4 bytes.

| Value                | OpenPGP MPI     | OpenSSH mpint                         |
| -------------------- | --------------- | ------------------------------------- |
| `0`                  | `00 00`         | `00 00 00 00`                         |
| `1`                  | `00 01 01`      | `00 00 00 01 01`\*                    |
| `128`                | `00 02 00 80`\* | `00 00 00 02 00 80`                   |
| `511`                | `00 09 01 ff`   | ?                                     |
| `694531781388612263` | ?               | `00 00 00 08 09 a3 78 f9 b2 e3 32 a7` |
| `-4660`              | ?               | `00 00 00 02 ed cc`                   |
| `-3735928559`        | ?               | `00 00 00 05 ff 21 52 41 11`          |

The only reason that converting between these formats is working right now is because `ssh_key::Mpint` and `sequoia_openpgp::crypto::mpi::MPI` are storing values after decoding them (with the exception of some weird point stuff).

Some suggestions:
- Consider replacing `sequoia_openpgp::crypto::mpi::MPI` with `elliptic_curve::sec1::EncodedPoint` where appropriate (e.g. `sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { q }`)
- Consider replacing `ssh_key::private::PrivateKey` and `ssh_key::public::PublicKey` with a unified struct (e.g. `ssh_key::Key<P: KeyParts>`) like `sequoia_openpgp::packet::key::Key`