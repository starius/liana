//! Signer module
//!
//! Some helpers to facilitate the usage of a signer in client of the Liana daemon. For now
//! only contains a hot signer.

use crate::random;

use std::{
    collections::BTreeMap,
    convert::TryInto,
    error, fmt, fs,
    io::{self, Write},
    path,
    str::FromStr,
};

use miniscript::bitcoin::{
    self,
    bip32::{self, Error as Bip32Error, Fingerprint},
    ecdsa,
    hashes::Hash,
    key::TapTweak,
    psbt::{raw, Input as PsbtIn, Psbt},
    secp256k1, sighash,
};
use musig2::{
    secp256k1 as musig_secp256k1, AggNonce, BinaryEncoding, CompactSignature, KeyAggContext,
    PartialSignature, PubNonce, SecNonce,
};

/// An error related to using a signer.
#[derive(Debug)]
pub enum SignerError {
    Randomness(random::RandomnessError),
    Mnemonic(bip39::Error),
    Bip32(Bip32Error),
    MnemonicStorage(io::Error),
    InsanePsbt,
    IncompletePsbt,
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Randomness(s) => write!(f, "Error related to getting randomness: {s}"),
            Self::Mnemonic(s) => write!(f, "Error when working with mnemonics: {s}"),
            Self::Bip32(e) => write!(f, "BIP32 error: {e}"),
            Self::MnemonicStorage(e) => write!(f, "BIP39 mnemonic storage error: {e}"),
            Self::InsanePsbt => write!(f, "Information contained in the PSBT is wrong."),
            Self::IncompletePsbt => write!(
                f,
                "The PSBT is missing some information necessary for signing."
            ),
        }
    }
}

impl error::Error for SignerError {}

pub const MNEMONICS_FOLDER_NAME: &str = "mnemonics";

const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x1a;
const PSBT_IN_MUSIG2_PUB_NONCE: u8 = 0x1b;
const PSBT_IN_MUSIG2_PARTIAL_SIG: u8 = 0x1c;

const PSBT_PROPRIETARY_PREFIX_LIANA: &[u8] = b"liana";
const PSBT_IN_LIANA_MUSIG2_NONCE_SEED: u8 = 0x00;
const PSBT_IN_LIANA_MUSIG2_AGGNONCE: u8 = 0x01;

// TODO: zeroize, mlock, etc.. For now we don't even encrypt the seed on disk so that'd be
// overkill.
/// A signer that keeps the key on the laptop. Based on BIP39.
pub struct HotSigner {
    mnemonic: bip39::Mnemonic,
    master_xpriv: bip32::Xpriv,
}

// TODO: instead of copying them here we could have a util module with those helpers.
// Create a directory with no permission for group and other users.
fn create_dir(path: &path::Path) -> io::Result<()> {
    #[cfg(unix)]
    return {
        use fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = DirBuilder::new();
        builder.mode(0o700).recursive(true).create(path)
    };

    // TODO: permissions on Windows..
    #[cfg(not(unix))]
    fs::create_dir_all(path)
}

// Create a file with no permission for the group and other users, and only read permissions for
// the current user.
fn create_file(path: &path::Path) -> Result<fs::File, std::io::Error> {
    let mut options = fs::OpenOptions::new();
    let options = options.read(true).write(true).create_new(true);

    #[cfg(unix)]
    return {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o400).open(path)
    };

    #[cfg(not(unix))]
    return {
        // TODO: permissions for Windows...
        options.open(path)
    };
}

#[derive(Clone)]
struct Musig2ParticipantSet {
    aggregate_pubkey: secp256k1::PublicKey,
    participant_pubkeys: Vec<secp256k1::PublicKey>,
}

struct Musig2InputSession {
    participant_set: Musig2ParticipantSet,
    participant_pubkeys: Vec<secp256k1::PublicKey>,
    key_agg_ctx: KeyAggContext,
}

#[derive(Clone)]
struct OwnedMusig2Participant {
    participant_pubkey: secp256k1::PublicKey,
    derivation_path: bip32::DerivationPath,
}

fn musig2_composite_key(
    type_value: u8,
    participant_pubkey: secp256k1::PublicKey,
    aggregate_pubkey: secp256k1::PublicKey,
) -> raw::Key {
    raw::Key {
        type_value,
        key: [
            participant_pubkey.serialize().as_slice(),
            aggregate_pubkey.serialize().as_slice(),
        ]
        .concat(),
    }
}

fn musig2_input_proprietary_key(
    subtype: u8,
    participant_pubkey: secp256k1::PublicKey,
    aggregate_pubkey: secp256k1::PublicKey,
) -> raw::ProprietaryKey {
    raw::ProprietaryKey {
        prefix: PSBT_PROPRIETARY_PREFIX_LIANA.to_vec(),
        subtype,
        key: [
            participant_pubkey.serialize().as_slice(),
            aggregate_pubkey.serialize().as_slice(),
        ]
        .concat(),
    }
}

fn bitcoin_to_musig_pubkey(
    pubkey: secp256k1::PublicKey,
) -> Result<musig_secp256k1::PublicKey, SignerError> {
    musig_secp256k1::PublicKey::from_slice(&pubkey.serialize()).map_err(|_| SignerError::InsanePsbt)
}

fn musig_to_bitcoin_pubkey(
    pubkey: musig_secp256k1::PublicKey,
) -> Result<secp256k1::PublicKey, SignerError> {
    secp256k1::PublicKey::from_slice(&pubkey.serialize()).map_err(|_| SignerError::InsanePsbt)
}

fn bitcoin_to_musig_secret_key(
    secret_key: secp256k1::SecretKey,
) -> Result<musig_secp256k1::SecretKey, SignerError> {
    musig_secp256k1::SecretKey::from_byte_array(secret_key.secret_bytes())
        .map_err(|_| SignerError::InsanePsbt)
}

fn parse_musig2_participant_sets(
    psbt_in: &PsbtIn,
) -> Result<Vec<Musig2ParticipantSet>, SignerError> {
    let mut sets = Vec::new();
    for (key, value) in &psbt_in.unknown {
        if key.type_value != PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS {
            continue;
        }
        if key.key.len() != 33 || value.is_empty() || value.len() % 33 != 0 {
            return Err(SignerError::InsanePsbt);
        }
        let aggregate_pubkey =
            secp256k1::PublicKey::from_slice(&key.key).map_err(|_| SignerError::InsanePsbt)?;
        let participant_pubkeys = value
            .chunks_exact(33)
            .map(|pubkey| {
                secp256k1::PublicKey::from_slice(pubkey).map_err(|_| SignerError::InsanePsbt)
            })
            .collect::<Result<Vec<_>, _>>()?;
        sets.push(Musig2ParticipantSet {
            aggregate_pubkey,
            participant_pubkeys,
        });
    }
    Ok(sets)
}

fn parse_musig2_pubnonces(
    psbt_in: &PsbtIn,
    aggregate_pubkey: secp256k1::PublicKey,
) -> Result<Vec<(secp256k1::PublicKey, PubNonce)>, SignerError> {
    let mut pubnonces = Vec::new();
    for (key, value) in &psbt_in.unknown {
        if key.type_value != PSBT_IN_MUSIG2_PUB_NONCE {
            continue;
        }
        if key.key.len() != 66 {
            continue;
        }
        let participant_pubkey = secp256k1::PublicKey::from_slice(&key.key[..33])
            .map_err(|_| SignerError::InsanePsbt)?;
        let key_aggregate_pubkey = secp256k1::PublicKey::from_slice(&key.key[33..])
            .map_err(|_| SignerError::InsanePsbt)?;
        if key_aggregate_pubkey != aggregate_pubkey {
            continue;
        }
        let pubnonce =
            PubNonce::from_bytes(value.as_slice()).map_err(|_| SignerError::InsanePsbt)?;
        pubnonces.push((participant_pubkey, pubnonce));
    }
    Ok(pubnonces)
}

fn parse_musig2_partial_signatures(
    psbt_in: &PsbtIn,
    aggregate_pubkey: secp256k1::PublicKey,
) -> Result<Vec<(secp256k1::PublicKey, PartialSignature)>, SignerError> {
    let mut partial_signatures = Vec::new();
    for (key, value) in &psbt_in.unknown {
        if key.type_value != PSBT_IN_MUSIG2_PARTIAL_SIG {
            continue;
        }
        if key.key.len() != 66 {
            continue;
        }
        let participant_pubkey = secp256k1::PublicKey::from_slice(&key.key[..33])
            .map_err(|_| SignerError::InsanePsbt)?;
        let key_aggregate_pubkey = secp256k1::PublicKey::from_slice(&key.key[33..])
            .map_err(|_| SignerError::InsanePsbt)?;
        if key_aggregate_pubkey != aggregate_pubkey {
            continue;
        }
        let partial_signature =
            PartialSignature::from_slice(value.as_slice()).map_err(|_| SignerError::InsanePsbt)?;
        partial_signatures.push((participant_pubkey, partial_signature));
    }
    Ok(partial_signatures)
}

fn read_musig2_nonce_seed(
    psbt_in: &PsbtIn,
    participant_pubkey: secp256k1::PublicKey,
    aggregate_pubkey: secp256k1::PublicKey,
) -> Result<Option<[u8; 32]>, SignerError> {
    let key = musig2_input_proprietary_key(
        PSBT_IN_LIANA_MUSIG2_NONCE_SEED,
        participant_pubkey,
        aggregate_pubkey,
    );
    psbt_in
        .proprietary
        .get(&key)
        .map(|bytes| {
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| SignerError::InsanePsbt)
        })
        .transpose()
}

fn read_musig2_aggnonce(
    psbt_in: &PsbtIn,
    participant_pubkey: secp256k1::PublicKey,
    aggregate_pubkey: secp256k1::PublicKey,
) -> Result<Option<AggNonce>, SignerError> {
    let key = musig2_input_proprietary_key(
        PSBT_IN_LIANA_MUSIG2_AGGNONCE,
        participant_pubkey,
        aggregate_pubkey,
    );
    psbt_in
        .proprietary
        .get(&key)
        .map(|bytes| AggNonce::from_bytes(bytes.as_slice()).map_err(|_| SignerError::InsanePsbt))
        .transpose()
}

impl HotSigner {
    fn from_mnemonic(
        network: bitcoin::Network,
        mnemonic: bip39::Mnemonic,
    ) -> Result<Self, SignerError> {
        let master_xpriv =
            bip32::Xpriv::new_master(network, &mnemonic.to_seed("")).map_err(SignerError::Bip32)?;
        Ok(Self {
            mnemonic,
            master_xpriv,
        })
    }

    /// Create a new hot signer from random bytes. Uses a 12-words mnemonics without a passphrase.
    pub fn generate(network: bitcoin::Network) -> Result<Self, SignerError> {
        // We want a 12-words mnemonic so we only use 16 of the 32 bytes.
        let random_32bytes = random::random_bytes().map_err(SignerError::Randomness)?;
        let mnemonic =
            bip39::Mnemonic::from_entropy(&random_32bytes[..16]).map_err(SignerError::Mnemonic)?;
        Self::from_mnemonic(network, mnemonic)
    }

    pub fn from_str(network: bitcoin::Network, s: &str) -> Result<Self, SignerError> {
        let mnemonic = bip39::Mnemonic::from_str(s).map_err(SignerError::Mnemonic)?;
        Self::from_mnemonic(network, mnemonic)
    }

    fn mnemonics_folder(datadir_root: &path::Path, network: bitcoin::Network) -> path::PathBuf {
        [
            datadir_root,
            path::Path::new(&network.to_string()),
            path::Path::new(MNEMONICS_FOLDER_NAME),
        ]
        .iter()
        .collect()
    }

    /// Read all the mnemonics from the datadir for the given network.
    pub fn from_datadir(
        datadir_root: &path::Path,
        network: bitcoin::Network,
    ) -> Result<Vec<Self>, SignerError> {
        let mut signers = Vec::new();

        let mnemonic_paths = fs::read_dir(Self::mnemonics_folder(datadir_root, network))
            .map_err(SignerError::MnemonicStorage)?;
        for entry in mnemonic_paths {
            let mnemonic = fs::read_to_string(entry.map_err(SignerError::MnemonicStorage)?.path())
                .map_err(SignerError::MnemonicStorage)?;
            signers.push(Self::from_str(network, &mnemonic)?);
        }

        Ok(signers)
    }

    /// The BIP39 mnemonics from which the master key of this signer is derived.
    pub fn words(&self) -> [&'static str; 12] {
        let words: Vec<&'static str> = self.mnemonic.words().collect();
        words.try_into().expect("Always 12 words")
    }

    /// The BIP39 mnemonic words as a string.
    pub fn mnemonic_str(&self) -> String {
        let mut mnemonic_str = String::with_capacity(12 * 7);
        let words = self.words();

        for (i, word) in words.iter().enumerate() {
            mnemonic_str += word;
            if i < words.len() - 1 {
                mnemonic_str += " ";
            }
        }

        mnemonic_str
    }

    /// Get the fingerprint of the master xpub for this signer.
    pub fn fingerprint(
        &self,
        secp: &secp256k1::Secp256k1<impl secp256k1::Signing>,
    ) -> bip32::Fingerprint {
        self.master_xpriv.fingerprint(secp)
    }

    /// Store the mnemonic in a file within the given "data directory".
    /// The file is stored within a "mnemonics" folder, with the filename set to the fingerprint of
    /// the master xpub corresponding to this mnemonic.
    /// returns the filename
    pub fn store(
        &self,
        datadir_root: &path::Path,
        network: bitcoin::Network,
        secp: &secp256k1::Secp256k1<impl secp256k1::Signing>,
        descriptor_info: Option<(String, i64)>,
    ) -> Result<(), SignerError> {
        let mnemonics_folder = Self::mnemonics_folder(datadir_root, network);
        if !mnemonics_folder.exists() {
            create_dir(&mnemonics_folder).map_err(SignerError::MnemonicStorage)?;
        }

        // This will fail if a file with this fingerprint exists already.
        let filename = MnemonicFileName {
            fingerprint: self.fingerprint(secp),
            descriptor_info,
        };
        let mut mnemonic_file = create_file(&mnemonics_folder.join(filename.to_string()))
            .map_err(SignerError::MnemonicStorage)?;
        mnemonic_file
            .write_all(self.mnemonic_str().as_bytes())
            .map_err(SignerError::MnemonicStorage)?;

        Ok(())
    }

    fn xpriv_at(
        &self,
        der_path: &bip32::DerivationPath,
        secp: &secp256k1::Secp256k1<impl secp256k1::Signing>,
    ) -> bip32::Xpriv {
        self.master_xpriv
            .derive_priv(secp, der_path)
            .expect("Never fails")
    }

    /// Get the extended public key at the given derivation path.
    pub fn xpub_at(
        &self,
        der_path: &bip32::DerivationPath,
        secp: &secp256k1::Secp256k1<impl secp256k1::Signing>,
    ) -> bip32::Xpub {
        let xpriv = self.xpriv_at(der_path, secp);
        bip32::Xpub::from_priv(secp, &xpriv)
    }

    // Provide an ECDSA signature for this transaction input from the PSBT input information.
    fn sign_p2wsh(
        &self,
        secp: &secp256k1::Secp256k1<impl secp256k1::Signing>,
        sighash_cache: &mut sighash::SighashCache<&bitcoin::Transaction>,
        master_fingerprint: bip32::Fingerprint,
        psbt_in: &mut PsbtIn,
        input_index: usize,
    ) -> Result<(), SignerError> {
        // First of all compute the sighash for this input. We assume P2WSH spend: the sighash
        // script code is always the witness script.
        let witscript = psbt_in
            .witness_script
            .as_ref()
            .ok_or(SignerError::IncompletePsbt)?;
        let value = psbt_in
            .witness_utxo
            .as_ref()
            .ok_or(SignerError::IncompletePsbt)?
            .value;
        let sighash_type = sighash::EcdsaSighashType::All;
        let sighash = sighash_cache
            .p2wsh_signature_hash(input_index, witscript, value, sighash_type)
            .map_err(|_| SignerError::InsanePsbt)?;
        let sighash = secp256k1::Message::from_digest_slice(sighash.as_byte_array())
            .expect("Sighash is always 32 bytes.");

        // Then provide a signature for all the keys they asked for.
        for (curr_pubkey, (fingerprint, der_path)) in psbt_in.bip32_derivation.iter() {
            if *fingerprint != master_fingerprint {
                continue;
            }
            let privkey = self.xpriv_at(der_path, secp).to_priv();
            let pubkey = privkey.public_key(secp);
            if pubkey.inner != *curr_pubkey {
                return Err(SignerError::InsanePsbt);
            }
            let signature = secp.sign_ecdsa_low_r(&sighash, &privkey.inner);
            psbt_in.partial_sigs.insert(
                pubkey,
                ecdsa::Signature {
                    signature,
                    sighash_type,
                },
            );
        }

        Ok(())
    }

    // Provide a BIP340 signature for this transaction input from the PSBT input information.
    fn sign_taproot(
        &self,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        sighash_cache: &mut sighash::SighashCache<&bitcoin::Transaction>,
        master_fingerprint: bip32::Fingerprint,
        prevouts: &[bitcoin::TxOut],
        psbt_in: &mut PsbtIn,
        input_index: usize,
    ) -> Result<(), SignerError> {
        let sighash_type = sighash::TapSighashType::Default;
        let prevouts_slice = prevouts;
        let prevouts = sighash::Prevouts::All(prevouts_slice);

        let is_musig2_input = self.sign_musig2_taproot(
            secp,
            sighash_cache,
            master_fingerprint,
            prevouts_slice,
            psbt_in,
            input_index,
            sighash_type,
        )?;

        if !is_musig2_input {
            // If the details of the internal key are filled, provide a keypath signature.
            if let Some(ref int_key) = psbt_in.tap_internal_key {
                // NB: we don't check for empty leaf hashes on purpose, in case the internal key also
                // appears in a leaf.
                if let Some((_, (fg, der_path))) = psbt_in.tap_key_origins.get(int_key) {
                    if *fg == master_fingerprint {
                        let privkey = self.xpriv_at(der_path, secp).to_priv();
                        let keypair = secp256k1::Keypair::from_secret_key(secp, &privkey.inner);
                        if keypair.x_only_public_key().0 != *int_key {
                            return Err(SignerError::InsanePsbt);
                        }
                        let keypair = secp256k1::Keypair::from(
                            keypair.tap_tweak(secp, psbt_in.tap_merkle_root),
                        );
                        let sighash = sighash_cache
                            .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
                            .map_err(|_| SignerError::InsanePsbt)?;
                        let sighash =
                            secp256k1::Message::from_digest_slice(sighash.as_byte_array())
                                .expect("Sighash is always 32 bytes.");
                        let signature = secp.sign_schnorr_no_aux_rand(&sighash, &keypair);
                        let sig = bitcoin::taproot::Signature {
                            signature,
                            sighash_type,
                        };
                        psbt_in.tap_key_sig = Some(sig);
                    }
                }
            }
        }

        // Now sign for all the public keys derived from our master secret, in all the leaves where
        // they are present.
        for (pubkey, (leaf_hashes, (fg, der_path))) in &psbt_in.tap_key_origins {
            if *fg != master_fingerprint {
                continue;
            }

            for leaf_hash in leaf_hashes {
                let privkey = self.xpriv_at(der_path, secp).to_priv();
                let keypair = secp256k1::Keypair::from_secret_key(secp, &privkey.inner);
                let sighash = sighash_cache
                    .taproot_script_spend_signature_hash(
                        input_index,
                        &prevouts,
                        *leaf_hash,
                        sighash_type,
                    )
                    .map_err(|_| SignerError::InsanePsbt)?;
                let sighash = secp256k1::Message::from_digest_slice(sighash.as_byte_array())
                    .expect("Sighash is always 32 bytes.");
                let signature = secp.sign_schnorr_no_aux_rand(&sighash, &keypair);
                let sig = bitcoin::taproot::Signature {
                    signature,
                    sighash_type,
                };
                psbt_in.tap_script_sigs.insert((*pubkey, *leaf_hash), sig);
            }
        }

        Ok(())
    }

    fn sign_musig2_taproot(
        &self,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        sighash_cache: &mut sighash::SighashCache<&bitcoin::Transaction>,
        master_fingerprint: bip32::Fingerprint,
        prevouts: &[bitcoin::TxOut],
        psbt_in: &mut PsbtIn,
        input_index: usize,
        sighash_type: sighash::TapSighashType,
    ) -> Result<bool, SignerError> {
        let participant_sets = parse_musig2_participant_sets(psbt_in)?;
        if participant_sets.is_empty() {
            return Ok(false);
        }
        if participant_sets.len() != 1 {
            return Err(SignerError::InsanePsbt);
        }

        let session =
            self.reconstruct_musig2_session(secp, psbt_in, participant_sets[0].clone())?;
        let owned_participants =
            self.owned_musig2_participants(secp, psbt_in, &session, master_fingerprint)?;

        let participant_pubkeys = session.participant_pubkeys.clone();
        let expected_participant_count = participant_pubkeys.len();
        let aggregate_pubkey = session.participant_set.aggregate_pubkey;
        let participant_index = participant_pubkeys
            .iter()
            .cloned()
            .map(|pubkey| (pubkey, ()))
            .collect::<BTreeMap<_, _>>();

        let mut pubnonces = parse_musig2_pubnonces(psbt_in, aggregate_pubkey)?
            .into_iter()
            .map(|(participant_pubkey, pubnonce)| {
                if !participant_index.contains_key(&participant_pubkey) {
                    Err(SignerError::InsanePsbt)
                } else {
                    Ok((participant_pubkey, pubnonce))
                }
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let mut partial_signatures = parse_musig2_partial_signatures(psbt_in, aggregate_pubkey)?
            .into_iter()
            .map(|(participant_pubkey, partial_signature)| {
                if !participant_index.contains_key(&participant_pubkey) {
                    Err(SignerError::InsanePsbt)
                } else {
                    Ok((participant_pubkey, partial_signature))
                }
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        if !partial_signatures.is_empty() && pubnonces.len() != expected_participant_count {
            return Err(SignerError::InsanePsbt);
        }

        let prevouts = sighash::Prevouts::All(prevouts);
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
            .map_err(|_| SignerError::InsanePsbt)?;
        let sighash_bytes = sighash.to_byte_array();
        let signing_pubkey = session
            .key_agg_ctx
            .aggregated_pubkey::<musig_secp256k1::PublicKey>();

        for owned_participant in &owned_participants {
            if pubnonces.contains_key(&owned_participant.participant_pubkey) {
                continue;
            }

            let nonce_seed = if let Some(nonce_seed) = read_musig2_nonce_seed(
                psbt_in,
                owned_participant.participant_pubkey,
                aggregate_pubkey,
            )? {
                nonce_seed
            } else {
                let nonce_seed = random::random_bytes().map_err(SignerError::Randomness)?;
                psbt_in.proprietary.insert(
                    musig2_input_proprietary_key(
                        PSBT_IN_LIANA_MUSIG2_NONCE_SEED,
                        owned_participant.participant_pubkey,
                        aggregate_pubkey,
                    ),
                    nonce_seed.to_vec(),
                );
                nonce_seed
            };

            let seckey = self.musig2_participant_secret_key(
                secp,
                owned_participant.participant_pubkey,
                &owned_participant.derivation_path,
            )?;
            let musig_seckey = bitcoin_to_musig_secret_key(seckey)?;
            let secnonce = SecNonce::generate(
                nonce_seed,
                musig_seckey,
                signing_pubkey.clone(),
                sighash_bytes,
                [],
            );
            let pubnonce = secnonce.public_nonce();
            psbt_in.unknown.insert(
                musig2_composite_key(
                    PSBT_IN_MUSIG2_PUB_NONCE,
                    owned_participant.participant_pubkey,
                    aggregate_pubkey,
                ),
                pubnonce.to_bytes().to_vec(),
            );
            pubnonces.insert(owned_participant.participant_pubkey, pubnonce);
        }

        if pubnonces.len() != expected_participant_count {
            return Ok(true);
        }

        let aggregated_nonce =
            AggNonce::sum(participant_pubkeys.iter().map(|pubkey| &pubnonces[pubkey]));

        for owned_participant in &owned_participants {
            if partial_signatures.contains_key(&owned_participant.participant_pubkey) {
                continue;
            }

            let nonce_seed = read_musig2_nonce_seed(
                psbt_in,
                owned_participant.participant_pubkey,
                aggregate_pubkey,
            )?
            .ok_or(SignerError::IncompletePsbt)?;

            if let Some(stored_nonce) = read_musig2_aggnonce(
                psbt_in,
                owned_participant.participant_pubkey,
                aggregate_pubkey,
            )? {
                if stored_nonce != aggregated_nonce {
                    return Err(SignerError::InsanePsbt);
                }
            } else {
                psbt_in.proprietary.insert(
                    musig2_input_proprietary_key(
                        PSBT_IN_LIANA_MUSIG2_AGGNONCE,
                        owned_participant.participant_pubkey,
                        aggregate_pubkey,
                    ),
                    aggregated_nonce.to_bytes().to_vec(),
                );
            }

            let seckey = self.musig2_participant_secret_key(
                secp,
                owned_participant.participant_pubkey,
                &owned_participant.derivation_path,
            )?;
            let musig_seckey = bitcoin_to_musig_secret_key(seckey)?;
            let secnonce = SecNonce::generate(
                nonce_seed,
                musig_seckey.clone(),
                signing_pubkey.clone(),
                sighash_bytes,
                [],
            );
            let partial_signature: PartialSignature = musig2::sign_partial(
                &session.key_agg_ctx,
                musig_seckey,
                secnonce,
                &aggregated_nonce,
                sighash_bytes,
            )
            .map_err(|_| SignerError::InsanePsbt)?;
            psbt_in.unknown.insert(
                musig2_composite_key(
                    PSBT_IN_MUSIG2_PARTIAL_SIG,
                    owned_participant.participant_pubkey,
                    aggregate_pubkey,
                ),
                partial_signature.serialize().to_vec(),
            );
            partial_signatures.insert(owned_participant.participant_pubkey, partial_signature);
        }

        for participant_pubkey in &participant_pubkeys {
            if let Some(partial_signature) = partial_signatures.get(participant_pubkey) {
                musig2::verify_partial(
                    &session.key_agg_ctx,
                    partial_signature.clone(),
                    &aggregated_nonce,
                    bitcoin_to_musig_pubkey(participant_pubkey.clone())?,
                    &pubnonces[participant_pubkey],
                    sighash_bytes,
                )
                .map_err(|_| SignerError::InsanePsbt)?;
            }
        }

        if partial_signatures.len() == expected_participant_count && psbt_in.tap_key_sig.is_none() {
            let signature = musig2::aggregate_partial_signatures::<_, CompactSignature>(
                &session.key_agg_ctx,
                &aggregated_nonce,
                participant_pubkeys.iter().map(|participant_pubkey| {
                    partial_signatures
                        .get(participant_pubkey)
                        .cloned()
                        .expect("present after count check")
                }),
                sighash_bytes,
            )
            .map_err(|_| SignerError::InsanePsbt)?;
            psbt_in.tap_key_sig = Some(bitcoin::taproot::Signature {
                signature: secp256k1::schnorr::Signature::from_slice(&signature.to_bytes())
                    .map_err(|_| SignerError::InsanePsbt)?,
                sighash_type,
            });
        }

        Ok(true)
    }

    fn reconstruct_musig2_session(
        &self,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        psbt_in: &PsbtIn,
        participant_set: Musig2ParticipantSet,
    ) -> Result<Musig2InputSession, SignerError> {
        let tap_internal_key = psbt_in
            .tap_internal_key
            .ok_or(SignerError::IncompletePsbt)?;
        let mut participant_pubkeys = participant_set.participant_pubkeys.clone();
        participant_pubkeys.sort();

        let musig_participant_pubkeys = participant_pubkeys
            .iter()
            .cloned()
            .map(bitcoin_to_musig_pubkey)
            .collect::<Result<Vec<_>, _>>()?;
        let mut key_agg_ctx =
            KeyAggContext::new(musig_participant_pubkeys).map_err(|_| SignerError::InsanePsbt)?;
        let mut internal_pubkey = musig_to_bitcoin_pubkey(
            key_agg_ctx.aggregated_pubkey_untweaked::<musig_secp256k1::PublicKey>(),
        )?;
        if internal_pubkey != participant_set.aggregate_pubkey {
            return Err(SignerError::InsanePsbt);
        }

        if let Some((_, (_, derivation_path))) = psbt_in.tap_key_origins.get(&tap_internal_key) {
            // The network prefix does not affect the BIP328 synthetic xpub fingerprint or child
            // tweak computation, so any consistent xpub version is fine here.
            let mut synthetic_xpub = crate::descriptors::bip328_synthetic_xpub(
                participant_set.aggregate_pubkey,
                bitcoin::Network::Bitcoin,
            );
            let synthetic_fingerprint = synthetic_xpub.fingerprint();
            let internal_key_fingerprint = psbt_in
                .tap_key_origins
                .get(&tap_internal_key)
                .ok_or(SignerError::InsanePsbt)?
                .1
                 .0;
            if synthetic_fingerprint == internal_key_fingerprint {
                for child in derivation_path {
                    let (tweak, chain_code) = synthetic_xpub
                        .ckd_pub_tweak(*child)
                        .map_err(|_| SignerError::InsanePsbt)?;
                    let tweak_scalar: secp256k1::Scalar = tweak.clone().into();
                    key_agg_ctx = key_agg_ctx
                        .with_tweak(bitcoin_to_musig_secret_key(tweak)?, false)
                        .map_err(|_| SignerError::InsanePsbt)?;
                    let public_key = synthetic_xpub
                        .public_key
                        .add_exp_tweak(secp, &tweak_scalar)
                        .map_err(|_| SignerError::InsanePsbt)?;
                    synthetic_xpub = bip32::Xpub {
                        network: synthetic_xpub.network,
                        depth: synthetic_xpub.depth + 1,
                        parent_fingerprint: synthetic_xpub.fingerprint(),
                        child_number: *child,
                        chain_code,
                        public_key,
                    };
                }
                internal_pubkey = synthetic_xpub.public_key;
            }
        }

        if internal_pubkey.x_only_public_key().0 != tap_internal_key {
            return Err(SignerError::InsanePsbt);
        }

        key_agg_ctx = if let Some(tap_merkle_root) = psbt_in.tap_merkle_root {
            key_agg_ctx
                .with_taproot_tweak(tap_merkle_root.as_byte_array())
                .map_err(|_| SignerError::InsanePsbt)?
        } else {
            key_agg_ctx
                .with_unspendable_taproot_tweak()
                .map_err(|_| SignerError::InsanePsbt)?
        };

        Ok(Musig2InputSession {
            participant_set,
            participant_pubkeys,
            key_agg_ctx,
        })
    }

    fn owned_musig2_participants(
        &self,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        psbt_in: &PsbtIn,
        session: &Musig2InputSession,
        master_fingerprint: bip32::Fingerprint,
    ) -> Result<Vec<OwnedMusig2Participant>, SignerError> {
        session
            .participant_pubkeys
            .iter()
            .filter_map(|participant_pubkey| {
                psbt_in
                    .tap_key_origins
                    .get(&participant_pubkey.x_only_public_key().0)
                    .and_then(|(_, (fg, derivation_path))| {
                        (*fg == master_fingerprint).then(|| OwnedMusig2Participant {
                            participant_pubkey: *participant_pubkey,
                            derivation_path: derivation_path.clone(),
                        })
                    })
            })
            .map(|owned_participant| {
                self.musig2_participant_secret_key(
                    secp,
                    owned_participant.participant_pubkey,
                    &owned_participant.derivation_path,
                )?;
                Ok(owned_participant)
            })
            .collect()
    }

    fn musig2_participant_secret_key(
        &self,
        secp: &secp256k1::Secp256k1<impl secp256k1::Signing>,
        participant_pubkey: secp256k1::PublicKey,
        derivation_path: &bip32::DerivationPath,
    ) -> Result<secp256k1::SecretKey, SignerError> {
        let privkey = self.xpriv_at(derivation_path, secp).to_priv();
        let pubkey = privkey.public_key(secp);
        if pubkey.inner != participant_pubkey {
            return Err(SignerError::InsanePsbt);
        }
        Ok(privkey.inner)
    }

    /// Sign all inputs of the given PSBT.
    ///
    /// **This does not perform any check. It will blindly sign anything that's passed.**
    pub fn sign_psbt(
        &self,
        mut psbt: Psbt,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
    ) -> Result<Psbt, SignerError> {
        let master_fingerprint = self.fingerprint(secp);
        let mut sighash_cache = sighash::SighashCache::new(&psbt.unsigned_tx);

        let prevouts: Vec<_> = psbt
            .inputs
            .iter()
            .filter_map(|psbt_in| psbt_in.witness_utxo.clone())
            .collect();
        if prevouts.len() != psbt.inputs.len() {
            return Err(SignerError::IncompletePsbt);
        }

        // Sign each input in the PSBT.
        for i in 0..psbt.inputs.len() {
            if psbt.inputs[i].witness_script.is_some() {
                self.sign_p2wsh(
                    secp,
                    &mut sighash_cache,
                    master_fingerprint,
                    &mut psbt.inputs[i],
                    i,
                )?;
            } else {
                self.sign_taproot(
                    secp,
                    &mut sighash_cache,
                    master_fingerprint,
                    &prevouts,
                    &mut psbt.inputs[i],
                    i,
                )?;
            }
        }

        Ok(psbt)
    }

    /// Change the network of generated extended keys. Note this value only has to do with the
    /// BIP32 encoding of those keys (xpubs, tpubs, ..) but does not affect any data (whether it is
    /// the keys or the mnemonics).
    pub fn set_network(&mut self, network: bitcoin::Network) {
        self.master_xpriv.network = network.into();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MnemonicFileName {
    pub fingerprint: Fingerprint,
    pub descriptor_info: Option<(String, i64)>, // (descriptor_checksum, timestamp)
}

impl fmt::Display for MnemonicFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.descriptor_info {
            Some((checksum, timestamp)) => {
                write!(
                    f,
                    "mnemonic-{}-{}-{}.txt",
                    self.fingerprint, checksum, timestamp
                )
            }
            None => {
                write!(f, "mnemonic-{}.txt", self.fingerprint)
            }
        }
    }
}

#[derive(Debug)]
pub enum MnemonicFileNameError {
    InvalidFormat,
    InvalidFingerprint,
    InvalidTimestamp,
}

impl fmt::Display for MnemonicFileNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MnemonicFileNameError::InvalidFormat => write!(f, "Invalid mnemonic file name format"),
            MnemonicFileNameError::InvalidFingerprint => write!(f, "Invalid fingerprint format"),
            MnemonicFileNameError::InvalidTimestamp => write!(f, "Invalid timestamp format"),
        }
    }
}

impl std::error::Error for MnemonicFileNameError {}

// Implementation of FromStr for MnemonicFileName
impl FromStr for MnemonicFileName {
    type Err = MnemonicFileNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Check if the string starts with "mnemonic-" and ends with ".txt"
        if !s.starts_with("mnemonic-") || !s.ends_with(".txt") {
            return Err(MnemonicFileNameError::InvalidFormat);
        }

        let content = s
            .strip_prefix("mnemonic-")
            .expect("Already checked")
            .strip_suffix(".txt")
            .expect("Already checked");

        let parts: Vec<&str> = content.split('-').collect();
        match parts.len() {
            1 => {
                // Only fingerprint
                let fingerprint = Fingerprint::from_str(parts[0])
                    .map_err(|_| MnemonicFileNameError::InvalidFingerprint)?;

                Ok(MnemonicFileName {
                    fingerprint,
                    descriptor_info: None,
                })
            }
            3 => {
                // Fingerprint + checksum + timestamp
                let fingerprint = Fingerprint::from_str(parts[0])
                    .map_err(|_| MnemonicFileNameError::InvalidFingerprint)?;

                let timestamp = parts[2]
                    .parse::<i64>()
                    .map_err(|_| MnemonicFileNameError::InvalidTimestamp)?;

                Ok(MnemonicFileName {
                    fingerprint,
                    descriptor_info: Some((parts[1].to_string(), timestamp)),
                })
            }
            _ => Err(MnemonicFileNameError::InvalidFormat),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptors;
    use miniscript::{
        bitcoin::{locktime::absolute, psbt::Input as PsbtIn, Amount},
        descriptor::{
            DerivPaths, DescriptorMultiXKey, DescriptorPublicKey, DescriptorXKey, Wildcard,
        },
    };
    use std::collections::{BTreeMap, HashSet};

    static mut COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    fn uid() -> usize {
        #[allow(static_mut_refs)]
        unsafe {
            let uid = COUNTER.load(std::sync::atomic::Ordering::Relaxed);
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            uid
        }
    }
    fn tmp_dir() -> path::PathBuf {
        std::env::temp_dir().join(format!(
            "lianad-{}-{:?}-{}",
            std::process::id(),
            std::thread::current().id(),
            uid(),
        ))
    }

    fn multi_xpub_key(
        signer: &HotSigner,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        origin: &str,
        branch_a: &str,
        branch_b: &str,
    ) -> DescriptorPublicKey {
        let origin_der = bip32::DerivationPath::from_str(origin).unwrap();
        let xkey = signer.xpub_at(&origin_der, secp);
        DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some((signer.fingerprint(secp), origin_der)),
            xkey,
            derivation_paths: DerivPaths::new(vec![
                bip32::DerivationPath::from_str(branch_a).unwrap(),
                bip32::DerivationPath::from_str(branch_b).unwrap(),
            ])
            .unwrap(),
            wildcard: Wildcard::Unhardened,
        })
    }

    fn plain_xpub_key(
        signer: &HotSigner,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        origin: &str,
    ) -> DescriptorPublicKey {
        let origin_der = bip32::DerivationPath::from_str(origin).unwrap();
        let xkey = signer.xpub_at(&origin_der, secp);
        DescriptorPublicKey::XPub(DescriptorXKey {
            origin: Some((signer.fingerprint(secp), origin_der)),
            xkey,
            derivation_path: bip32::DerivationPath::default(),
            wildcard: Wildcard::None,
        })
    }

    fn musig2_test_descriptor(
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        primary_signer_a: &HotSigner,
        primary_signer_b: &HotSigner,
        recovery_signer: &HotSigner,
        derivation_mode: descriptors::MuSig2DerivationMode,
    ) -> descriptors::LianaDescriptor {
        let primary_key_a = match derivation_mode {
            descriptors::MuSig2DerivationMode::DeriveThenAggregate => {
                multi_xpub_key(primary_signer_a, secp, "m/48'/1'/0'/2'", "m/0", "m/1")
            }
            descriptors::MuSig2DerivationMode::AggregateThenDeriveBip328 => {
                plain_xpub_key(primary_signer_a, secp, "m/48'/1'/0'/2'")
            }
        };
        let primary_key_b = match derivation_mode {
            descriptors::MuSig2DerivationMode::DeriveThenAggregate => {
                multi_xpub_key(primary_signer_b, secp, "m/48'/1'/1'/2'", "m/0", "m/1")
            }
            descriptors::MuSig2DerivationMode::AggregateThenDeriveBip328 => {
                plain_xpub_key(primary_signer_b, secp, "m/48'/1'/1'/2'")
            }
        };
        let recovery_key = multi_xpub_key(recovery_signer, secp, "m/84'/1'/0'/0'", "m/2", "m/3");

        let musig_expr = match derivation_mode {
            descriptors::MuSig2DerivationMode::DeriveThenAggregate => {
                format!("musig({primary_key_a},{primary_key_b})")
            }
            descriptors::MuSig2DerivationMode::AggregateThenDeriveBip328 => {
                format!("musig({primary_key_a},{primary_key_b})/<0;1>/*")
            }
        };
        let musig_expr = descriptors::MuSig2KeyExpr::from_str(&musig_expr).unwrap();
        let policy = descriptors::LianaPolicy::new_with_primary_info(
            descriptors::PrimaryPathInfo::MuSig2(musig_expr),
            [(10, descriptors::PathInfo::Single(recovery_key))]
                .iter()
                .cloned()
                .collect(),
        )
        .unwrap();
        descriptors::LianaDescriptor::new(policy)
    }

    fn musig2_test_psbt(
        descriptor: &descriptors::LianaDescriptor,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
    ) -> Psbt {
        let spent_coin_desc = descriptor.receive_descriptor().derive(42.into(), secp);
        let mut psbt_in = PsbtIn::default();
        spent_coin_desc.update_psbt_in(&mut psbt_in);
        psbt_in.witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(19_000),
            script_pubkey: spent_coin_desc.script_pubkey(),
        });
        Psbt {
            unsigned_tx: bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: absolute::LockTime::Blocks(absolute::Height::ZERO),
                input: vec![bitcoin::TxIn {
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    previous_output: bitcoin::OutPoint::from_str(
                        "4613e078e4cdbb0fce1bc6e44b028f0e11621a134a1605efdc456c32d155c922:19",
                    )
                    .unwrap(),
                    ..bitcoin::TxIn::default()
                }],
                output: vec![bitcoin::TxOut {
                    value: Amount::from_sat(18_420),
                    script_pubkey: bitcoin::Address::from_str(
                        "bc1qvklensptw5lk7d470ds60pcpsr0psdpgyvwepv",
                    )
                    .unwrap()
                    .assume_checked()
                    .script_pubkey(),
                }],
            },
            version: 0,
            xpub: BTreeMap::new(),
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),
            inputs: vec![psbt_in],
            outputs: Vec::new(),
        }
    }

    fn count_unknown_entries(psbt_in: &PsbtIn, type_value: u8) -> usize {
        psbt_in
            .unknown
            .keys()
            .filter(|key| key.type_value == type_value)
            .count()
    }

    fn assert_hot_signer_signs_musig2(derivation_mode: descriptors::MuSig2DerivationMode) {
        let secp = secp256k1::Secp256k1::new();
        let network = bitcoin::Network::Bitcoin;
        let primary_signer_a = HotSigner::generate(network).unwrap();
        let primary_signer_b = HotSigner::generate(network).unwrap();
        let recovery_signer = HotSigner::generate(network).unwrap();
        let descriptor = musig2_test_descriptor(
            &secp,
            &primary_signer_a,
            &primary_signer_b,
            &recovery_signer,
            derivation_mode,
        );

        let psbt = musig2_test_psbt(&descriptor, &secp);
        assert_eq!(
            count_unknown_entries(&psbt.inputs[0], PSBT_IN_MUSIG2_PUB_NONCE),
            0
        );
        assert_eq!(
            count_unknown_entries(&psbt.inputs[0], PSBT_IN_MUSIG2_PARTIAL_SIG),
            0
        );
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        let psbt = primary_signer_a.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(
            count_unknown_entries(&psbt.inputs[0], PSBT_IN_MUSIG2_PUB_NONCE),
            1
        );
        assert_eq!(
            count_unknown_entries(&psbt.inputs[0], PSBT_IN_MUSIG2_PARTIAL_SIG),
            0
        );
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        let psbt = primary_signer_b.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(
            count_unknown_entries(&psbt.inputs[0], PSBT_IN_MUSIG2_PUB_NONCE),
            2
        );
        assert_eq!(
            count_unknown_entries(&psbt.inputs[0], PSBT_IN_MUSIG2_PARTIAL_SIG),
            1
        );
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        let psbt = primary_signer_a.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(
            count_unknown_entries(&psbt.inputs[0], PSBT_IN_MUSIG2_PUB_NONCE),
            2
        );
        assert_eq!(
            count_unknown_entries(&psbt.inputs[0], PSBT_IN_MUSIG2_PARTIAL_SIG),
            2
        );
        assert!(psbt.inputs[0].tap_key_sig.is_some());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        let psbt = recovery_signer.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt.inputs[0].tap_key_sig.is_some());
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
    }

    #[test]
    fn hot_signer_gen() {
        // Entropy isn't completely broken.
        assert_ne!(
            HotSigner::generate(bitcoin::Network::Bitcoin)
                .unwrap()
                .words(),
            HotSigner::generate(bitcoin::Network::Bitcoin)
                .unwrap()
                .words()
        );

        // Roundtrips.
        let signer = HotSigner::generate(bitcoin::Network::Bitcoin).unwrap();
        let mnemonics_str = signer.mnemonic_str();
        assert_eq!(
            HotSigner::from_str(bitcoin::Network::Bitcoin, &mnemonics_str)
                .unwrap()
                .words(),
            signer.words()
        );

        // We can get an xpub for it.
        let secp = secp256k1::Secp256k1::signing_only();
        let _ = signer.xpub_at(
            &bip32::DerivationPath::from_str("m/42'/43/0987'/0/2").unwrap(),
            &secp,
        );
    }

    #[test]
    fn hot_signer_storage() {
        let secp = secp256k1::Secp256k1::signing_only();
        let tmp_dir = tmp_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let network = bitcoin::Network::Bitcoin;

        let words_set: HashSet<_> = (0..10)
            .map(|_| {
                let signer = HotSigner::generate(network).unwrap();
                signer.store(&tmp_dir, network, &secp, None).unwrap();
                signer.words()
            })
            .collect();
        let words_read: HashSet<_> = HotSigner::from_datadir(&tmp_dir, network)
            .unwrap()
            .into_iter()
            .map(|signer| signer.words())
            .collect();
        assert_eq!(words_set, words_read);

        fs::remove_dir_all(tmp_dir).unwrap();
    }

    #[test]
    fn hot_signer_sign_p2wsh() {
        let secp = secp256k1::Secp256k1::new();
        let network = bitcoin::Network::Bitcoin;

        // Create a Liana descriptor with as primary path a 2-of-3 with three hot signers and a
        // single hot signer as recovery path. (The recovery path signer is also used in the
        // primary path.) Use various random derivation paths.
        let (prim_signer_a, prim_signer_b, recov_signer) = (
            HotSigner::generate(network).unwrap(),
            HotSigner::generate(network).unwrap(),
            HotSigner::generate(network).unwrap(),
        );
        let origin_der = bip32::DerivationPath::from_str("m/0'/12'/42").unwrap();
        let xkey = prim_signer_a.xpub_at(&origin_der, &secp);
        let prim_key_a = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some((prim_signer_a.fingerprint(&secp), origin_der)),
            xkey,
            derivation_paths: DerivPaths::new(vec![
                bip32::DerivationPath::from_str("m/420/56/0").unwrap(),
                bip32::DerivationPath::from_str("m/420/56/1").unwrap(),
            ])
            .unwrap(),
            wildcard: Wildcard::Unhardened,
        });
        let origin_der = bip32::DerivationPath::from_str("m/18'/24'").unwrap();
        let xkey = prim_signer_b.xpub_at(&origin_der, &secp);
        let prim_key_b = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some((prim_signer_b.fingerprint(&secp), origin_der)),
            xkey,
            derivation_paths: DerivPaths::new(vec![
                bip32::DerivationPath::from_str("m/31/0").unwrap(),
                bip32::DerivationPath::from_str("m/31/1").unwrap(),
            ])
            .unwrap(),
            wildcard: Wildcard::Unhardened,
        });
        let origin_der = bip32::DerivationPath::from_str("m/18'/25'").unwrap();
        let xkey = recov_signer.xpub_at(&origin_der, &secp);
        let prim_key_c = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some((recov_signer.fingerprint(&secp), origin_der)),
            xkey,
            derivation_paths: DerivPaths::new(vec![
                bip32::DerivationPath::from_str("m/0").unwrap(),
                bip32::DerivationPath::from_str("m/1").unwrap(),
            ])
            .unwrap(),
            wildcard: Wildcard::Unhardened,
        });
        let prim_keys = descriptors::PathInfo::Multi(2, vec![prim_key_a, prim_key_b, prim_key_c]);
        let origin_der = bip32::DerivationPath::from_str("m/1/2'/3/4'").unwrap();
        let xkey = recov_signer.xpub_at(&origin_der, &secp);
        let recov_key = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some((recov_signer.fingerprint(&secp), origin_der)),
            xkey,
            derivation_paths: DerivPaths::new(vec![
                bip32::DerivationPath::from_str("m/5/6/0").unwrap(),
                bip32::DerivationPath::from_str("m/5/6/1").unwrap(),
            ])
            .unwrap(),
            wildcard: Wildcard::Unhardened,
        });
        let recov_keys = descriptors::PathInfo::Single(recov_key);
        let policy = descriptors::LianaPolicy::new_legacy(
            prim_keys,
            [(46, recov_keys)].iter().cloned().collect(),
        )
        .unwrap();
        let desc = descriptors::LianaDescriptor::new(policy);

        // Create a dummy PSBT spending a coin from this descriptor with a single input and single
        // (external) output. We'll be modifying it as we go.
        let spent_coin_desc = desc.receive_descriptor().derive(42.into(), &secp);
        let mut psbt_in = PsbtIn::default();
        spent_coin_desc.update_psbt_in(&mut psbt_in);
        psbt_in.witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(19_000),
            script_pubkey: spent_coin_desc.script_pubkey(),
        });
        let mut dummy_psbt = Psbt {
            unsigned_tx: bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: absolute::LockTime::Blocks(absolute::Height::ZERO),
                input: vec![bitcoin::TxIn {
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    previous_output: bitcoin::OutPoint::from_str(
                        "4613e078e4cdbb0fce1bc6e44b028f0e11621a134a1605efdc456c32d155c922:19",
                    )
                    .unwrap(),
                    ..bitcoin::TxIn::default()
                }],
                output: vec![bitcoin::TxOut {
                    value: Amount::from_sat(18_420),
                    script_pubkey: bitcoin::Address::from_str(
                        "bc1qvklensptw5lk7d470ds60pcpsr0psdpgyvwepv",
                    )
                    .unwrap()
                    .assume_checked()
                    .script_pubkey(),
                }],
            },
            version: 0,
            xpub: BTreeMap::new(),
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),
            inputs: vec![psbt_in],
            outputs: Vec::new(),
        };

        // Sign the PSBT with the two primary signers. The recovery signer will sign for the two keys
        // that it manages.
        let psbt = dummy_psbt.clone();
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        let psbt = prim_signer_a.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        let psbt = prim_signer_b.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 2);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        let psbt = recov_signer.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 4);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        // We can add another external output to the transaction, we can still sign without issue.
        // The output can be insane, we don't check it. It doesn't even need an accompanying PSBT
        // output.
        dummy_psbt.unsigned_tx.output.push(bitcoin::TxOut::NULL);
        let psbt = dummy_psbt.clone();
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        let psbt = prim_signer_a.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        let psbt = prim_signer_b.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 2);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        let psbt = recov_signer.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 4);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        // We can add another input to the PSBT. If we don't attach also another transaction input
        // it will fail.
        let other_spent_coin_desc = desc.receive_descriptor().derive(84.into(), &secp);
        let mut psbt_in = PsbtIn::default();
        other_spent_coin_desc.update_psbt_in(&mut psbt_in);
        psbt_in.witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(19_000),
            script_pubkey: other_spent_coin_desc.script_pubkey(),
        });
        dummy_psbt.inputs.push(psbt_in);
        let psbt = dummy_psbt.clone();
        assert!(prim_signer_a
            .sign_psbt(psbt, &secp)
            .unwrap_err()
            .to_string()
            .contains("Information contained in the PSBT is wrong"));

        // But now if we add the inputs also to the transaction itself, it will have signed both
        // inputs.
        dummy_psbt.unsigned_tx.input.push(bitcoin::TxIn {
            // Note the sequence can be different. We don't care.
            sequence: bitcoin::Sequence::ENABLE_LOCKTIME_NO_RBF,
            previous_output: bitcoin::OutPoint::from_str(
                "5613e078e4cdbb0fce1bc6e44b028f0e11621a134a1605efdc456c32d155c922:0",
            )
            .unwrap(),
            ..bitcoin::TxIn::default()
        });
        let psbt = dummy_psbt.clone();
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.partial_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_key_sig.is_none()));
        let psbt = prim_signer_a.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.partial_sigs.len() == 1));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_key_sig.is_none()));
        let psbt = prim_signer_b.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.partial_sigs.len() == 2));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_key_sig.is_none()));
        let psbt = recov_signer.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.partial_sigs.len() == 4));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_key_sig.is_none()));

        // If the witness script is missing for one of the inputs it'll assume it's a Taproot input
        // and provide Taproot signatures. But since we haven't provided any Taproot details it
        // won't fill anything.
        let mut psbt = dummy_psbt.clone();
        psbt.inputs[1].witness_script = None;
        let psbt = prim_signer_a.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt.inputs[1].partial_sigs.is_empty());
        assert!(psbt.inputs[1].tap_key_sig.is_none());
        assert!(psbt.inputs[1].tap_script_sigs.is_empty());

        // If the witness utxo is missing for one of the inputs it'll tell us the PSBT is
        // incomplete.
        let mut psbt = dummy_psbt.clone();
        psbt.inputs[1].witness_utxo = None;
        assert!(prim_signer_a
            .sign_psbt(psbt, &secp)
            .unwrap_err()
            .to_string()
            .contains("The PSBT is missing some information necessary for signing."));

        // If we remove the BIP32 derivations for the first input it will only provide signatures
        // for the second one.
        let mut psbt = dummy_psbt.clone();
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        assert!(psbt.inputs[1].partial_sigs.is_empty());
        psbt.inputs[0].bip32_derivation.clear();
        let psbt = prim_signer_b.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        assert_eq!(psbt.inputs[1].partial_sigs.len(), 1);
    }

    #[test]
    fn hot_signer_sign_taproot() {
        let secp = secp256k1::Secp256k1::new();
        let network = bitcoin::Network::Bitcoin;

        // Create a Liana descriptor with as primary path a 2-of-3 with three hot signers and a
        // single hot signer as recovery path. (The recovery path signer is also used in the
        // primary path.) Use various random derivation paths.
        let (prim_signer_a, prim_signer_b, recov_signer) = (
            HotSigner::generate(network).unwrap(),
            HotSigner::generate(network).unwrap(),
            HotSigner::generate(network).unwrap(),
        );
        let origin_der = bip32::DerivationPath::from_str("m/0'/12'/42").unwrap();
        let xkey = prim_signer_a.xpub_at(&origin_der, &secp);
        let prim_key_a = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some((prim_signer_a.fingerprint(&secp), origin_der)),
            xkey,
            derivation_paths: DerivPaths::new(vec![
                bip32::DerivationPath::from_str("m/420/56/0").unwrap(),
                bip32::DerivationPath::from_str("m/420/56/1").unwrap(),
            ])
            .unwrap(),
            wildcard: Wildcard::Unhardened,
        });
        let origin_der = bip32::DerivationPath::from_str("m/18'/24'").unwrap();
        let xkey = prim_signer_b.xpub_at(&origin_der, &secp);
        let prim_key_b = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some((prim_signer_b.fingerprint(&secp), origin_der)),
            xkey,
            derivation_paths: DerivPaths::new(vec![
                bip32::DerivationPath::from_str("m/31/0").unwrap(),
                bip32::DerivationPath::from_str("m/31/1").unwrap(),
            ])
            .unwrap(),
            wildcard: Wildcard::Unhardened,
        });
        let origin_der = bip32::DerivationPath::from_str("m/18'/25'").unwrap();
        let xkey = recov_signer.xpub_at(&origin_der, &secp);
        let prim_key_c = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some((recov_signer.fingerprint(&secp), origin_der)),
            xkey,
            derivation_paths: DerivPaths::new(vec![
                bip32::DerivationPath::from_str("m/0").unwrap(),
                bip32::DerivationPath::from_str("m/1").unwrap(),
            ])
            .unwrap(),
            wildcard: Wildcard::Unhardened,
        });
        let prim_keys =
            descriptors::PathInfo::Multi(2, vec![prim_key_a.clone(), prim_key_b, prim_key_c]);
        let origin_der = bip32::DerivationPath::from_str("m/1/2'/3/4'").unwrap();
        let xkey = recov_signer.xpub_at(&origin_der, &secp);
        let recov_key = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some((recov_signer.fingerprint(&secp), origin_der)),
            xkey,
            derivation_paths: DerivPaths::new(vec![
                bip32::DerivationPath::from_str("m/5/6/0").unwrap(),
                bip32::DerivationPath::from_str("m/5/6/1").unwrap(),
            ])
            .unwrap(),
            wildcard: Wildcard::Unhardened,
        });
        let recov_keys = descriptors::PathInfo::Single(recov_key.clone());
        let policy =
            descriptors::LianaPolicy::new(prim_keys, [(46, recov_keys)].iter().cloned().collect())
                .unwrap();
        let desc = descriptors::LianaDescriptor::new(policy);

        // Create a dummy PSBT spending a coin from this descriptor with a single input and single
        // (external) output. We'll be modifying it as we go.
        let spent_coin_desc = desc.receive_descriptor().derive(42.into(), &secp);
        let mut psbt_in = PsbtIn::default();
        spent_coin_desc.update_psbt_in(&mut psbt_in);
        psbt_in.witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(19_000),
            script_pubkey: spent_coin_desc.script_pubkey(),
        });
        let mut dummy_psbt = Psbt {
            unsigned_tx: bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: absolute::LockTime::Blocks(absolute::Height::ZERO),
                input: vec![bitcoin::TxIn {
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    previous_output: bitcoin::OutPoint::from_str(
                        "4613e078e4cdbb0fce1bc6e44b028f0e11621a134a1605efdc456c32d155c922:19",
                    )
                    .unwrap(),
                    ..bitcoin::TxIn::default()
                }],
                output: vec![bitcoin::TxOut {
                    value: Amount::from_sat(18_420),
                    script_pubkey: bitcoin::Address::from_str(
                        "bc1qvklensptw5lk7d470ds60pcpsr0psdpgyvwepv",
                    )
                    .unwrap()
                    .assume_checked()
                    .script_pubkey(),
                }],
            },
            version: 0,
            xpub: BTreeMap::new(),
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),
            inputs: vec![psbt_in],
            outputs: Vec::new(),
        };

        // Sign the PSBT with the two primary signers. The recovery signer will sign for the two keys
        // that it manages.
        let psbt = dummy_psbt.clone();
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        let psbt = prim_signer_a.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        let psbt = prim_signer_b.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 2);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        let psbt = recov_signer.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 4);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].partial_sigs.is_empty());

        // We can add another external output to the transaction, we can still sign without issue.
        // The output can be insane, we don't check it. It doesn't even need an accompanying PSBT
        // output.
        dummy_psbt.unsigned_tx.output.push(bitcoin::TxOut::NULL);
        let psbt = dummy_psbt.clone();
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        let psbt = prim_signer_a.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        let psbt = prim_signer_b.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 2);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        let psbt = recov_signer.sign_psbt(psbt, &secp).unwrap();
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 4);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].partial_sigs.is_empty());

        // We can add another input to the PSBT. If we don't attach also another transaction input
        // it will fail.
        let other_spent_coin_desc = desc.receive_descriptor().derive(84.into(), &secp);
        let mut psbt_in = PsbtIn::default();
        other_spent_coin_desc.update_psbt_in(&mut psbt_in);
        psbt_in.witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(19_000),
            script_pubkey: other_spent_coin_desc.script_pubkey(),
        });
        dummy_psbt.inputs.push(psbt_in);
        let psbt = dummy_psbt.clone();
        assert!(prim_signer_a
            .sign_psbt(psbt, &secp)
            .unwrap_err()
            .to_string()
            .contains("Information contained in the PSBT is wrong"));

        // But now if we add the inputs also to the transaction itself, it will have signed both
        // inputs.
        dummy_psbt.unsigned_tx.input.push(bitcoin::TxIn {
            // Note the sequence can be different. We don't care.
            sequence: bitcoin::Sequence::ENABLE_LOCKTIME_NO_RBF,
            previous_output: bitcoin::OutPoint::from_str(
                "5613e078e4cdbb0fce1bc6e44b028f0e11621a134a1605efdc456c32d155c922:0",
            )
            .unwrap(),
            ..bitcoin::TxIn::default()
        });
        let psbt = dummy_psbt.clone();
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_key_sig.is_none()));
        let psbt = prim_signer_a.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.len() == 1));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.partial_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_key_sig.is_none()));
        let psbt = prim_signer_b.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.len() == 2));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.partial_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_key_sig.is_none()));
        let psbt = recov_signer.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.len() == 4));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.partial_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_key_sig.is_none()));

        // If the witness script is set it'll assume it's a P2WSH input and provide ECDSA sigs.
        // But since we haven't provided any P2WSH details it won't fill anything.
        let mut psbt = dummy_psbt.clone();
        psbt.inputs[1].witness_script = Some(Default::default());
        let psbt = prim_signer_a.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt.inputs[1].partial_sigs.is_empty());
        assert!(psbt.inputs[1].tap_key_sig.is_none());
        assert!(psbt.inputs[1].tap_script_sigs.is_empty());

        // If the witness utxo is missing for one of the inputs it'll tell us the PSBT is
        // incomplete.
        let mut psbt = dummy_psbt.clone();
        psbt.inputs[1].witness_utxo = None;
        assert!(prim_signer_a
            .sign_psbt(psbt, &secp)
            .unwrap_err()
            .to_string()
            .contains("The PSBT is missing some information necessary for signing."));

        // If we remove the BIP32 derivations for the first input it will only provide signatures
        // for the second one.
        let mut psbt = dummy_psbt.clone();
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        assert!(psbt.inputs[1].tap_script_sigs.is_empty());
        psbt.inputs[0].tap_key_origins.clear();
        let psbt = prim_signer_b.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        assert_eq!(psbt.inputs[1].tap_script_sigs.len(), 1);

        // Now use a Taproot descriptor such as there is a single primary key as the internal key.
        let prim_keys = descriptors::PathInfo::Single(prim_key_a);
        let recov_keys = descriptors::PathInfo::Single(recov_key);
        let policy =
            descriptors::LianaPolicy::new(prim_keys, [(42, recov_keys)].iter().cloned().collect())
                .unwrap();
        let desc = descriptors::LianaDescriptor::new(policy);
        let spent_coin_desc = desc.receive_descriptor().derive(412.into(), &secp);

        // Update the two inputs with the details for this descriptor.
        dummy_psbt.inputs[0].tap_key_origins.clear();
        spent_coin_desc.update_psbt_in(&mut dummy_psbt.inputs[0]);
        dummy_psbt.inputs[1].tap_key_origins.clear();
        spent_coin_desc.update_psbt_in(&mut dummy_psbt.inputs[1]);

        // Sign the PSBT with the primary and recovery signers. The prim signer will add a sig for
        // the key path and the recov signer for the script path.
        let psbt = dummy_psbt.clone();
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_key_sig.is_none()));
        let psbt = prim_signer_a.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_key_sig.is_some()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.is_empty()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.partial_sigs.is_empty()));
        let psbt = recov_signer.sign_psbt(psbt, &secp).unwrap();
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_key_sig.is_some()));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.tap_script_sigs.len() == 1));
        assert!(psbt
            .inputs
            .iter()
            .all(|psbt_in| psbt_in.partial_sigs.is_empty()));
    }

    #[test]
    fn hot_signer_signs_musig2_derive_then_aggregate() {
        assert_hot_signer_signs_musig2(descriptors::MuSig2DerivationMode::DeriveThenAggregate);
    }

    #[test]
    fn hot_signer_signs_musig2_aggregate_then_derive() {
        assert_hot_signer_signs_musig2(
            descriptors::MuSig2DerivationMode::AggregateThenDeriveBip328,
        );
    }

    #[test]
    fn signer_set_net() {
        let secp = secp256k1::Secp256k1::signing_only();
        let mut signer = HotSigner::from_str(
            bitcoin::Network::Bitcoin,
            "burger ball theme dog light account produce chest warrior swarm flip equip",
        )
        .unwrap();
        assert_eq!(signer.xpub_at(&bip32::DerivationPath::master(), &secp).to_string(), "xpub661MyMwAqRbcGKvR8dChsA92AHfJS6fJMR41jAASu5S79v65dac244iBd7PwqnfMQ9jWsmg8SqnNz3MjkwYF8Edzr2ttxt171Cr5RyJrvF2");

        let tpub = "tpubD6NzVbkrYhZ4Y87GapBo55UPVQkxRVAMu3eK5iDbEzBzuCknhoT7CWP1s9UjNHcbC4GRVMBzywcRgDrM9oPV1g6HudeCeQfLbASVBxpNJV3";
        for net in &[
            bitcoin::Network::Testnet,
            bitcoin::Network::Signet,
            bitcoin::Network::Regtest,
        ] {
            signer.set_network(*net);
            assert_eq!(
                signer
                    .xpub_at(&bip32::DerivationPath::master(), &secp)
                    .to_string(),
                tpub
            );
        }
    }

    #[test]
    fn test_mnemonic_filename() {
        // Test to_string with descriptor info
        let fingerprint = Fingerprint::from_str("abcd1234").unwrap();
        let filename_with_info = MnemonicFileName {
            fingerprint,
            descriptor_info: Some(("def456".to_string(), 1620000000)),
        };

        assert_eq!(
            filename_with_info.to_string(),
            "mnemonic-abcd1234-def456-1620000000.txt"
        );

        // Test to_string without descriptor info
        let filename_without_info = MnemonicFileName {
            fingerprint,
            descriptor_info: None,
        };

        assert_eq!(filename_without_info.to_string(), "mnemonic-abcd1234.txt");

        // Test from_str with descriptor info
        let input_with_info = "mnemonic-abcd1234-def456-1620000000.txt";
        let parsed_with_info = MnemonicFileName::from_str(input_with_info).unwrap();

        assert_eq!(parsed_with_info.fingerprint, fingerprint);
        assert_eq!(
            parsed_with_info.descriptor_info,
            Some(("def456".to_string(), 1620000000))
        );

        // Test from_str without descriptor info
        let input_without_info = "mnemonic-abcd1234.txt";
        let parsed_without_info = MnemonicFileName::from_str(input_without_info).unwrap();

        assert_eq!(parsed_without_info.fingerprint, fingerprint);
        assert_eq!(parsed_without_info.descriptor_info, None);

        // Test roundtrip with descriptor info
        let roundtrip_with_info =
            MnemonicFileName::from_str(&filename_with_info.to_string()).unwrap();
        assert_eq!(filename_with_info, roundtrip_with_info);

        // Test roundtrip without descriptor info
        let roundtrip_without_info =
            MnemonicFileName::from_str(&filename_without_info.to_string()).unwrap();
        assert_eq!(filename_without_info, roundtrip_without_info);

        // Test error cases

        // Missing prefix
        assert!(MnemonicFileName::from_str("abcd1234.txt").is_err());

        // Missing suffix
        assert!(MnemonicFileName::from_str("mnemonic-abcd1234").is_err());

        // Wrong number of parts
        assert!(MnemonicFileName::from_str("mnemonic-abcd1234-def456.txt").is_err());

        // Invalid fingerprint (assuming Fingerprint::from_str fails for "invalid")
        assert!(MnemonicFileName::from_str("mnemonic-invalid-def456-1620000000.txt").is_err());

        // Invalid timestamp
        assert!(MnemonicFileName::from_str("mnemonic-abcd1234-def456-notanumber.txt").is_err());
    }
}
