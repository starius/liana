//! A test-only helper which signs Taproot and MuSig2 PSBTs from a master xpriv.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    env, fmt,
    io::{self, Write},
    str::FromStr,
};

use liana::descriptors::bip328_synthetic_xpub;
use miniscript::bitcoin::{
    self,
    bip32::{self, Fingerprint, Xpriv},
    hashes::Hash,
    key::TapTweak,
    psbt::{raw, Input as PsbtIn, Psbt},
    secp256k1, sighash,
    taproot::TapLeafHash,
};
use musig2::{
    secp256k1 as musig_secp256k1, AggNonce, BinaryEncoding, CompactSignature, KeyAggContext,
    PartialSignature, PubNonce, SecNonce,
};

const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x1a;
const PSBT_IN_MUSIG2_PUB_NONCE: u8 = 0x1b;
const PSBT_IN_MUSIG2_PARTIAL_SIG: u8 = 0x1c;

const PSBT_PROPRIETARY_PREFIX_LIANA: &[u8] = b"liana";
const PSBT_IN_LIANA_MUSIG2_NONCE_SEED: u8 = 0x00;
const PSBT_IN_LIANA_MUSIG2_AGGNONCE: u8 = 0x01;

#[derive(Debug)]
enum SignerError {
    Bip32(bip32::Error),
    IncompletePsbt,
    InsanePsbt,
    Random(getrandom::Error),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bip32(e) => write!(f, "BIP32 error: {e}"),
            Self::IncompletePsbt => write!(f, "The PSBT is incomplete."),
            Self::InsanePsbt => write!(f, "The PSBT contains inconsistent signing data."),
            Self::Random(e) => write!(f, "Could not generate randomness: {e}"),
        }
    }
}

type Result<T> = std::result::Result<T, SignerError>;

#[derive(Clone, Debug)]
struct Musig2ParticipantSet {
    aggregate_pubkey: secp256k1::PublicKey,
    participant_pubkeys: Vec<secp256k1::PublicKey>,
    has_unscoped_entry: bool,
    legacy_script_leaf_hashes: BTreeSet<TapLeafHash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Musig2InputScope {
    KeySpend,
    ScriptSpend(TapLeafHash),
}

struct Musig2InputSession {
    participant_set_pubkey: secp256k1::PublicKey,
    spend_pubkey: secp256k1::PublicKey,
    scope: Musig2InputScope,
    participant_pubkeys: Vec<secp256k1::PublicKey>,
    key_agg_ctx: KeyAggContext,
}

#[derive(Clone)]
struct OwnedMusig2Participant {
    participant_pubkey: secp256k1::PublicKey,
    derivation_path: bip32::DerivationPath,
}

struct XprivSigner {
    master_xpriv: Xpriv,
}

fn musig2_composite_key(
    type_value: u8,
    participant_pubkey: secp256k1::PublicKey,
    aggregate_pubkey: secp256k1::PublicKey,
    scope: Musig2InputScope,
) -> raw::Key {
    let mut key = [
        participant_pubkey.serialize().as_slice(),
        aggregate_pubkey.serialize().as_slice(),
    ]
    .concat();
    if let Musig2InputScope::ScriptSpend(leaf_hash) = scope {
        key.extend_from_slice(leaf_hash.as_byte_array());
    }
    raw::Key { type_value, key }
}

fn musig2_input_proprietary_key(
    subtype: u8,
    participant_pubkey: secp256k1::PublicKey,
    aggregate_pubkey: secp256k1::PublicKey,
    scope: Musig2InputScope,
) -> raw::ProprietaryKey {
    let mut key = [
        participant_pubkey.serialize().as_slice(),
        aggregate_pubkey.serialize().as_slice(),
    ]
    .concat();
    if let Musig2InputScope::ScriptSpend(leaf_hash) = scope {
        key.extend_from_slice(leaf_hash.as_byte_array());
    }
    raw::ProprietaryKey {
        prefix: PSBT_PROPRIETARY_PREFIX_LIANA.to_vec(),
        subtype,
        key,
    }
}

fn bitcoin_to_musig_pubkey(pubkey: secp256k1::PublicKey) -> Result<musig_secp256k1::PublicKey> {
    musig_secp256k1::PublicKey::from_slice(&pubkey.serialize()).map_err(|_| SignerError::InsanePsbt)
}

fn bitcoin_to_musig_secret_key(
    secret_key: secp256k1::SecretKey,
) -> Result<musig_secp256k1::SecretKey> {
    musig_secp256k1::SecretKey::from_byte_array(secret_key.secret_bytes())
        .map_err(|_| SignerError::InsanePsbt)
}

fn musig_to_bitcoin_pubkey(pubkey: musig_secp256k1::PublicKey) -> Result<secp256k1::PublicKey> {
    secp256k1::PublicKey::from_slice(&pubkey.serialize()).map_err(|_| SignerError::InsanePsbt)
}

fn musig2_synthetic_fingerprint(aggregate_pubkey: secp256k1::PublicKey) -> Fingerprint {
    bip328_synthetic_xpub(aggregate_pubkey, bitcoin::Network::Bitcoin).fingerprint()
}

fn parse_musig2_participant_sets(psbt_in: &PsbtIn) -> Result<Vec<Musig2ParticipantSet>> {
    let mut sets =
        BTreeMap::<(secp256k1::PublicKey, Vec<secp256k1::PublicKey>), Musig2ParticipantSet>::new();
    for (key, value) in &psbt_in.unknown {
        if key.type_value != PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS {
            continue;
        }
        if !matches!(key.key.len(), 33 | 65) || value.is_empty() || value.len() % 33 != 0 {
            return Err(SignerError::InsanePsbt);
        }
        let aggregate_pubkey = secp256k1::PublicKey::from_slice(&key.key[..33])
            .map_err(|_| SignerError::InsanePsbt)?;
        let mut participant_pubkeys = value
            .chunks_exact(33)
            .map(|pubkey| {
                secp256k1::PublicKey::from_slice(pubkey).map_err(|_| SignerError::InsanePsbt)
            })
            .collect::<Result<Vec<_>>>()?;
        participant_pubkeys.sort();
        let entry = sets
            .entry((aggregate_pubkey, participant_pubkeys.clone()))
            .or_insert_with(|| Musig2ParticipantSet {
                aggregate_pubkey,
                participant_pubkeys,
                has_unscoped_entry: false,
                legacy_script_leaf_hashes: BTreeSet::new(),
            });
        if key.key.len() == 33 {
            entry.has_unscoped_entry = true;
        } else {
            let leaf_hash =
                TapLeafHash::from_slice(&key.key[33..]).map_err(|_| SignerError::InsanePsbt)?;
            entry.legacy_script_leaf_hashes.insert(leaf_hash);
        }
    }
    Ok(sets.into_values().collect())
}

fn parse_musig2_pubnonces(
    psbt_in: &PsbtIn,
    session: &Musig2InputSession,
) -> Result<Vec<(secp256k1::PublicKey, PubNonce)>> {
    let mut pubnonces = Vec::new();
    for (key, value) in &psbt_in.unknown {
        if key.type_value != PSBT_IN_MUSIG2_PUB_NONCE {
            continue;
        }
        if !matches!(key.key.len(), 66 | 98) {
            continue;
        }
        let participant_pubkey = secp256k1::PublicKey::from_slice(&key.key[..33])
            .map_err(|_| SignerError::InsanePsbt)?;
        let key_aggregate_pubkey = secp256k1::PublicKey::from_slice(&key.key[33..66])
            .map_err(|_| SignerError::InsanePsbt)?;
        let key_scope = if key.key.len() == 66 {
            Musig2InputScope::KeySpend
        } else {
            Musig2InputScope::ScriptSpend(
                TapLeafHash::from_slice(&key.key[66..]).map_err(|_| SignerError::InsanePsbt)?,
            )
        };
        if key_scope != session.scope
            || (key_aggregate_pubkey != session.participant_set_pubkey
                && key_aggregate_pubkey != session.spend_pubkey)
        {
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
    session: &Musig2InputSession,
) -> Result<Vec<(secp256k1::PublicKey, PartialSignature)>> {
    let mut partial_signatures = Vec::new();
    for (key, value) in &psbt_in.unknown {
        if key.type_value != PSBT_IN_MUSIG2_PARTIAL_SIG {
            continue;
        }
        if !matches!(key.key.len(), 66 | 98) {
            continue;
        }
        let participant_pubkey = secp256k1::PublicKey::from_slice(&key.key[..33])
            .map_err(|_| SignerError::InsanePsbt)?;
        let key_aggregate_pubkey = secp256k1::PublicKey::from_slice(&key.key[33..66])
            .map_err(|_| SignerError::InsanePsbt)?;
        let key_scope = if key.key.len() == 66 {
            Musig2InputScope::KeySpend
        } else {
            Musig2InputScope::ScriptSpend(
                TapLeafHash::from_slice(&key.key[66..]).map_err(|_| SignerError::InsanePsbt)?,
            )
        };
        if key_scope != session.scope
            || (key_aggregate_pubkey != session.participant_set_pubkey
                && key_aggregate_pubkey != session.spend_pubkey)
        {
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
    session: &Musig2InputSession,
) -> Result<Option<[u8; 32]>> {
    let key = musig2_input_proprietary_key(
        PSBT_IN_LIANA_MUSIG2_NONCE_SEED,
        participant_pubkey,
        session.participant_set_pubkey,
        session.scope,
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
    session: &Musig2InputSession,
) -> Result<Option<AggNonce>> {
    let key = musig2_input_proprietary_key(
        PSBT_IN_LIANA_MUSIG2_AGGNONCE,
        participant_pubkey,
        session.participant_set_pubkey,
        session.scope,
    );
    psbt_in
        .proprietary
        .get(&key)
        .map(|bytes| AggNonce::from_bytes(bytes.as_slice()).map_err(|_| SignerError::InsanePsbt))
        .transpose()
}

fn participant_set_scopes(
    psbt_in: &PsbtIn,
    participant_set: &Musig2ParticipantSet,
) -> Result<Vec<Musig2InputScope>> {
    let mut scopes = participant_set
        .legacy_script_leaf_hashes
        .iter()
        .copied()
        .map(Musig2InputScope::ScriptSpend)
        .collect::<BTreeSet<_>>();

    if participant_set.has_unscoped_entry {
        let aggregate_xonly = participant_set.aggregate_pubkey.x_only_public_key().0;
        let synthetic_fingerprint = musig2_synthetic_fingerprint(participant_set.aggregate_pubkey);

        if psbt_in.tap_internal_key == Some(aggregate_xonly)
            || psbt_in
                .tap_internal_key
                .and_then(|tap_internal_key| psbt_in.tap_key_origins.get(&tap_internal_key))
                .is_some_and(|(_, (fg, _))| *fg == synthetic_fingerprint)
        {
            scopes.insert(Musig2InputScope::KeySpend);
        }

        if let Some((leaf_hashes, _)) = psbt_in.tap_key_origins.get(&aggregate_xonly) {
            scopes.extend(
                leaf_hashes
                    .iter()
                    .copied()
                    .map(Musig2InputScope::ScriptSpend),
            );
        }

        scopes.extend(
            psbt_in
                .tap_key_origins
                .iter()
                .filter(|(_, (leaf_hashes, (fg, _)))| {
                    !leaf_hashes.is_empty() && *fg == synthetic_fingerprint
                })
                .flat_map(|(_, (leaf_hashes, _))| {
                    leaf_hashes
                        .iter()
                        .copied()
                        .map(Musig2InputScope::ScriptSpend)
                        .collect::<Vec<_>>()
                }),
        );
    }

    if scopes.is_empty() {
        return Err(SignerError::InsanePsbt);
    }

    Ok(scopes.into_iter().collect())
}

impl XprivSigner {
    fn new(master_xpriv: Xpriv) -> Self {
        Self { master_xpriv }
    }

    fn fingerprint(
        &self,
        secp: &secp256k1::Secp256k1<impl secp256k1::Signing>,
    ) -> bip32::Fingerprint {
        self.master_xpriv.fingerprint(secp)
    }

    fn xpriv_at(
        &self,
        der_path: &bip32::DerivationPath,
        secp: &secp256k1::Secp256k1<impl secp256k1::Signing>,
    ) -> Result<Xpriv> {
        self.master_xpriv
            .derive_priv(secp, der_path)
            .map_err(SignerError::Bip32)
    }

    fn musig2_participant_secret_key(
        &self,
        secp: &secp256k1::Secp256k1<impl secp256k1::Signing>,
        participant_pubkey: secp256k1::PublicKey,
        derivation_path: &bip32::DerivationPath,
    ) -> Result<secp256k1::SecretKey> {
        let privkey = self.xpriv_at(derivation_path, secp)?.to_priv();
        let pubkey = privkey.public_key(secp);
        if pubkey.inner != participant_pubkey {
            return Err(SignerError::InsanePsbt);
        }
        Ok(privkey.inner)
    }

    fn reconstruct_musig2_session(
        &self,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        psbt_in: &PsbtIn,
        participant_set: Musig2ParticipantSet,
        scope: Musig2InputScope,
    ) -> Result<Musig2InputSession> {
        let mut participant_pubkeys = participant_set.participant_pubkeys.clone();
        participant_pubkeys.sort();

        let musig_participant_pubkeys = participant_pubkeys
            .iter()
            .cloned()
            .map(bitcoin_to_musig_pubkey)
            .collect::<Result<Vec<_>>>()?;
        let mut key_agg_ctx =
            KeyAggContext::new(musig_participant_pubkeys).map_err(|_| SignerError::InsanePsbt)?;
        let mut internal_pubkey = musig_to_bitcoin_pubkey(
            key_agg_ctx.aggregated_pubkey_untweaked::<musig_secp256k1::PublicKey>(),
        )?;
        if internal_pubkey != participant_set.aggregate_pubkey {
            return Err(SignerError::InsanePsbt);
        }

        let mut synthetic_xpub =
            bip328_synthetic_xpub(participant_set.aggregate_pubkey, bitcoin::Network::Bitcoin);
        let synthetic_fingerprint = synthetic_xpub.fingerprint();

        let maybe_bip328_derivation = match scope {
            Musig2InputScope::KeySpend => {
                let tap_internal_key = psbt_in
                    .tap_internal_key
                    .ok_or(SignerError::IncompletePsbt)?;
                psbt_in.tap_key_origins.get(&tap_internal_key).and_then(
                    |(_, (fg, derivation_path))| {
                        (*fg == synthetic_fingerprint).then(|| derivation_path.clone())
                    },
                )
            }
            Musig2InputScope::ScriptSpend(leaf_hash) => psbt_in
                .tap_key_origins
                .iter()
                .find_map(|(pubkey, (leaf_hashes, (fg, derivation_path)))| {
                    (*fg == synthetic_fingerprint && leaf_hashes.contains(&leaf_hash))
                        .then_some((*pubkey, derivation_path.clone()))
                })
                .map(|(_, derivation_path)| derivation_path),
        };

        if let Some(derivation_path) = maybe_bip328_derivation {
            for child in &derivation_path {
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

        match scope {
            Musig2InputScope::KeySpend => {
                let tap_internal_key = psbt_in
                    .tap_internal_key
                    .ok_or(SignerError::IncompletePsbt)?;
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
            }
            Musig2InputScope::ScriptSpend(leaf_hash) => {
                let aggregate_xonly = internal_pubkey.x_only_public_key().0;
                let Some((leaf_hashes, _)) = psbt_in.tap_key_origins.get(&aggregate_xonly) else {
                    return Err(SignerError::IncompletePsbt);
                };
                if !leaf_hashes.contains(&leaf_hash) {
                    return Err(SignerError::InsanePsbt);
                }
            }
        }

        let spend_pubkey =
            musig_to_bitcoin_pubkey(key_agg_ctx.aggregated_pubkey::<musig_secp256k1::PublicKey>())?;

        Ok(Musig2InputSession {
            participant_set_pubkey: participant_set.aggregate_pubkey,
            spend_pubkey,
            scope,
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
    ) -> Result<Vec<OwnedMusig2Participant>> {
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

    fn sign_musig2_taproot(
        &self,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        sighash_cache: &mut sighash::SighashCache<&bitcoin::Transaction>,
        master_fingerprint: bip32::Fingerprint,
        prevouts: &[bitcoin::TxOut],
        psbt_in: &mut PsbtIn,
        input_index: usize,
        sighash_type: sighash::TapSighashType,
    ) -> Result<bool> {
        let participant_sets = parse_musig2_participant_sets(psbt_in)?;
        if participant_sets.is_empty() {
            return Ok(false);
        }
        let mut has_musig2_keyspend = false;
        for participant_set in participant_sets {
            for scope in participant_set_scopes(psbt_in, &participant_set)? {
                has_musig2_keyspend |= matches!(scope, Musig2InputScope::KeySpend);
                let session =
                    self.reconstruct_musig2_session(secp, psbt_in, participant_set.clone(), scope)?;
                let owned_participants =
                    self.owned_musig2_participants(secp, psbt_in, &session, master_fingerprint)?;

                let participant_pubkeys = session.participant_pubkeys.clone();
                let expected_participant_count = participant_pubkeys.len();
                let participant_set_pubkey = session.participant_set_pubkey;
                let participant_index = participant_pubkeys
                    .iter()
                    .cloned()
                    .map(|pubkey| (pubkey, ()))
                    .collect::<BTreeMap<_, _>>();

                let mut pubnonces = parse_musig2_pubnonces(psbt_in, &session)?
                    .into_iter()
                    .map(|(participant_pubkey, pubnonce)| {
                        if !participant_index.contains_key(&participant_pubkey) {
                            Err(SignerError::InsanePsbt)
                        } else {
                            Ok((participant_pubkey, pubnonce))
                        }
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?;
                let mut partial_signatures = parse_musig2_partial_signatures(psbt_in, &session)?
                    .into_iter()
                    .map(|(participant_pubkey, partial_signature)| {
                        if !participant_index.contains_key(&participant_pubkey) {
                            Err(SignerError::InsanePsbt)
                        } else {
                            Ok((participant_pubkey, partial_signature))
                        }
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?;

                if !partial_signatures.is_empty() && pubnonces.len() != expected_participant_count {
                    return Err(SignerError::InsanePsbt);
                }

                let prevouts = sighash::Prevouts::All(prevouts);
                let sighash = match session.scope {
                    Musig2InputScope::KeySpend => sighash_cache
                        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
                        .map_err(|_| SignerError::InsanePsbt)?,
                    Musig2InputScope::ScriptSpend(leaf_hash) => sighash_cache
                        .taproot_script_spend_signature_hash(
                            input_index,
                            &prevouts,
                            leaf_hash,
                            sighash_type,
                        )
                        .map_err(|_| SignerError::InsanePsbt)?,
                };
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
                        &session,
                    )? {
                        nonce_seed
                    } else {
                        let mut nonce_seed = [0; 32];
                        getrandom::fill(&mut nonce_seed).map_err(SignerError::Random)?;
                        psbt_in.proprietary.insert(
                            musig2_input_proprietary_key(
                                PSBT_IN_LIANA_MUSIG2_NONCE_SEED,
                                owned_participant.participant_pubkey,
                                participant_set_pubkey,
                                session.scope,
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
                            session.spend_pubkey,
                            session.scope,
                        ),
                        pubnonce.to_bytes().to_vec(),
                    );
                    pubnonces.insert(owned_participant.participant_pubkey, pubnonce);
                }

                if pubnonces.len() != expected_participant_count {
                    continue;
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
                        &session,
                    )?
                    .ok_or(SignerError::IncompletePsbt)?;

                    if let Some(stored_nonce) = read_musig2_aggnonce(
                        psbt_in,
                        owned_participant.participant_pubkey,
                        &session,
                    )? {
                        if stored_nonce != aggregated_nonce {
                            return Err(SignerError::InsanePsbt);
                        }
                    } else {
                        psbt_in.proprietary.insert(
                            musig2_input_proprietary_key(
                                PSBT_IN_LIANA_MUSIG2_AGGNONCE,
                                owned_participant.participant_pubkey,
                                participant_set_pubkey,
                                session.scope,
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
                            session.spend_pubkey,
                            session.scope,
                        ),
                        partial_signature.serialize().to_vec(),
                    );
                    partial_signatures
                        .insert(owned_participant.participant_pubkey, partial_signature);
                }

                for participant_pubkey in &participant_pubkeys {
                    if let Some(partial_signature) = partial_signatures.get(participant_pubkey) {
                        musig2::verify_partial(
                            &session.key_agg_ctx,
                            partial_signature.clone(),
                            &aggregated_nonce,
                            bitcoin_to_musig_pubkey(*participant_pubkey)?,
                            &pubnonces[participant_pubkey],
                            sighash_bytes,
                        )
                        .map_err(|_| SignerError::InsanePsbt)?;
                    }
                }

                if partial_signatures.len() == expected_participant_count {
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
                    let sig = bitcoin::taproot::Signature {
                        signature: secp256k1::schnorr::Signature::from_slice(&signature.to_bytes())
                            .map_err(|_| SignerError::InsanePsbt)?,
                        sighash_type,
                    };
                    match session.scope {
                        Musig2InputScope::KeySpend => {
                            if psbt_in.tap_key_sig.is_none() {
                                psbt_in.tap_key_sig = Some(sig);
                            }
                        }
                        Musig2InputScope::ScriptSpend(leaf_hash) => {
                            psbt_in.tap_script_sigs.insert(
                                (session.spend_pubkey.x_only_public_key().0, leaf_hash),
                                sig,
                            );
                        }
                    }
                }
            }
        }

        Ok(has_musig2_keyspend)
    }

    fn sign_taproot(
        &self,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        sighash_cache: &mut sighash::SighashCache<&bitcoin::Transaction>,
        master_fingerprint: bip32::Fingerprint,
        prevouts: &[bitcoin::TxOut],
        psbt_in: &mut PsbtIn,
        input_index: usize,
    ) -> Result<()> {
        let sighash_type = sighash::TapSighashType::Default;
        let is_musig2_input = self.sign_musig2_taproot(
            secp,
            sighash_cache,
            master_fingerprint,
            prevouts,
            psbt_in,
            input_index,
            sighash_type,
        )?;

        let prevouts = sighash::Prevouts::All(prevouts);
        if !is_musig2_input {
            if let Some(ref int_key) = psbt_in.tap_internal_key {
                if let Some((_, (fg, der_path))) = psbt_in.tap_key_origins.get(int_key) {
                    if *fg == master_fingerprint {
                        let privkey = self.xpriv_at(der_path, secp)?.to_priv();
                        let keypair = secp256k1::Keypair::from_secret_key(secp, &privkey.inner);
                        if keypair.x_only_public_key().0 != *int_key {
                            return Err(SignerError::InsanePsbt);
                        }
                        let keypair = keypair
                            .tap_tweak(secp, psbt_in.tap_merkle_root)
                            .to_keypair();
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

        for (pubkey, (leaf_hashes, (fg, der_path))) in &psbt_in.tap_key_origins {
            if *fg != master_fingerprint {
                continue;
            }

            for leaf_hash in leaf_hashes {
                let privkey = self.xpriv_at(der_path, secp)?.to_priv();
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

    fn sign_psbt(&self, psbt: &mut Psbt) -> Result<()> {
        let secp = secp256k1::Secp256k1::new();
        let master_fingerprint = self.fingerprint(&secp);
        let mut sighash_cache = sighash::SighashCache::new(&psbt.unsigned_tx);
        let prevouts: Vec<_> = psbt
            .inputs
            .iter()
            .filter_map(|psbt_in| psbt_in.witness_utxo.clone())
            .collect();
        if prevouts.len() != psbt.inputs.len() {
            return Err(SignerError::IncompletePsbt);
        }

        for i in 0..psbt.inputs.len() {
            self.sign_taproot(
                &secp,
                &mut sighash_cache,
                master_fingerprint,
                &prevouts,
                &mut psbt.inputs[i],
                i,
            )?;
        }

        Ok(())
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 3);

    let mut psbt = Psbt::from_str(&args[1]).unwrap();
    let master_xpriv = Xpriv::from_str(&args[2]).unwrap();
    XprivSigner::new(master_xpriv).sign_psbt(&mut psbt).unwrap();

    print!("{psbt}");
    io::stdout().flush().unwrap();
}
