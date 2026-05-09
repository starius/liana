use std::{fmt, str::FromStr};

use miniscript::{
    bitcoin::{
        self, bip32,
        psbt::{raw, Input as PsbtIn, Output as PsbtOut},
        secp256k1,
    },
    descriptor::{
        self, checksum::desc_checksum, DefiniteDescriptorKey, Descriptor, DescriptorPublicKey,
    },
    psbt::{PsbtInputExt, PsbtOutputExt},
    ToPublicKey,
};
use musig2::{secp::Point, KeyAggContext};

use super::{LianaPolicyError, MuSig2DerivationMode};

const DUMMY_XPUB: &str = "[8c3ffb6e/48'/1'/0'/2']tpubDEMt3bpQMa99W81K9h8f2FJH1C81eSd6bbSkBP8tcqQHAfSKvuGp2fz6xiVpfShzT9sKPx7DVBphChjxvNd15WcbsCca5oVz1AcUTWHxkdS";
const DUMMY_SHADOW_SUFFIX: &str = "/<0;1>/*";
const BIP328_SYNTHETIC_CHAINCODE: [u8; 32] = [
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74, 0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76,
    0x2d, 0x32, 0xcb, 0x45, 0x71, 0x71, 0x67, 0xe3, 0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65,
];
const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x1a;
const PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AggregateKeyDerivation {
    suffix: String,
    derivation_paths: descriptor::DerivPaths,
    wildcard: descriptor::Wildcard,
}

impl AggregateKeyDerivation {
    pub fn from_suffix(suffix: &str) -> Result<Self, LianaPolicyError> {
        if suffix.is_empty() {
            return Err(LianaPolicyError::InvalidMuSig2Expression);
        }

        let dummy_key = DescriptorPublicKey::from_str(&format!("{DUMMY_XPUB}{suffix}"))
            .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)?;
        let (derivation_paths, wildcard) = match dummy_key {
            DescriptorPublicKey::XPub(xpub) => (
                descriptor::DerivPaths::new(vec![xpub.derivation_path])
                    .ok_or(LianaPolicyError::InvalidMuSig2Expression)?,
                xpub.wildcard,
            ),
            DescriptorPublicKey::MultiXPub(xpub) => (xpub.derivation_paths, xpub.wildcard),
            _ => unreachable!("Dummy key is always an xpub."),
        };

        if wildcard == descriptor::Wildcard::Hardened
            || derivation_paths
                .paths()
                .iter()
                .flatten()
                .any(|step| !step.is_normal())
        {
            return Err(LianaPolicyError::InvalidMuSig2Expression);
        }

        Ok(Self {
            suffix: suffix.to_owned(),
            derivation_paths,
            wildcard,
        })
    }

    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    pub fn derivation_paths(&self) -> &descriptor::DerivPaths {
        &self.derivation_paths
    }

    pub fn wildcard(&self) -> descriptor::Wildcard {
        self.wildcard
    }
}

impl fmt::Display for AggregateKeyDerivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.suffix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MuSig2KeyExpr {
    participants: Vec<DescriptorPublicKey>,
    derivation_mode: MuSig2DerivationMode,
    aggregate_derivation: Option<AggregateKeyDerivation>,
}

impl MuSig2KeyExpr {
    pub fn from_str(expr: &str) -> Result<Self, LianaPolicyError> {
        let (participants, suffix) = split_musig_expression(expr)?;
        if participants.len() < 2 {
            return Err(LianaPolicyError::InvalidMuSig2ParticipantCount(
                participants.len(),
            ));
        }

        let participants = participants
            .into_iter()
            .map(|key| {
                DescriptorPublicKey::from_str(key)
                    .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let aggregate_derivation = if suffix.is_empty() {
            None
        } else {
            Some(AggregateKeyDerivation::from_suffix(suffix)?)
        };

        if aggregate_derivation.is_some()
            && participants.iter().any(|key| {
                !matches!(
                    key,
                    DescriptorPublicKey::XPub(xpub)
                        if xpub.wildcard == descriptor::Wildcard::None
                            && xpub.derivation_path.as_ref().iter().all(|step| step.is_normal())
                )
            })
        {
            return Err(LianaPolicyError::MixedMuSig2DerivationModes);
        }

        Ok(Self {
            participants,
            derivation_mode: if aggregate_derivation.is_some() {
                MuSig2DerivationMode::AggregateThenDeriveBip328
            } else {
                MuSig2DerivationMode::DeriveThenAggregate
            },
            aggregate_derivation,
        })
    }

    pub fn participants(&self) -> &[DescriptorPublicKey] {
        &self.participants
    }

    pub fn derivation_mode(&self) -> MuSig2DerivationMode {
        self.derivation_mode
    }

    pub fn aggregate_derivation(&self) -> Option<&AggregateKeyDerivation> {
        self.aggregate_derivation.as_ref()
    }
}

impl fmt::Display for MuSig2KeyExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let participants = self
            .participants
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "musig({participants})")?;
        if let Some(aggregate_derivation) = &self.aggregate_derivation {
            write!(f, "{aggregate_derivation}")?;
        }
        Ok(())
    }
}

pub fn dummy_shadow_key() -> DescriptorPublicKey {
    DescriptorPublicKey::from_str(&format!("{DUMMY_XPUB}{DUMMY_SHADOW_SUFFIX}"))
        .expect("valid dummy shadow key")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuSig2TaprootDescriptor {
    expr: MuSig2KeyExpr,
    shadow_desc: Descriptor<DescriptorPublicKey>,
}

impl MuSig2TaprootDescriptor {
    pub fn from_str(descriptor: &str) -> Result<Self, LianaPolicyError> {
        let body = descriptor_body(descriptor)?;
        let (primary_expr, tap_tree) = split_tr_descriptor(body)?;
        let expr = MuSig2KeyExpr::from_str(primary_expr)?;
        let shadow_desc = Descriptor::<DescriptorPublicKey>::from_str(&with_checksum(
            &render_tr_descriptor(&format!("{DUMMY_XPUB}{DUMMY_SHADOW_SUFFIX}"), tap_tree),
        ))
        .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)?;

        Ok(Self { expr, shadow_desc })
    }

    pub fn from_shadow_descriptor(
        shadow_desc: Descriptor<DescriptorPublicKey>,
        expr: MuSig2KeyExpr,
    ) -> Self {
        Self { expr, shadow_desc }
    }

    pub fn expr(&self) -> &MuSig2KeyExpr {
        &self.expr
    }

    pub fn shadow_desc(&self) -> &Descriptor<DescriptorPublicKey> {
        &self.shadow_desc
    }

    pub fn branch_descriptor(
        &self,
        path_index: usize,
    ) -> Result<MuSig2SinglePathDescriptor, LianaPolicyError> {
        let shadow_desc = self
            .shadow_desc
            .clone()
            .into_single_descriptors()
            .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)?
            .into_iter()
            .nth(path_index)
            .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
        let expr = branch_expr(&self.expr, path_index)?;
        Ok(MuSig2SinglePathDescriptor { expr, shadow_desc })
    }
}

impl fmt::Display for MuSig2TaprootDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shadow_string = self.shadow_desc.to_string();
        let body = descriptor_body(&shadow_string).map_err(|_| fmt::Error)?;
        let (_, tap_tree) = split_tr_descriptor(body).map_err(|_| fmt::Error)?;
        f.write_str(&with_checksum(&render_tr_descriptor(
            &self.expr.to_string(),
            tap_tree,
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuSig2SinglePathDescriptor {
    expr: MuSig2KeyExpr,
    shadow_desc: Descriptor<DescriptorPublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuSig2DerivedDescriptor {
    desc: Descriptor<DefiniteDescriptorKey>,
    aggregate_pubkey: secp256k1::PublicKey,
    participant_origins: Vec<(secp256k1::PublicKey, bip32::KeySource)>,
    output_key_origin: Option<bip32::KeySource>,
}

impl MuSig2SinglePathDescriptor {
    pub fn expr(&self) -> &MuSig2KeyExpr {
        &self.expr
    }

    pub fn shadow_desc(&self) -> &Descriptor<DescriptorPublicKey> {
        &self.shadow_desc
    }

    pub fn derive_descriptor(
        &self,
        child_index: u32,
    ) -> Result<Descriptor<DefiniteDescriptorKey>, LianaPolicyError> {
        let shadow_desc = self
            .shadow_desc
            .at_derivation_index(child_index)
            .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)?;
        let shadow_string = shadow_desc.to_string();
        let body = descriptor_body(&shadow_string)?;
        let (_, tap_tree) = split_tr_descriptor(body)?;
        let aggregate_pubkey = derive_aggregate_pubkey(&self.expr, 0, child_index)?;
        Descriptor::<DefiniteDescriptorKey>::from_str(&with_checksum(&render_tr_descriptor(
            &aggregate_pubkey.to_string(),
            tap_tree,
        )))
        .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)
    }

    pub fn derive_psbt_descriptor(
        &self,
        child_index: u32,
    ) -> Result<MuSig2DerivedDescriptor, LianaPolicyError> {
        let desc = self.derive_descriptor(child_index)?;
        let participant_origins = match self.expr.derivation_mode() {
            MuSig2DerivationMode::DeriveThenAggregate => self
                .expr
                .participants()
                .iter()
                .cloned()
                .map(|participant| derive_participant_origin(participant, 0, child_index))
                .collect::<Result<Vec<_>, _>>()?,
            MuSig2DerivationMode::AggregateThenDeriveBip328 => self
                .expr
                .participants()
                .iter()
                .cloned()
                .map(|participant| derive_participant_origin(participant, 0, 0))
                .collect::<Result<Vec<_>, _>>()?,
        };
        let aggregate_pubkey = match self.expr.derivation_mode() {
            MuSig2DerivationMode::DeriveThenAggregate => {
                derive_aggregate_pubkey(&self.expr, 0, child_index)?
            }
            MuSig2DerivationMode::AggregateThenDeriveBip328 => aggregate_sorted_pubkey(
                participant_origins
                    .iter()
                    .map(|(participant, _)| *participant)
                    .collect::<Vec<_>>()
                    .into_iter(),
            )
            .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)?,
        };
        let output_key_origin = match self.expr.derivation_mode() {
            MuSig2DerivationMode::DeriveThenAggregate => None,
            MuSig2DerivationMode::AggregateThenDeriveBip328 => {
                let network = participant_network(
                    self.expr
                        .participants()
                        .first()
                        .ok_or(LianaPolicyError::InvalidMuSig2ParticipantCount(0))?,
                )
                .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
                let synthetic_xpub = bip328_synthetic_xpub(aggregate_pubkey, network);
                let aggregate_derivation = self
                    .expr
                    .aggregate_derivation()
                    .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
                let branch_path = aggregate_derivation
                    .derivation_paths()
                    .paths()
                    .first()
                    .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
                let derivation_path =
                    if aggregate_derivation.wildcard() == descriptor::Wildcard::None {
                        branch_path.clone()
                    } else {
                        branch_path.clone().into_child(
                            bip32::ChildNumber::from_normal_idx(child_index)
                                .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)?,
                        )
                    };
                Some((synthetic_xpub.fingerprint(), derivation_path))
            }
        };

        Ok(MuSig2DerivedDescriptor {
            desc,
            aggregate_pubkey,
            participant_origins,
            output_key_origin,
        })
    }
}

impl fmt::Display for MuSig2SinglePathDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shadow_string = self.shadow_desc.to_string();
        let body = descriptor_body(&shadow_string).map_err(|_| fmt::Error)?;
        let (_, tap_tree) = split_tr_descriptor(body).map_err(|_| fmt::Error)?;
        f.write_str(&with_checksum(&render_tr_descriptor(
            &self.expr.to_string(),
            tap_tree,
        )))
    }
}

impl MuSig2DerivedDescriptor {
    pub fn descriptor(&self) -> &Descriptor<DefiniteDescriptorKey> {
        &self.desc
    }

    pub fn script_pubkey(&self) -> bitcoin::ScriptBuf {
        self.desc.script_pubkey()
    }

    pub fn address(&self, network: bitcoin::Network) -> bitcoin::Address {
        self.desc
            .address(network)
            .expect("A Taproot descriptor always has an address")
    }

    pub fn update_psbt_in(&self, psbt_in: &mut PsbtIn) {
        if let Err(e) = psbt_in.update_with_descriptor_unchecked(&self.desc) {
            log::error!(
                "BUG! Please report this! Error when adding MuSig2 input metadata for desc: {}. Descriptor: {}.",
                e,
                self.desc
            );
        }
        if let (Some(key_origin), Some(tap_internal_key)) =
            (&self.output_key_origin, psbt_in.tap_internal_key)
        {
            let leaf_hashes = psbt_in
                .tap_key_origins
                .get(&tap_internal_key)
                .map(|(leaf_hashes, _)| leaf_hashes.clone())
                .unwrap_or_default();
            psbt_in
                .tap_key_origins
                .insert(tap_internal_key, (leaf_hashes, key_origin.clone()));
        }
        for (participant, origin) in &self.participant_origins {
            psbt_in
                .tap_key_origins
                .entry(participant.x_only_public_key().0)
                .or_insert((vec![], origin.clone()));
        }
        psbt_in.unknown.insert(
            raw::Key {
                type_value: PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
                key: self.aggregate_pubkey.serialize().to_vec(),
            },
            self.participant_origins
                .iter()
                .flat_map(|(participant, _)| participant.serialize())
                .collect(),
        );
    }

    pub fn update_change_psbt_out(&self, psbt_out: &mut PsbtOut) {
        if let Err(e) = psbt_out.update_with_descriptor_unchecked(&self.desc) {
            log::error!(
                "BUG! Please report this! Error when adding MuSig2 output metadata for desc: {}. Descriptor: {}.",
                e,
                self.desc
            );
        }
        if let (Some(key_origin), Some(tap_internal_key)) =
            (&self.output_key_origin, psbt_out.tap_internal_key)
        {
            let leaf_hashes = psbt_out
                .tap_key_origins
                .get(&tap_internal_key)
                .map(|(leaf_hashes, _)| leaf_hashes.clone())
                .unwrap_or_default();
            psbt_out
                .tap_key_origins
                .insert(tap_internal_key, (leaf_hashes, key_origin.clone()));
        }
        for (participant, origin) in &self.participant_origins {
            psbt_out
                .tap_key_origins
                .entry(participant.x_only_public_key().0)
                .or_insert((vec![], origin.clone()));
        }
        psbt_out.unknown.insert(
            raw::Key {
                type_value: PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS,
                key: self.aggregate_pubkey.serialize().to_vec(),
            },
            self.participant_origins
                .iter()
                .flat_map(|(participant, _)| participant.serialize())
                .collect(),
        );
    }
}

pub fn aggregate_plain_pubkey<I>(
    pubkeys: I,
) -> Result<secp256k1::PublicKey, musig2::errors::KeyAggError>
where
    I: IntoIterator<Item = secp256k1::PublicKey>,
{
    let pubkeys = pubkeys
        .into_iter()
        .map(|pubkey| Point::from_slice(&pubkey.serialize()).expect("Valid pubkey bytes"))
        .collect::<Vec<_>>();
    let context = KeyAggContext::new(pubkeys)?;
    let aggregate_pubkey = secp256k1::PublicKey::from_slice(
        &context.aggregated_pubkey_untweaked::<Point>().serialize(),
    )
    .expect("MuSig2 aggregate key is a valid secp256k1 pubkey");
    Ok(aggregate_pubkey)
}

fn aggregate_sorted_pubkey<I>(
    pubkeys: I,
) -> Result<secp256k1::PublicKey, musig2::errors::KeyAggError>
where
    I: IntoIterator<Item = secp256k1::PublicKey>,
{
    let mut pubkeys = pubkeys.into_iter().collect::<Vec<_>>();
    pubkeys.sort();
    aggregate_plain_pubkey(pubkeys.into_iter())
}

pub fn bip328_synthetic_xpub(
    aggregate_pubkey: secp256k1::PublicKey,
    network: bitcoin::Network,
) -> bip32::Xpub {
    bip32::Xpub {
        network: network.into(),
        depth: 0,
        parent_fingerprint: [0; 4].into(),
        child_number: 0.into(),
        public_key: aggregate_pubkey,
        chain_code: BIP328_SYNTHETIC_CHAINCODE.into(),
    }
}

pub fn derive_aggregate_pubkey(
    expr: &MuSig2KeyExpr,
    path_index: usize,
    child_index: u32,
) -> Result<secp256k1::PublicKey, LianaPolicyError> {
    match expr.derivation_mode() {
        MuSig2DerivationMode::DeriveThenAggregate => aggregate_sorted_pubkey(
            expr.participants()
                .iter()
                .cloned()
                .map(|participant| derive_participant_pubkey(participant, path_index, child_index))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter(),
        )
        .map_err(|_| LianaPolicyError::InvalidMuSig2Expression),
        MuSig2DerivationMode::AggregateThenDeriveBip328 => {
            let participant_pubkeys = expr
                .participants()
                .iter()
                .cloned()
                .map(|participant| derive_participant_pubkey(participant, 0, 0))
                .collect::<Result<Vec<_>, _>>()?;
            let aggregate_pubkey = aggregate_sorted_pubkey(participant_pubkeys.into_iter())
                .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)?;
            let network = participant_network(
                expr.participants()
                    .first()
                    .ok_or(LianaPolicyError::InvalidMuSig2ParticipantCount(0))?,
            )
            .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
            let aggregate_derivation = expr
                .aggregate_derivation()
                .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
            let branch_path = aggregate_derivation
                .derivation_paths()
                .paths()
                .get(path_index)
                .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
            let derivation_path = if aggregate_derivation.wildcard() == descriptor::Wildcard::None {
                branch_path.clone()
            } else {
                branch_path.clone().into_child(
                    bip32::ChildNumber::from_normal_idx(child_index)
                        .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)?,
                )
            };
            let secp = secp256k1::Secp256k1::verification_only();
            Ok(bip328_synthetic_xpub(aggregate_pubkey, network)
                .derive_pub(&secp, &derivation_path)
                .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)?
                .public_key)
        }
    }
}

fn derive_participant_pubkey(
    participant: DescriptorPublicKey,
    path_index: usize,
    child_index: u32,
) -> Result<secp256k1::PublicKey, LianaPolicyError> {
    let participant = participant
        .into_single_keys()
        .into_iter()
        .nth(path_index)
        .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
    let definite_key = participant
        .at_derivation_index(child_index)
        .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)?;
    Ok(definite_key.to_public_key().inner)
}

fn derive_participant_origin(
    participant: DescriptorPublicKey,
    path_index: usize,
    child_index: u32,
) -> Result<(secp256k1::PublicKey, bip32::KeySource), LianaPolicyError> {
    let participant = participant
        .into_single_keys()
        .into_iter()
        .nth(path_index)
        .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
    let definite_key = participant
        .at_derivation_index(child_index)
        .map_err(|_| LianaPolicyError::InvalidMuSig2Expression)?;
    let derivation_path = definite_key
        .full_derivation_path()
        .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
    Ok((
        definite_key.to_public_key().inner,
        (definite_key.master_fingerprint(), derivation_path),
    ))
}

fn participant_network(participant: &DescriptorPublicKey) -> Option<bitcoin::Network> {
    match participant {
        DescriptorPublicKey::XPub(xpub) => Some(match xpub.xkey.network {
            bitcoin::NetworkKind::Main => bitcoin::Network::Bitcoin,
            bitcoin::NetworkKind::Test => bitcoin::Network::Testnet,
        }),
        DescriptorPublicKey::MultiXPub(xpub) => Some(match xpub.xkey.network {
            bitcoin::NetworkKind::Main => bitcoin::Network::Bitcoin,
            bitcoin::NetworkKind::Test => bitcoin::Network::Testnet,
        }),
        _ => None,
    }
}

fn split_musig_expression(expr: &str) -> Result<(Vec<&str>, &str), LianaPolicyError> {
    let expr = expr.trim();
    let inner = expr
        .strip_prefix("musig(")
        .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
    let closing_pos = inner
        .find(')')
        .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
    let (participants, suffix) = inner.split_at(closing_pos);
    let suffix = suffix
        .strip_prefix(')')
        .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
    if participants.is_empty() {
        return Err(LianaPolicyError::InvalidMuSig2ParticipantCount(0));
    }
    if suffix.contains(')') {
        return Err(LianaPolicyError::InvalidMuSig2Expression);
    }

    Ok((
        participants
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .collect(),
        suffix,
    ))
}

fn descriptor_body(descriptor: &str) -> Result<&str, LianaPolicyError> {
    let descriptor = descriptor.trim();
    if let Some((body, checksum)) = descriptor.rsplit_once('#') {
        let expected =
            desc_checksum(body).map_err(|_| LianaPolicyError::InvalidMuSig2Expression)?;
        if checksum == expected {
            Ok(body)
        } else {
            Err(LianaPolicyError::InvalidMuSig2Expression)
        }
    } else {
        Ok(descriptor)
    }
}

fn split_tr_descriptor(descriptor: &str) -> Result<(&str, Option<&str>), LianaPolicyError> {
    let inner = descriptor
        .strip_prefix("tr(")
        .and_then(|s| s.strip_suffix(')'))
        .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
    let mut paren_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut split_at = None;
    for (idx, ch) in inner.char_indices() {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            ',' if paren_depth == 0 && brace_depth == 0 => {
                split_at = Some(idx);
                break;
            }
            _ => {}
        }
    }

    if let Some(split_at) = split_at {
        Ok((&inner[..split_at], Some(&inner[split_at + 1..])))
    } else {
        Ok((inner, None))
    }
}

fn render_tr_descriptor(primary_expr: &str, tap_tree: Option<&str>) -> String {
    if let Some(tap_tree) = tap_tree {
        format!("tr({primary_expr},{tap_tree})")
    } else {
        format!("tr({primary_expr})")
    }
}

fn with_checksum(body: &str) -> String {
    let checksum = desc_checksum(body).expect("valid descriptor checksum body");
    format!("{body}#{checksum}")
}

fn branch_expr(expr: &MuSig2KeyExpr, path_index: usize) -> Result<MuSig2KeyExpr, LianaPolicyError> {
    match expr.derivation_mode() {
        MuSig2DerivationMode::DeriveThenAggregate => Ok(MuSig2KeyExpr::from_str(&format!(
            "musig({})",
            expr.participants()
                .iter()
                .cloned()
                .map(|participant| {
                    participant
                        .into_single_keys()
                        .into_iter()
                        .nth(path_index)
                        .map(|key| key.to_string())
                        .ok_or(LianaPolicyError::InvalidMuSig2Expression)
                })
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        ))?),
        MuSig2DerivationMode::AggregateThenDeriveBip328 => {
            let aggregate_derivation = expr
                .aggregate_derivation()
                .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
            let branch_path = aggregate_derivation
                .derivation_paths()
                .paths()
                .get(path_index)
                .ok_or(LianaPolicyError::InvalidMuSig2Expression)?;
            let suffix = format_derivation_suffix(branch_path, aggregate_derivation.wildcard());
            Ok(MuSig2KeyExpr::from_str(&format!(
                "musig({}){suffix}",
                expr.participants()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ))?)
        }
    }
}

fn format_derivation_suffix(
    derivation_path: &bip32::DerivationPath,
    wildcard: descriptor::Wildcard,
) -> String {
    let mut suffix = derivation_path
        .as_ref()
        .iter()
        .map(|child| format!("/{child}"))
        .collect::<String>();
    match wildcard {
        descriptor::Wildcard::None => {}
        descriptor::Wildcard::Unhardened => suffix.push_str("/*"),
        descriptor::Wildcard::Hardened => suffix.push_str("/*'"),
    }
    suffix
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::bitcoin::{key::TweakedPublicKey, Network, XOnlyPublicKey};

    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn parse_derive_then_aggregate_expression() {
        let expr = "musig([8c3ffb6e/48'/1'/0'/2']tpubDEMt3bpQMa99W81K9h8f2FJH1C81eSd6bbSkBP8tcqQHAfSKvuGp2fz6xiVpfShzT9sKPx7DVBphChjxvNd15WcbsCca5oVz1AcUTWHxkdS/<0;1>/*,[8c3ffb6f/48'/1'/0'/2']tpubDEMt3bpQMa99W81K9h8f2FJH1C81eSd6bbSkBP8tcqQHAfSKvuGp2fz6xiVpfShzT9sKPx7DVBphChjxvNd15WcbsCca5oVz1AcUTWHxkdS/<0;1>/*)";
        let musig = MuSig2KeyExpr::from_str(expr).unwrap();

        assert_eq!(
            musig.derivation_mode(),
            MuSig2DerivationMode::DeriveThenAggregate
        );
        assert!(musig.aggregate_derivation().is_none());
        assert_eq!(musig.to_string(), expr);
    }

    #[test]
    fn parse_aggregate_then_derive_expression() {
        let expr = "musig([8c3ffb6e/48'/1'/0'/2']tpubDEMt3bpQMa99W81K9h8f2FJH1C81eSd6bbSkBP8tcqQHAfSKvuGp2fz6xiVpfShzT9sKPx7DVBphChjxvNd15WcbsCca5oVz1AcUTWHxkdS,[8c3ffb6f/48'/1'/0'/2']tpubDEMt3bpQMa99W81K9h8f2FJH1C81eSd6bbSkBP8tcqQHAfSKvuGp2fz6xiVpfShzT9sKPx7DVBphChjxvNd15WcbsCca5oVz1AcUTWHxkdS)/<0;1>/*";
        let musig = MuSig2KeyExpr::from_str(expr).unwrap();

        assert_eq!(
            musig.derivation_mode(),
            MuSig2DerivationMode::AggregateThenDeriveBip328
        );
        assert_eq!(
            musig
                .aggregate_derivation()
                .map(ToString::to_string)
                .as_deref(),
            Some("/<0;1>/*")
        );
        assert_eq!(musig.to_string(), expr);
    }

    #[test]
    fn reject_mixed_modes() {
        let expr = "musig([8c3ffb6e/48'/1'/0'/2']tpubDEMt3bpQMa99W81K9h8f2FJH1C81eSd6bbSkBP8tcqQHAfSKvuGp2fz6xiVpfShzT9sKPx7DVBphChjxvNd15WcbsCca5oVz1AcUTWHxkdS/<0;1>/*,[8c3ffb6f/48'/1'/0'/2']tpubDEMt3bpQMa99W81K9h8f2FJH1C81eSd6bbSkBP8tcqQHAfSKvuGp2fz6xiVpfShzT9sKPx7DVBphChjxvNd15WcbsCca5oVz1AcUTWHxkdS)/<0;1>/*";
        assert!(matches!(
            MuSig2KeyExpr::from_str(expr),
            Err(LianaPolicyError::MixedMuSig2DerivationModes)
        ));
    }

    #[test]
    fn reject_hardened_aggregate_derivation() {
        let expr = "musig([8c3ffb6e/48'/1'/0'/2']tpubDEMt3bpQMa99W81K9h8f2FJH1C81eSd6bbSkBP8tcqQHAfSKvuGp2fz6xiVpfShzT9sKPx7DVBphChjxvNd15WcbsCca5oVz1AcUTWHxkdS,[8c3ffb6f/48'/1'/0'/2']tpubDEMt3bpQMa99W81K9h8f2FJH1C81eSd6bbSkBP8tcqQHAfSKvuGp2fz6xiVpfShzT9sKPx7DVBphChjxvNd15WcbsCca5oVz1AcUTWHxkdS)/0'/*";
        assert!(matches!(
            MuSig2KeyExpr::from_str(expr),
            Err(LianaPolicyError::InvalidMuSig2Expression)
        ));
    }

    #[test]
    fn taproot_descriptor_roundtrip_preserves_musig_expression() {
        let descriptor = "tr(musig([9e1c1983/48'/1'/0'/2']tpubDEWCLCMncbStq4BLXkQUAPqzzrh2tQUgYeQPt4NrB5D7gRraMyGbRqzPTmQGvqfdaFsXDVGSQBRgfXuNjDyfU626pxSjpQZszFNY6CzogxK/<0;1>/*,[3b1913e1/48'/1'/0'/2']tpubDFeZ2ezf4VUuTnjdhxJ1DKhLa2t6vzXZNz8NnEgeT2PN4pPqTCTeWUcaxKHPJcf1C8WzkLA71zSjDwuo4zqu4kkiL91ZUmJydC8f1gx89wM/<0;1>/*),and_v(v:pk([1dce71b2/48'/1'/0'/2']tpubDEeP3GefjqbaDTTaVAF5JkXWhoFxFDXQ9KuhVrMBViFXXNR2B3Lvme2d2AoyiKfzRFZChq2AGMNbU1qTbkBMfNv7WGVXLt2pnYXY87gXqcs/<2;3>/*),older(10)))";
        let musig_desc = MuSig2TaprootDescriptor::from_str(descriptor).unwrap();

        assert_eq!(musig_desc.to_string(), with_checksum(descriptor));
    }

    #[test]
    fn branch_descriptor_preserves_aggregate_mode() {
        let descriptor = "tr(musig([9e1c1983/48'/1'/0'/2']tpubDEWCLCMncbStq4BLXkQUAPqzzrh2tQUgYeQPt4NrB5D7gRraMyGbRqzPTmQGvqfdaFsXDVGSQBRgfXuNjDyfU626pxSjpQZszFNY6CzogxK,[3b1913e1/48'/1'/0'/2']tpubDFeZ2ezf4VUuTnjdhxJ1DKhLa2t6vzXZNz8NnEgeT2PN4pPqTCTeWUcaxKHPJcf1C8WzkLA71zSjDwuo4zqu4kkiL91ZUmJydC8f1gx89wM)/<0;1>/*,and_v(v:pk([1dce71b2/48'/1'/0'/2']tpubDEeP3GefjqbaDTTaVAF5JkXWhoFxFDXQ9KuhVrMBViFXXNR2B3Lvme2d2AoyiKfzRFZChq2AGMNbU1qTbkBMfNv7WGVXLt2pnYXY87gXqcs/<2;3>/*),older(10)))";
        let musig_desc = MuSig2TaprootDescriptor::from_str(descriptor).unwrap();

        assert_eq!(
            musig_desc.branch_descriptor(0).unwrap().to_string(),
            with_checksum("tr(musig([9e1c1983/48'/1'/0'/2']tpubDEWCLCMncbStq4BLXkQUAPqzzrh2tQUgYeQPt4NrB5D7gRraMyGbRqzPTmQGvqfdaFsXDVGSQBRgfXuNjDyfU626pxSjpQZszFNY6CzogxK,[3b1913e1/48'/1'/0'/2']tpubDFeZ2ezf4VUuTnjdhxJ1DKhLa2t6vzXZNz8NnEgeT2PN4pPqTCTeWUcaxKHPJcf1C8WzkLA71zSjDwuo4zqu4kkiL91ZUmJydC8f1gx89wM)/0/*,and_v(v:pk([1dce71b2/48'/1'/0'/2']tpubDEeP3GefjqbaDTTaVAF5JkXWhoFxFDXQ9KuhVrMBViFXXNR2B3Lvme2d2AoyiKfzRFZChq2AGMNbU1qTbkBMfNv7WGVXLt2pnYXY87gXqcs/2/*),older(10)))")
        );
        assert_eq!(
            musig_desc.branch_descriptor(1).unwrap().to_string(),
            with_checksum("tr(musig([9e1c1983/48'/1'/0'/2']tpubDEWCLCMncbStq4BLXkQUAPqzzrh2tQUgYeQPt4NrB5D7gRraMyGbRqzPTmQGvqfdaFsXDVGSQBRgfXuNjDyfU626pxSjpQZszFNY6CzogxK,[3b1913e1/48'/1'/0'/2']tpubDFeZ2ezf4VUuTnjdhxJ1DKhLa2t6vzXZNz8NnEgeT2PN4pPqTCTeWUcaxKHPJcf1C8WzkLA71zSjDwuo4zqu4kkiL91ZUmJydC8f1gx89wM)/1/*,and_v(v:pk([1dce71b2/48'/1'/0'/2']tpubDEeP3GefjqbaDTTaVAF5JkXWhoFxFDXQ9KuhVrMBViFXXNR2B3Lvme2d2AoyiKfzRFZChq2AGMNbU1qTbkBMfNv7WGVXLt2pnYXY87gXqcs/3/*),older(10)))")
        );
    }

    #[test]
    fn derived_descriptor_is_standard_taproot() {
        let descriptor = "tr(musig([9e1c1983/48'/1'/0'/2']tpubDEWCLCMncbStq4BLXkQUAPqzzrh2tQUgYeQPt4NrB5D7gRraMyGbRqzPTmQGvqfdaFsXDVGSQBRgfXuNjDyfU626pxSjpQZszFNY6CzogxK,[3b1913e1/48'/1'/0'/2']tpubDFeZ2ezf4VUuTnjdhxJ1DKhLa2t6vzXZNz8NnEgeT2PN4pPqTCTeWUcaxKHPJcf1C8WzkLA71zSjDwuo4zqu4kkiL91ZUmJydC8f1gx89wM)/<0;1>/*,and_v(v:pk([1dce71b2/48'/1'/0'/2']tpubDEeP3GefjqbaDTTaVAF5JkXWhoFxFDXQ9KuhVrMBViFXXNR2B3Lvme2d2AoyiKfzRFZChq2AGMNbU1qTbkBMfNv7WGVXLt2pnYXY87gXqcs/<2;3>/*),older(10)))";
        let derived = MuSig2TaprootDescriptor::from_str(descriptor)
            .unwrap()
            .branch_descriptor(0)
            .unwrap()
            .derive_descriptor(7)
            .unwrap();

        assert!(matches!(derived, Descriptor::Tr(_)));
        assert!(!derived.to_string().contains("musig("));
    }

    #[test]
    fn bip328_vector_two_keys() {
        let pubkeys = [
            "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
                .parse()
                .unwrap(),
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
                .parse()
                .unwrap(),
        ];
        let aggregate_pubkey = aggregate_plain_pubkey(pubkeys).unwrap();
        assert_eq!(
            aggregate_pubkey.to_string(),
            "0354240c76b8f2999143301a99c7f721ee57eee0bce401df3afeaa9ae218c70f23"
        );
        assert_eq!(
            bip328_synthetic_xpub(aggregate_pubkey, Network::Bitcoin).to_string(),
            "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwXEKGEouzXE6QLLRxjatMcLLzJ5LV5Nib1BN7vJg6yp45yHHRbm"
        );
    }

    #[test]
    fn bip328_vector_four_keys() {
        let pubkeys = [
            "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
                .parse()
                .unwrap(),
            "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66"
                .parse()
                .unwrap(),
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
                .parse()
                .unwrap(),
            "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
                .parse()
                .unwrap(),
        ];
        let aggregate_pubkey = aggregate_plain_pubkey(pubkeys).unwrap();
        assert_eq!(
            aggregate_pubkey.to_string(),
            "022479f134cdb266141dab1a023cbba30a870f8995b95a91fc8464e56a7d41f8ea"
        );
        assert_eq!(
            bip328_synthetic_xpub(aggregate_pubkey, Network::Bitcoin).to_string(),
            "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwUvaZYpysLX4wN59tjwU5pBuDjNrPEJbfxjLwn7ruzbXTcUTHkZ"
        );
    }

    #[test]
    fn bip390_rawtr_vector_aggregate_then_derive() {
        let expr = MuSig2KeyExpr::from_str("musig(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y)/0/*").unwrap();
        let expected_spks = [
            "51209508c08832f3bb9d5e8baf8cb5cfa3669902e2f2da19acea63ff47b93faa9bfc",
            "51205ca1102663025a83dd9b5dbc214762c5a6309af00d48167d2d6483808525a298",
            "51207dbed1b89c338df6a1ae137f133a19cae6e03d481196ee6f1a5c7d1aeb56b166",
        ];

        for (index, expected_spk) in expected_spks.iter().enumerate() {
            let aggregate_pubkey = derive_aggregate_pubkey(&expr, 0, index as u32).unwrap();
            let output_key =
                TweakedPublicKey::dangerous_assume_tweaked(XOnlyPublicKey::from(aggregate_pubkey));
            assert_eq!(
                lower_hex(bitcoin::ScriptBuf::new_p2tr_tweaked(output_key).as_bytes()),
                *expected_spk
            );
        }
    }
}
