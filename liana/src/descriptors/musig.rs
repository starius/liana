use std::{fmt, str::FromStr};

use miniscript::descriptor::{self, DescriptorPublicKey};

use super::{LianaPolicyError, MuSig2DerivationMode};

const DUMMY_XPUB: &str = "[8c3ffb6e/48'/1'/0'/2']tpubDEMt3bpQMa99W81K9h8f2FJH1C81eSd6bbSkBP8tcqQHAfSKvuGp2fz6xiVpfShzT9sKPx7DVBphChjxvNd15WcbsCca5oVz1AcUTWHxkdS";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
