// descriptor.rs — import, normalize, validate, checksum.

use std::str::FromStr;

use super::miniscript::{Descriptor, DescriptorPublicKey};
use super::{Error, Result};

/// A parsed + validated Nunchuk-shaped descriptor.
pub struct ParsedDescriptor {
    pub descriptor: Descriptor<DescriptorPublicKey>,
    /// 8-char miniscript checksum (the compact policy fingerprint we show).
    pub checksum: String,
    /// Canonical string including `#checksum`.
    pub canonical: String,
}

/// Import descriptor text. Supports the two shapes Nunchuk emits: P2WSH
/// (`wsh(...)`) and Taproot (`tr(...)`); other forms are rejected with a clear
/// error rather than silently accepted.
pub fn import(text: &str) -> Result<ParsedDescriptor> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(Error::Parse("empty descriptor".into()));
    }

    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(trimmed)
        .map_err(|e| Error::Parse(format!("invalid descriptor: {e}")))?;

    match &descriptor {
        Descriptor::Wsh(_) | Descriptor::Tr(_) => {}
        other => {
            return Err(Error::Unsupported(format!(
                "only P2WSH (wsh) and Taproot (tr) Nunchuk descriptors are supported, got: {}",
                kind_name(other)
            )))
        }
    }

    let canonical = descriptor.to_string();
    let checksum = canonical
        .rsplit('#')
        .next()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| Error::Parse("descriptor has no checksum".into()))?
        .to_string();

    Ok(ParsedDescriptor { descriptor, checksum, canonical })
}

fn kind_name(d: &Descriptor<DescriptorPublicKey>) -> &'static str {
    match d {
        Descriptor::Bare(_) => "bare",
        Descriptor::Pkh(_) => "pkh",
        Descriptor::Wpkh(_) => "wpkh",
        Descriptor::Sh(_) => "sh",
        Descriptor::Wsh(_) => "wsh",
        Descriptor::Tr(_) => "tr",
    }
}
