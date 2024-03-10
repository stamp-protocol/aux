//! Claimlib is a module specifically for verifying certain types of claims
//! immediately by a client. The benefit is that a client doesn't need to rely
//! on third-party stamps or trust to verify a claim: they can immediately
//! determine that trust themselves.
//!
//! Keep in mind, this only applies to specific claims, namely ones in which
//! the claim information is posted somewhere publicly in a location of a
//! system in which we know the protocol. Think, HTTP/DNS.

use crate::error::{Error, Result};
use resolve::record::Txt;
use resolve::{DnsConfig, DnsResolver};
use stamp_core::{
    crypto::{
        base::{rng, HashAlgo, SecretKey},
        private::MaybePrivate,
    },
    dag::{Transaction, Transactions},
    identity::{
        claim::{Claim, ClaimSpec, Relationship, RelationshipType},
        IdentityID,
    },
    rasn::{Decode, Encode},
    util::{BinaryVec, Date, Timestamp, Url},
};
use std::convert::TryFrom;
use std::str::FromStr;

/// How many bytes a photo can be
pub const MAX_PHOTO_BYTES: usize = 8192;

fn claim_post(transactions: &Transactions, hash_with: &HashAlgo, spec: ClaimSpec, name: Option<&str>) -> Result<Transaction> {
    Ok(transactions.make_claim(hash_with, Timestamp::now(), spec, name)?)
}

fn maybe_private<T>(master_key: &SecretKey, private: bool, value: T) -> Result<MaybePrivate<T>>
where
    T: Clone + Encode + Decode,
{
    let maybe = if private {
        let mut rng = rng::chacha20();
        MaybePrivate::new_private(&mut rng, &master_key, value)?
    } else {
        MaybePrivate::new_public(value)
    };
    Ok(maybe)
}

pub fn new_id(
    master_key: &SecretKey,
    transactions: &Transactions,
    hash_with: &HashAlgo,
    value: String,
    private: bool,
    name: Option<&str>,
) -> Result<Transaction> {
    let id = IdentityID::try_from(value.as_str())?;
    let maybe = maybe_private(&master_key, private, id)?;
    let spec = ClaimSpec::Identity(maybe);
    claim_post(transactions, hash_with, spec, name)
}

pub fn new_name(
    master_key: &SecretKey,
    transactions: &Transactions,
    hash_with: &HashAlgo,
    value: String,
    private: bool,
    name: Option<&str>,
) -> Result<Transaction> {
    let maybe = maybe_private(&master_key, private, value)?;
    let spec = ClaimSpec::Name(maybe);
    claim_post(transactions, hash_with, spec, name)
}

pub fn new_birthday(
    master_key: &SecretKey,
    transactions: &Transactions,
    hash_with: &HashAlgo,
    value: String,
    private: bool,
    name: Option<&str>,
) -> Result<Transaction> {
    let dob = Date::from_str(&value)?;
    let maybe = maybe_private(&master_key, private, dob)?;
    let spec = ClaimSpec::Birthday(maybe);
    claim_post(transactions, hash_with, spec, name)
}

pub fn new_email(
    master_key: &SecretKey,
    transactions: &Transactions,
    hash_with: &HashAlgo,
    value: String,
    private: bool,
    name: Option<&str>,
) -> Result<Transaction> {
    let maybe = maybe_private(&master_key, private, value)?;
    let spec = ClaimSpec::Email(maybe);
    claim_post(transactions, hash_with, spec, name)
}

pub fn new_photo(
    master_key: &SecretKey,
    transactions: &Transactions,
    hash_with: &HashAlgo,
    photo_bytes: Vec<u8>,
    private: bool,
    name: Option<&str>,
) -> Result<Transaction> {
    if photo_bytes.len() > MAX_PHOTO_BYTES {
        Err(Error::TooBig(format!(
            "Please choose a photo smaller than {} bytes (given photo is {} bytes)",
            MAX_PHOTO_BYTES,
            photo_bytes.len()
        )))?;
    }
    let maybe = maybe_private(&master_key, private, BinaryVec::from(photo_bytes))?;
    let spec = ClaimSpec::Photo(maybe);
    claim_post(transactions, hash_with, spec, name)
}

pub fn new_pgp(
    master_key: &SecretKey,
    transactions: &Transactions,
    hash_with: &HashAlgo,
    value: String,
    private: bool,
    name: Option<&str>,
) -> Result<Transaction> {
    let maybe = maybe_private(&master_key, private, value)?;
    let spec = ClaimSpec::Pgp(maybe);
    claim_post(transactions, hash_with, spec, name)
}

pub fn new_domain(
    master_key: &SecretKey,
    transactions: &Transactions,
    hash_with: &HashAlgo,
    value: String,
    private: bool,
    name: Option<&str>,
) -> Result<Transaction> {
    let maybe = maybe_private(&master_key, private, value.clone())?;
    let spec = ClaimSpec::Domain(maybe);
    claim_post(transactions, hash_with, spec, name)
}

pub fn new_url(
    master_key: &SecretKey,
    transactions: &Transactions,
    hash_with: &HashAlgo,
    value: String,
    private: bool,
    name: Option<&str>,
) -> Result<Transaction> {
    let url = Url::parse(&value)?;
    let maybe = maybe_private(&master_key, private, url)?;
    let spec = ClaimSpec::Url(maybe);
    claim_post(transactions, hash_with, spec, name)
}

pub fn new_address(
    master_key: &SecretKey,
    transactions: &Transactions,
    hash_with: &HashAlgo,
    value: String,
    private: bool,
    name: Option<&str>,
) -> Result<Transaction> {
    let maybe = maybe_private(&master_key, private, value)?;
    let spec = ClaimSpec::Address(maybe);
    claim_post(transactions, hash_with, spec, name)
}

pub fn new_phone(
    master_key: &SecretKey,
    transactions: &Transactions,
    hash_with: &HashAlgo,
    value: String,
    private: bool,
    name: Option<&str>,
) -> Result<Transaction> {
    let maybe = maybe_private(&master_key, private, value)?;
    let spec = ClaimSpec::PhoneNumber(maybe);
    claim_post(transactions, hash_with, spec, name)
}

pub fn new_relation(
    master_key: &SecretKey,
    transactions: &Transactions,
    hash_with: &HashAlgo,
    reltype: RelationshipType,
    value: String,
    private: bool,
    name: Option<&str>,
) -> Result<Transaction> {
    let rel_id = IdentityID::try_from(value.as_str())?;
    let relationship = Relationship::new(reltype, rel_id);
    let maybe = maybe_private(&master_key, private, relationship)?;
    let spec = ClaimSpec::Relation(maybe);
    claim_post(transactions, hash_with, spec, name)
}

/// Rename a claim.
pub fn rename(transactions: &Transactions, hash_with: &HashAlgo, claim_id: &str, name: Option<&str>) -> Result<Transaction> {
    let identity = transactions.build_identity()?;
    let id_str = id_str!(identity.id())?;
    let mut found: Option<Claim> = None;
    for claim in identity.claims() {
        let id_str = id_str!(claim.id())?;
        if id_str.starts_with(claim_id) {
            found = Some(claim.clone());
            break;
        }
    }
    let claim = found.ok_or(Error::NotFound(format!("Cannot find the claim {} in identity {}", claim_id, id_str)))?;
    Ok(transactions.edit_claim(hash_with, Timestamp::now(), claim.id().clone(), name)?)
}

/// Create a transaction to delete a claim, if the claim exists and stuff.
pub fn delete(transactions: &Transactions, hash_with: &HashAlgo, claim_id: &str) -> Result<Transaction> {
    let identity = transactions.build_identity()?;
    let id_str = id_str!(identity.id())?;
    let mut found: Option<Claim> = None;
    for claim in identity.claims() {
        let id_str = id_str!(claim.id())?;
        if id_str.starts_with(claim_id) {
            found = Some(claim.clone());
            break;
        }
    }
    let claim = found.ok_or(Error::NotFound(format!("Cannot find the claim {} in identity {}", claim_id, id_str)))?;
    Ok(transactions.delete_claim(hash_with, Timestamp::now(), claim.id().clone())?)
}

/// Run an instant check on a claim. This only applies to certain claim types,
/// such as Domain or Url, which can be verified simple by reading publicly
/// available information.
pub fn check_claim(transactions: &Transactions, claim: &Claim) -> Result<String> {
    let identity = transactions.build_identity()?;
    let identity_id = identity.id();
    let instant_values = claim.instant_verify_allowed_values(identity_id)?;
    match claim.spec() {
        ClaimSpec::Domain(maybe) => {
            let domain = maybe
                .open_public()
                .ok_or(Error::ClaimCheckFail(format!("This claim is private, but must be public to be checked.")))?;
            let config = DnsConfig::load_default()?;
            let resolver = DnsResolver::new(config)?;
            let records = resolver.resolve_record::<Txt>(&domain)?;
            let mut found = false;
            for record in records {
                let body = match String::from_utf8(record.data.clone()) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                for val in &instant_values {
                    if body.contains(val) {
                        found = true;
                        break;
                    }
                }
            }
            if found {
                Ok(domain)
            } else {
                Err(Error::ClaimCheckFail(format!(
                    "The domain {} does not contain any of the required values for verification",
                    domain
                )))
            }
        }
        ClaimSpec::Url(maybe) => {
            let url = maybe
                .open_public()
                .ok_or(Error::ClaimCheckFail(format!("This claim is private, but must be public to be checked.")))?;
            let body = ureq::get(&String::from(url.clone()))
                .set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .set("Accept-Language", "en-US,en;q=0.5")
                .set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0")
                .call()
                .map_err(|e| match e {
                    ureq::Error::Status(code, res) => {
                        let res_str = res
                            .into_string()
                            .unwrap_or_else(|e| format!("Could not map error response to string: {:?}", e));
                        Error::ClaimCheckFail(format!(
                            "Problem calling GET on {}: {} -- {}",
                            url,
                            code,
                            &res_str[0..std::cmp::min(100, res_str.len())]
                        ))
                    }
                    _ => Error::ClaimCheckFail(format!("Problem calling GET on {}: {}", url, e)),
                })?
                .into_string()
                .map_err(|e| Error::ClaimCheckFail(format!("Problem grabbing output of {}: {}", url, e)))?;
            let mut found = false;
            for val in instant_values {
                if body.contains(&val) {
                    found = true;
                    break;
                }
            }
            if found {
                Ok(url.into())
            } else {
                Err(Error::ClaimCheckFail(format!(
                    "The URL {} does not contain any of the required values for verification",
                    url
                )))
            }
        }
        _ => Err(Error::ClaimCheckFail(format!("Claim checking is only available for domain or URL claim types.")))?,
    }
}
