//! Claimlib is a module specifically for verifying certain types of claims
//! immediately by a client. The benefit is that a client doesn't need to rely
//! on third-party stamps or trust to verify a claim: they can immediately
//! determine that trust themselves.
//!
//! Keep in mind, this only applies to specific claims, namely ones in which
//! the claim information is posted somewhere publicly in a location of a
//! system in which we know the protocol. Think, HTTP/DNS.

use stamp_core::{
    identity::{IdentityID, ClaimID, ClaimSpec, Claim},
};
use std::convert::TryFrom;

/// Run an instant check on a claim. This only applies to certain claim types,
/// such as Domain or Url, which can be verified simple by reading publicly
/// available information.
pub fn check(identity_id: &IdentityID, claim: &Claim) -> Result<String, String> {
    let claim_id_str = String::try_from(claim.id())
        .map_err(|e| format!("There was a problem converting the id {:?} to a string: {:?}", claim.id(), e))?;
    let instant_values = claim.instant_verify_allowed_values(identity_id)
        .map_err(|e| format!("Could not get verification values for claim {}: {}", ClaimID::short(&claim_id_str), e))?;
    match claim.spec() {
        ClaimSpec::Domain(maybe) => {
            let domain = maybe.open_public().ok_or(format!("This claim is private, but must be public to be checked."))?;
            unimplemented!();
        }
        ClaimSpec::Url(maybe) => {
            let url = maybe.open_public().ok_or(format!("This claim is private, but must be public to be checked."))?;
            let body = ureq::get(&url.clone().into_string())
                .set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .set("Accept-Language", "en-US,en;q=0.5")
                .set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0")
                .call()
                .map_err(|e| {
                    match e {
                        ureq::Error::Status(code, res) => {
                            let res_str = res.into_string()
                                .unwrap_or_else(|e| format!("Could not map error response to string: {:?}", e));
                            format!("Problem calling GET on {}: {} -- {}", url, code, &res_str[0..std::cmp::min(100, res_str.len())])
                        },
                        _ => format!("Problem calling GET on {}: {}", url, e)
                    }
                })?
                .into_string()
                .map_err(|e| format!("Problem grabbing output of {}: {}", url, e))?;
            let mut found = false;
            for val in instant_values {
                if body.contains(&val) {
                    found = true;
                    break;
                }
            }
            if found {
                Ok(url.into_string())
            } else {
                Err(format!("The URL {} does not contain any of the required values for verification", url))
            }
        }
        _ => Err(format!("Claim checking is only available for domain or URL claim types."))?,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
