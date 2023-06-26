use crate::{
    config,
    db,
    error::{Error, Result},
};
use stamp_core::{
    crypto::base::{Hash, HashAlgo, SecretKey, SignKeypair, CryptoKeypair},
    dag::{Transaction, TransactionBody, Transactions},
    identity::{
        Identity,
        IdentityID,
        claim::{ClaimSpec},
        keychain::{ExtendKeypair, AdminKey, AdminKeypair, Key}
    },
    policy::{Capability, MultisigPolicy, Policy},
    private::{PrivateWithMac, MaybePrivate},
    util::{Timestamp, SerdeBinary},
};
use std::convert::TryFrom;
use std::ops::Deref;

/// Given an identity, master key, and transaction, find the admin key in the identity
/// most optimal for signing this particular transaction.
pub fn sign_with_optimal_key(identity: &Identity, master_key: &SecretKey, transaction: Transaction) -> Result<Transaction> {
    // The current strategy is to just use the first key that has permissions.
    for admin in identity.keychain().admin_keys() {
        let signed = transaction.clone().sign(master_key, admin)?;
        if signed.verify(Some(identity)).is_ok() {
            return Ok(signed);
        }
    }
    Err(Error::AdminKeyNotFound)
}

pub fn post_new_personal_id(master_key: &SecretKey, transactions: Transactions, hash_with: &HashAlgo, name: Option<String>, email: Option<String>) -> Result<Transactions> {
    // ask if they want name/email claims, then add three default subkeys (sign,
    // crypto, secret) to their keychain.
    let subkey_sign = SignKeypair::new_ed25519(&master_key)?;
    let subkey_crypto = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key)?;
    let subkey_secret = PrivateWithMac::seal(&master_key, SecretKey::new_xchacha20poly1305()?)?;
    let identity = transactions.build_identity()?;
    macro_rules! sign_and_push {
        ($transactions:expr, $([ $fn:ident, $($args:expr),* ])*) => {{
            let mut trans_tmp = $transactions;
            $(
                let trans = trans_tmp.$fn($($args),*)?;
                let trans_signed = sign_with_optimal_key(&identity, master_key, trans)?;
                trans_tmp = trans_tmp.push_transaction(trans_signed)?;
            )*
            trans_tmp
        }};
    }

    let transactions = sign_and_push! { transactions,
        [ make_claim, hash_with, Timestamp::now(), ClaimSpec::Identity(MaybePrivate::new_public(identity.id().clone())), None::<&str> ]
    };
    let transactions = match name {
        Some(name) => {
            sign_and_push! { transactions,
                [ make_claim, hash_with, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public(name)), None::<&str> ]
            }
        }
        None => transactions,
    };
    let transactions = match email {
        Some(email) => {
            sign_and_push! { transactions,
                [ make_claim, hash_with, Timestamp::now(), ClaimSpec::Email(MaybePrivate::new_public(email)), None::<&str> ]
            }
        }
        None => transactions,
    };
    let transactions = sign_and_push! { transactions,
        [ add_subkey, hash_with, Timestamp::now(), Key::new_sign(subkey_sign), "default/sign", Some("A default key for signing documents or messages.") ]
        [ add_subkey, hash_with, Timestamp::now(), Key::new_crypto(subkey_crypto), "default/crypto", Some("A default key for receiving private messages.") ]
        [ add_subkey, hash_with, Timestamp::now(), Key::new_secret(subkey_secret), "default/secret", Some("A default key allowing encryption/decryption of personal data.") ]
    };
    let transactions = db::save_identity(transactions)?;
    let mut conf = config::load()?;
    if conf.default_identity.is_none() {
        let id_str = id_str!(identity.id())?;
        conf.default_identity = Some(id_str);
        config::save(&conf)?;
    }
    Ok(transactions)
}

/// Create a new random personal identity.
pub fn create_personal_random(master_key: &SecretKey, hash_with: &HashAlgo, now: Timestamp) -> Result<Transactions> {
    let admin = AdminKey::new(AdminKeypair::new_ed25519(&master_key)?, "alpha", Some("Your main admin key"));
    let policy = Policy::new(
        vec![Capability::Permissive],
        MultisigPolicy::MOfN { must_have: 1, participants: vec![admin.clone().into()] },
    );
    let transactions = Transactions::new();
    let genesis = transactions
        .create_identity(hash_with, now.clone(), vec![admin.clone()], vec![policy])?
        .sign(master_key, &admin)?;
    let transactions2 = transactions.push_transaction(genesis)?;
    Ok(transactions2)
}

/// Create a new vanity identity, where the resulting string ID matches a pre-
/// determined pattern.
pub fn create_personal_vanity<F>(hash_with: &HashAlgo, regex: Option<&str>, contains: Vec<&str>, prefix: Option<&str>, mut progress: F) -> Result<(SecretKey, Transactions, Timestamp)>
    where F: FnMut(u64),
{
    let mut counter: u64 = 0;
    let regex = if let Some(re) = regex {
        Some(regex::Regex::new(re)?)
    } else {
        None
    };
    let mut filter = |id_str: &str| -> bool {
        counter += 1;
        if counter % 1000 == 0 {
            progress(counter);
        }
        if let Some(regex) = regex.as_ref() {
            if !regex.is_match(id_str) {
                return false;
            }
        }
        if let Some(prefix) = prefix {
            if !id_str.starts_with(prefix) {
                return false;
            }
        }
        for needle in &contains {
            if !id_str.contains(needle) {
                return false;
            }
        }
        return true;
    };

    let mut now;
    let mut genesis_transaction;
    let tmp_master_key = SecretKey::new_xchacha20poly1305()?;
    let empty = Transactions::new();
    loop {
        now = Timestamp::now();
        let admin = AdminKey::new(AdminKeypair::new_ed25519(&tmp_master_key)?, "alpha", Some("Your main admin key"));
        let policy = Policy::new(
            vec![Capability::Permissive],
            MultisigPolicy::MOfN { must_have: 1, participants: vec![admin.clone().into()] },
        );
        genesis_transaction = empty.create_identity(hash_with, now.clone(), vec![admin.clone()], vec![policy])?;
        let based = id_str!(genesis_transaction.id())?;
        if filter(&based) {
            genesis_transaction = genesis_transaction.sign(&tmp_master_key, &admin)?;
            break;
        }
    }
    let transactions = empty.push_transaction(genesis_transaction)?;
    Ok((tmp_master_key, transactions, now))
}

/// Does the legwork of importing, but stops before actually saving the identity
/// so that if there is an existing identity with the same ID the user can
/// decide what to do. Basically, just call [crate::db::save_identity][db::save_identity]
/// if you want to go through with the import. Easy.
pub fn import_pre(contents: &[u8]) -> Result<(Transactions, Option<Transactions>)> {
    // first try importing an owned identity
    let imported = Transactions::deserialize_binary(contents)
        .or_else(|_| {
            let trans = Transaction::deserialize_binary(contents)?;
            match trans.entry().body() {
                TransactionBody::PublishV1 { transactions } => {
                    Ok(*(transactions.clone()))
                }
                _ => Err(Error::DeserializeFailure),
            }
        })?;
    let identity = imported.build_identity()?;
    let exists = db::load_identity(identity.id())?;
    if let Some(existing) = exists.as_ref() {
        if existing.is_owned() && !identity.is_owned() {
            Err(Error::Conflict("You are attempting to overwrite an existing owned identity with a public identity, which will erase all of your private data.".into()))?;
        }
    }
    Ok((imported, exists))
}

/// Takes an identity id and returns a 256x256 pixel-"art" SVG that acts as the fingerprint (a
/// sloppily unique-ish icon/pictogram) for that identity.
///
/// The idea here is that if I have the identity ID "andrew-a90s8d7fhasdf_as9d7afs876" and someone
/// wants to impersonate me and generates "andrew-a90x987fa0df987_znaksndf" most people will not
/// be able to immediately discern the difference. The fingerprint allows a very quick visual
/// indicator that (hopefully) provides enough uniqueness across various identities that two
/// similar identity IDs will have wildly different fingerprints.
///
/// Of course, it's possible that two identities with strikingly-similar IDs will also have
/// strikingly-similar fingerprints. But there's only so much we can do here.
pub fn fingerprint(identity_id: &IdentityID) -> Result<Vec<(u8, u8, [u8; 3])>> {
    let hash = Hash::new_blake2b_256(identity_id.deref().deref().as_bytes())?;
    let hash_bytes = hash.as_bytes();
    let hash_color = Hash::new_blake2b_256(hash.as_bytes())?;
    let hash_color_bytes = hash_color.as_bytes();

    struct Hsl {
        h_grav: Vec<i16>,
    }

    impl Hsl {
        fn new(h_grav_initial: Vec<u64>) -> Self {
            let mut h_grav_mod = h_grav_initial.into_iter()
                .map(|x| (x % 256) as i16)
                .collect::<Vec<i16>>();
            h_grav_mod.sort();
            let mut h_grav = Vec::with_capacity(h_grav_mod.len() + 2);
            if let Some(last) = h_grav_mod.last() {
                h_grav.push(last - 256)
            }
            let first = h_grav_mod.first().map(|x| x.clone());
            for x in h_grav_mod {
                h_grav.push(x);
            }
            if let Some(first) = first {
                h_grav.push(first + 256);
            }
            Self { h_grav }
        }

        fn to_rgb(h: f32, s: f32, l: f32) -> [u8; 3] {
            let (r, g, b) = if s == 0.0 {
                (l, l, l)
            } else {
                let one_third = 1.0 / 3.0;
                let hue_to_rgb = |p, q, t| {
                    let t = if t < 0.0 {
                        t + 1.0
                    } else if t > 1.0 {
                        t - 1.0
                    } else {
                        t
                    };
                    if t < (1.0/6.0) {
                        return p + (q - p) * 6.0 * t;
                    } else if t < (1.0/2.0) {
                        return q;
                    } else if t < (2.0/3.0) {
                        return p + (q - p) * ((2.0 / 3.0) - t) * 6.0;
                    } else {
                        return p;
                    }
                };
                let q = if l < 0.5 { l * (1.0 + s) } else { l + s - l * s };
                let p = 2.0 * l - q;
                (
                    hue_to_rgb(p, q, h + one_third),
                    hue_to_rgb(p, q, h),
                    hue_to_rgb(p, q, h - one_third),
                )
            };
            return [(r * 255.0).round() as u8, (g * 255.0).round() as u8, (b * 255.0).round() as u8];
        }

        fn disp(&self, h: u8, s: f32, l: f32) -> [u8; 3] {
            let mut gravved = self.h_grav.iter()
                .map(|g| (g, (h as i16 - g).abs()))
                .collect::<Vec<_>>();
            gravved.sort_by_key(|x| x.1);
            let h_gravved_255 = (gravved[0].0 + 256) % 256;
            Self::to_rgb(h_gravved_255 as f32 / 255.0, s, l)
        }
    }

    let split_val = |val: u8| {
        (val & 0xf, (val >> 4) & 0xf)
    };

    let hsl_buckets = 2;
    let mut buckets = vec![0; hsl_buckets];
    let mut idx = 0;
    for v in hash_color_bytes {
        buckets[idx % hsl_buckets] += *v as u64;
        idx += 1;
    }
    let hsl = Hsl::new(buckets);

    let mirror_x = true;
    let mirror_y = true;
    let hsl_saturation = 0.7;
    let hsl_lightness = 0.6;

    let mut points = vec![];
    let mut idx = 0;
    for h in hash_bytes {
        let (x, y) = split_val(*h);
        let color_val = hash_color_bytes[idx];
        let color = hsl.disp(color_val, hsl_saturation, hsl_lightness);
        points.push((x, y, color.clone()));
        if mirror_x {
            points.push((15 - x, y, color.clone()));
        }
        if mirror_y {
            points.push((x, 15 - y, color.clone()));
        }
        if mirror_x && mirror_y {
            points.push((15 - x, 15 - y, color.clone()));
        }
        idx += 1;
    }

    Ok(points)
}

/*
pub fn export_private(id: &str) -> Result<Vec<u8>, String> {
    let identity = try_load_single_identity(id)?;
    let serialized = identity.serialize_binary()
        .map_err(|e| format!("There was a problem serializing the identity: {:?}", e))?;
    Ok(serialized)
}

pub fn delete(search: &str, skip_confirm: bool, verbose: bool) -> Result<(), String> {
    let identities = db::list_local_identities(Some(search))?;
    if identities.len() == 0 {
        Err(format!("No identities match that search"))?;
    }
    let identities = identities.into_iter()
        .map(|x| util::build_identity(&x))
        .collect::<Result<Vec<_>, String>>()?;
    print_identities_table(&identities, verbose);
    if !skip_confirm {
        let msg = format!("Permanently delete these {} identities? [y/N]", identities.len());
        if !util::yesno_prompt(&msg, "n")? {
            return Ok(());
        }
    }
    let id_len = identities.len();
    for identity in identities {
        let id = id_str!(identity.id())?;
        db::delete_identity(&id)?;
    }
    println!("Deleted {} identities", id_len);
    Ok(())
}

pub fn view(search: &str) -> Result<String, String> {
    let identities = db::list_local_identities(Some(search))?;
    if identities.len() > 1 {
        let identities = identities.iter()
            .map(|x| util::build_identity(&x))
            .collect::<Result<Vec<_>, String>>()?;
        print_identities_table(&identities, false);
        Err(format!("Multiple identities matched that search"))?;
    } else if identities.len() == 0 {
        Err(format!("No identities match that search"))?;
    }
    let transactions = identities[0].clone();
    let identity = util::build_identity(&transactions)?;
    let serialized = identity.serialize()
        .map_err(|e| format!("Problem serializing identity: {:?}", e))?;
    Ok(serialized)
}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use stamp_core::{
        crypto::base::Hash,
        dag::{TransactionID},
    };

    #[test]
    fn fingerprint_svg() {
        let seed = b"as3dffe";
        let identity_id = IdentityID::from(TransactionID::from(Hash::new_blake2b_512(seed).unwrap()));
        let fp = fingerprint(&identity_id).unwrap();
        println!("---\n{:?}", fp);
    }
}

