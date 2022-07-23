use crate::{
    config,
    db,
    error::{Error, Result},
};
use stamp_core::{
    crypto::key::{SecretKey, SignKeypair, CryptoKeypair},
    dag::Transactions,
    identity::{ExtendKeypair, AlphaKeypair, PolicyKeypair, PublishKeypair, RootKeypair, Key, IdentityID, ClaimSpec, PublishedIdentity},
    private::{Private, MaybePrivate},
    util::{Timestamp, SerdeBinary},
};
use std::convert::TryFrom;
use std::ops::Deref;

pub fn post_new_id(master_key: &SecretKey, transactions: Transactions, name: Option<String>, email: Option<String>) -> Result<Transactions> {
    // ask if they want name/email claims, then add three default subkeys (sign,
    // crypto, secret) to their keychain.
    let subkey_sign = SignKeypair::new_ed25519(&master_key)?;
    let subkey_crypto = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key)?;
    let subkey_secret = Private::seal(&master_key, &SecretKey::new_xchacha20poly1305()?)?;
    let identity = transactions.build_identity()?;
    let transactions = transactions
        .make_claim(&master_key, Timestamp::now(), ClaimSpec::Identity(identity.id().clone()))?;
    let transactions = match name {
        Some(name) => transactions.make_claim(master_key, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public(name)))?,
        None => transactions,
    };
    let transactions = match email {
        Some(email) => transactions.make_claim(master_key, Timestamp::now(), ClaimSpec::Email(MaybePrivate::new_public(email)))?,
        None => transactions,
    };
    let transactions = transactions
        .add_subkey(master_key, Timestamp::now(), Key::new_sign(subkey_sign), "default/sign", Some("A default key for signing documents or messages."))?
        .add_subkey(master_key, Timestamp::now(), Key::new_crypto(subkey_crypto), "default/crypto", Some("A default key for receiving private messages."))?
        .add_subkey(master_key, Timestamp::now(), Key::new_secret(subkey_secret), "default/secret", Some("A default key allowing encryption/decryption of personal data."))?;
    let transactions = db::save_identity(transactions)?;
    let mut conf = config::load()?;
    if conf.default_identity.is_none() {
        let id_str = id_str!(identity.id())?;
        conf.default_identity = Some(id_str);
        config::save(&conf)?;
    }
    Ok(transactions)
}

/// Create a new random identity.
pub fn new(master_key: &SecretKey, now: Timestamp) -> Result<Transactions> {
    let alpha = AlphaKeypair::new_ed25519(&master_key)?;
    let policy = PolicyKeypair::new_ed25519(&master_key)?;
    let publish = PublishKeypair::new_ed25519(&master_key)?;
    let root = RootKeypair::new_ed25519(&master_key)?;
    let transactions = Transactions::new()
        .create_identity(&master_key, now, alpha, policy, publish, root)?;
    Ok(transactions)
}

/// Create a new vanity identity, where the resulting string ID matches a pre-
/// determined pattern.
pub fn create_vanity<F>(regex: Option<&str>, contains: Vec<&str>, prefix: Option<&str>, mut progress: F) -> Result<(SecretKey, Transactions, Timestamp)>
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
    let mut transactions;
    let tmp_master_key = SecretKey::new_xchacha20poly1305()?;
    let policy_keypair = PolicyKeypair::new_ed25519(&tmp_master_key)?;
    let publish_keypair = PublishKeypair::new_ed25519(&tmp_master_key)?;
    let root_keypair = RootKeypair::new_ed25519(&tmp_master_key)?;
    loop {
        now = Timestamp::now();
        let alpha_keypair = AlphaKeypair::new_ed25519(&tmp_master_key)?;
        transactions = Transactions::new()
            .create_identity(&tmp_master_key, now.clone(), alpha_keypair, policy_keypair.clone(), publish_keypair.clone(), root_keypair.clone())?;
        let id = IdentityID::from(transactions.transactions()[0].id().deref().clone());
        let based = id_str!(&id)?;
        if filter(&based) {
            break;
        }
    }
    Ok((tmp_master_key, transactions, now))
}

/// Does the legwork of importing, but stops before actually saving the identity
/// so that if there is an exissting identity with the same ID the user can
/// decide what to do. Basically, just call [crate::db::save_identity][db::save_identity]
/// if you want to go through with the import. Easy.
pub fn import_pre(contents: &[u8]) -> Result<(Transactions, Option<Transactions>)> {
    // first try importing an owned identity
    let imported = Transactions::deserialize_binary(contents)
        .or_else(|_| {
            PublishedIdentity::deserialize(contents)
                .map(|x| x.identity().clone())
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

