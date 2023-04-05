use crate::{
    config,
    db,
    error::{Error, Result},
};
use stamp_core::{
    crypto::base::{HashAlgo, SecretKey, SignKeypair, CryptoKeypair},
    dag::{Transaction, TransactionBody, Transactions},
    identity::{ExtendKeypair, AdminKey, AdminKeypair, Key, ClaimSpec, Identity},
    policy::{Capability, MultisigPolicy, Policy},
    private::{PrivateWithMac, MaybePrivate},
    util::{Timestamp, SerdeBinary},
};
use std::convert::TryFrom;

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

