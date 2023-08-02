//! The sync model abstracts a number of functions related to initializing and
//! operating a private sync pool.
//!
//! The idea here is that while you may want to publish your public identity to
//! stampnet, you also want to seamlessly sync your private identity across your
//! devices privately, in private, such that only authorized peers can access this
//! private data (which is private).
//!
//! This is accomplished by twice-encrypting the DAG transactions in the identity:
//! once as a way to secure all peers on this private sync network and again such
//! that an even smaller subset of peers on this network can *decrypt* the DAG
//! transactions. This allows setting up non-decrypting ("blind") peers that can
//! live on public/cloud servers and act as message-passers but don't have access
//! to the data itself.

use crate::{
    config::{self, NetConfig},
    db,
    error::{Error, Result},
};
use stamp_core::{
    crypto::base::{Hash, HashAlgo, SecretKey, SignKeypair, SignKeypairPublic},
    dag::{Transaction, TransactionID, Transactions},
    identity::{
        keychain::{Key},
    },
    private::PrivateWithMac,
    util::{Timestamp},
};
use stamp_net::{
    core::{self},
    sync::{self, TransactionMessageSigned},
    Multiaddr, Protocol,
};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::{task, time, sync::mpsc as channel};
use tracing::{debug, error, info, warn};

/// Turns a secret key into a signing keypair.
pub fn shared_key_to_sign_key(seckey: &SecretKey) -> Result<SignKeypair> {
    let hash = Hash::new_blake2b_256(seckey.as_ref())?;
    let seed: [u8; 32] = hash.as_bytes().try_into().map_err(|_| Error::ConversionError)?;
    Ok(SignKeypair::new_ed25519_from_seed(&seckey, &seed)?)
}

/// Turns a secret key into a sync channel (the channel is actually a base64
/// representation of a public key).
pub fn shared_key_to_channel(seckey: &SecretKey) -> Result<String> {
    let sign_keypair = shared_key_to_sign_key(seckey)?;
    let pubkey = SignKeypairPublic::from(sign_keypair.clone());
    let pubkey_ser = pubkey.serialize()?;
    let channel = stamp_core::util::base64_encode(&pubkey_ser);
    Ok(channel)
}

/// Returns a private syncing key ([SecretKey][stamp_core::crypto::key::SecretKey])
/// and private syncing token (a MAC of our secret key and identity id). If
/// this key doesn't exist, we generate it and save it into the identity then use it
/// to generate the token.
pub fn gen_token(master_key: &SecretKey, transactions: &Transactions, hash_with: &HashAlgo) -> Result<(Option<Transaction>, SecretKey)> {
    let identity = transactions.build_identity()?;

    let sync_key_maybe = identity.keychain()
        .subkey_by_name("stamp/sync")
        .filter(|k| k.revocation().is_none())
        .map(|s| s.key().clone());
    let (staged, key) = if let Some(sync_key) = sync_key_maybe {
        (None, sync_key)
    } else {
        let now = Timestamp::now();
        let secretkey = SecretKey::new_xchacha20poly1305()?;
        let key = Key::new_secret(PrivateWithMac::seal(master_key, secretkey)?);
        let transaction = transactions
            .add_subkey(hash_with, now.clone(), key.clone(), "stamp/sync", Some("The key used for syncing your private identity between your devices"))?;
        (Some(transaction), key)
    };

    let seckey = key.as_secretkey()
        .ok_or(Error::KeygenFailed)?
        .open_and_verify(master_key)?;
    Ok((staged, seckey))
}

/// Do two main things:
/// 
/// 1. Take our join list, and override the list we have in our config if any are given
/// (we make no attempt to merge them, it's either-or). Then save the list back into
/// our config.
/// 2. Loop over the join list and resolve any DNS references in the Multiaddr objects,
/// replacing with their resolved ip addressed
///
/// Then we return the resolved list.
fn process_joinlist(join: Vec<Multiaddr>) -> Result<Vec<Multiaddr>> {
    // if we specified joins, use those, otherwise load them from config. note
    // that we make no attempt to merge the two lists in any way.
    let mut conf = config::load()?;
    let mut net_conf = conf.net.unwrap_or_else(|| NetConfig::default());
    let join_list = if join.len() > 0 {
        join
    } else {
        net_conf.join_list.iter()
            .map(|j| Multiaddr::from_str(j).map_err(|_| Error::ConversionError))
            .collect::<Result<Vec<_>>>()?
    };
    let mut resolved = Vec::with_capacity(join_list.len());
    for addr in &join_list {
        let mut new_addr = Multiaddr::empty();
        for part in addr.iter() {
            match part {
                Protocol::Ip4(_) | Protocol::Ip6(_) | Protocol::Tcp(_) | Protocol::P2p(_) | Protocol::P2pCircuit => {
                    new_addr.push(part);
                }
                Protocol::Dns(val) | Protocol::Dns4(val) | Protocol::Dns6(val) | Protocol::Dnsaddr(val) => {
                    let mut ip_iter = resolve::resolve_host(&val)?;
                    if let Some(ip) = ip_iter.next() {
                        match &ip {
                            IpAddr::V4(ip) => new_addr.push(Protocol::Ip4(ip.clone())),
                            IpAddr::V6(ip) => new_addr.push(Protocol::Ip6(ip.clone())),
                        }
                    } else {
                        Err(Error::DnsLookupFailure(String::from(val)))?;
                    }
                }
                _ => Err(Error::InvalidProtocol(format!("invalid protocol in join address {}", addr)))?,
            }
        }
        resolved.push(new_addr);
    }
    // save our join list back into the config (could be either the original list from
    // the config or the list we passed in).
    net_conf.join_list = join_list.into_iter().map(|x| format!("{}", x)).collect::<Vec<_>>();
    conf.net = Some(net_conf);
    config::save(&conf)?;
    Ok(resolved)
}

/// Given an identity id prefix, find a single matching identity.
pub fn load_identity_by_prefix(identity_id: &str) -> Result<Transactions> {
    let identities = db::load_identities_by_prefix(identity_id)?;
    if identities.len() > 1 {
        Err(Error::IdentityCollision(String::from(identity_id)))?;
    } else if identities.len() == 0 {
        Err(Error::NotFound(String::from(identity_id)))?;
    }
    let transactions = identities.into_iter().next()
        .ok_or_else(|| Error::NotFound(String::from(identity_id)))?;
    Ok(transactions)
}

/// Load local transactions for a given identity for transport to our peers who
/// need them.
///
/// If we have a signing key, we grab transactions from the locally saved identity
/// and encrypt them. If we have no such key, we pull encrypted transactions from
/// our local syncing table and forward them verbatim.
#[tracing::instrument(skip(shared_key, sync_signkey, exclude))]
fn load_local_transactions(identity_id: &str, shared_key: &Option<SecretKey>, sync_signkey: &Option<SignKeypair>, exclude: &Vec<TransactionID>) -> Result<Vec<TransactionMessageSigned>> {
    match (&shared_key, &sync_signkey) {
        (Some(seckey), Some(signkey)) => {
            let transactions = match load_identity_by_prefix(identity_id) {
                Ok(trans) => trans,
                Err(Error::NotFound(_)) => return Ok(Vec::new()),
                Err(e) => Err(e)?,
            };
            let exclude_set = exclude.iter().collect::<HashSet<_>>();
            transactions.transactions().iter()
                .filter(|t| !exclude_set.contains(t.id()))
                .map(|t| TransactionMessageSigned::seal_and_sign(seckey, signkey, t).map_err(|e| Error::from(e)))
                .collect::<Result<Vec<_>>>()
        }
        _ => {
            db::find_sync_transactions(identity_id, exclude)
        }
    }
}

/// Create a request to ask for any identity transactions we do not already have.
#[tracing::instrument(skip(identity_id, shared_key))]
fn request_identity(identity_id: &str, shared_key: &Option<SecretKey>) -> Result<sync::IdentityRequest> {
    match &shared_key {
        Some(_) => {
            let already_have = match load_identity_by_prefix(identity_id) {
                Ok(transactions) => {
                    transactions.transactions().iter()
                        .map(|t| t.id().clone())
                        .collect::<Vec<_>>()
                }
                Err(Error::NotFound(..)) => Vec::new(),
                Err(e) => Err(e)?,
            };
            Ok(sync::IdentityRequest::new(already_have))
        }
        None => {
            let transaction_messages = db::find_sync_transactions(identity_id, &vec![])?;
            let already_have = transaction_messages.iter()
                .map(|t| t.transaction().id().clone())
                .collect::<Vec<_>>();
            Ok(sync::IdentityRequest::new(already_have))
        }
    }
}

/// Save a transaction we got from someone else that we don't already have.
#[tracing::instrument(skip(identity_id, shared_key, transaction_messages))]
fn save_transactions(identity_id: &str, shared_key: &Option<SecretKey>, transaction_messages: Vec<TransactionMessageSigned>) -> Result<usize> {
    match shared_key {
        Some(seckey) => {
            let mut transactions = match load_identity_by_prefix(identity_id) {
                Ok(transactions) => transactions,
                Err(Error::NotFound(..)) => Transactions::new(),
                Err(e) => Err(e)?,
            };
            let trans_set = transactions.iter()
                .map(|t| t.id().clone())
                .collect::<HashSet<_>>();
            let filtered = transaction_messages.into_iter()
                .filter(|t| !trans_set.contains(t.transaction().id()))
                .collect::<Vec<_>>();
            let save_len = filtered.len();
            for trans_raw in filtered {
                let transaction_versioned = trans_raw.open(seckey)?;
                transactions.push_transaction_raw(transaction_versioned)?;
            }
            transactions.build_identity()?;
            db::save_identity(transactions)?;
            info!("Saved {} transactions", save_len);
            Ok(save_len)
        }
        None => {
            let len = transaction_messages.len();
            for trans_raw in transaction_messages {
                db::save_sync_transaction(identity_id, trans_raw)?;
            }
            Ok(len)
        }
    }
}

enum ProcessResult {
    Other,
    RequestedIdentity,
    SavedTransactions(usize),
    SentTransactions(usize),
    Subscribed,
    Unsubscribed,
}

/// Process a sync event.
#[tracing::instrument(skip(event, identity_id, shared_key, sync_signkey, sync_incoming_send))]
async fn process_sync_event(event: sync::Event, identity_id: &str, shared_key: &Option<SecretKey>, sync_signkey: &Option<SignKeypair>, sync_incoming_send: &channel::Sender<sync::Command>) -> Result<ProcessResult> {
    debug!("event: listen: {}", event);
    let mut res = ProcessResult::Other;
    macro_rules! do_request_identity {
        () => {
            match request_identity(identity_id, shared_key) {
                Ok(req) => {
                    debug!("Requesting identity {} from peers (have {} transactions)", identity_id, req.already_have().len());
                    match sync_incoming_send.send(sync::Command::RequestIdentity(req)).await {
                        Err(e) => error!("Error sending identity request: {}", e),
                        _ => {
                            res = ProcessResult::RequestedIdentity;
                        }
                    }
                }
                Err(e) => error!("Error grabbing identity transactions for request: {}", e),
            }
        }
    }
    match event {
        sync::Event::IdentityTransactions(transactions) => {
            // if the transaction is valid and we have a shared key,
            // decrypt the transaction and push it onto the stinkin
            // list. otherwise, save the raw (encrypted) transaction
            // into the sync store.
            if transactions.len() > 0 {
                info!("Got {} identity transactions from peers, saving", transactions.len());
                match save_transactions(identity_id, shared_key, transactions) {
                    Ok(len) => {
                        if len > 0 {
                            res = ProcessResult::SavedTransactions(len);
                        }
                    }
                    Err(e) => error!("Error saving identity transactions: {}", e),
                }
            }
        }
        sync::Event::MaybeRequestIdentity => {
            do_request_identity!()
        }
        sync::Event::RequestIdentity(req) => {
            match load_local_transactions(identity_id, shared_key, sync_signkey, req.already_have()) {
                Ok(signed_messages) => {
                    if signed_messages.len() > 0 {
                        let msg_len = signed_messages.len();
                        info!("Publishing {} identity transactions to peers", msg_len);
                        match sync_incoming_send.send(sync::Command::SendTransactions(signed_messages)).await {
                            Err(e) => error!("Error sending transaction message: {}", e),
                            _ => {
                                res = ProcessResult::SentTransactions(msg_len);
                            }
                        }
                    }
                }
                Err(e) => error!("Error loading transaction messages: {}", e),
            }
        }
        sync::Event::Subscribed { topic } => {
            info!("Subscribed to topic {}", topic);
            res = ProcessResult::Subscribed;
            do_request_identity!()
        }
        sync::Event::Unsubscribed { topic } => {
            res = ProcessResult::Unsubscribed;
            info!("Unsubscribed from topic {}", topic);
        }
        _ => {}
    }
    Ok(res)
}

/// Create a long-lived sync listener.
///
/// This will join the larger StampNet network if given a set of nodes to join
/// and will help other nodes' discovery via DHT.
#[tracing::instrument(skip(id_str, channel, shared_key, bind, join))]
pub async fn listen(id_str: &str, channel: &str, shared_key: Option<SecretKey>, bind: Multiaddr, join: Vec<Multiaddr>) -> Result<()> {
    for part in bind.iter() {
        if !matches!(part, Protocol::Ip4(_) | Protocol::Ip6(_) | Protocol::Tcp(_)) {
            Err(Error::InvalidProtocol(String::from("can only bind to ipv4/ipv6/tcp")))?;
        }
    }

    // our channel is also a base64-serialized public key that can be used to
    // verify transaction parts signed by full nodes.
    let key_bytes = stamp_core::util::base64_decode(channel)?;
    let sync_pubkey = SignKeypairPublic::deserialize(&key_bytes)?;
    let sync_signkey = shared_key.as_ref()
        .map(|seckey| shared_key_to_sign_key(seckey))
        .transpose()?;

    let resolved = process_joinlist(join)?;
    let local_key = stamp_net::random_peer_key();

    info!("Listening -- id: {} / channel: {}", id_str, channel);
    let mut swarm = stamp_net::setup(local_key, true)?;
    swarm.listen_on(bind)
        .map_err(|e| stamp_net::Error::Transport(format!("{}", e)))?;
    for address in &resolved {
        match swarm.dial(address.clone()) {
            Ok(_) => info!("Dialed {:?}", address),
            Err(e) => error!("Dial {:?} failed: {:?}", address, e),
        };
    }
    let (core_incoming_send, core_incoming_recv) = channel::channel::<core::Command>(16);
    let (core_outgoing_send, core_outgoing_recv) = channel::channel::<core::Event>(16);
    let (sync_incoming_send, sync_incoming_recv) = channel::channel::<sync::Command>(16);
    let (sync_outgoing_send, mut sync_outgoing_recv) = channel::channel::<sync::Event>(16);
    let channel = String::from(channel);
    let identity_id = String::from(id_str);
    let runner = task::spawn(async move {
        stamp_net::core::run(swarm, core_incoming_recv, core_outgoing_send).await
    });
    // this MITMs the core events and spits out sync events (and takes sync commands)
    let syncer = task::spawn(async move {
        stamp_net::sync::run(&channel, &sync_pubkey, core_incoming_send, core_outgoing_recv, sync_incoming_recv, sync_outgoing_send).await
    });
    let events = task::spawn(async move {
        loop {
            let event = match sync_outgoing_recv.recv().await {
                Some(x) => x,
                None => break,
            };
            if matches!(event, sync::Event::Quit) {
                break;
            }
            match process_sync_event(event, identity_id.as_str(), &shared_key, &sync_signkey, &sync_incoming_send).await {
                Err(e) => error!("Problem processing incoming event: {}", e),
                _ => {}
            }
        }
        Ok::<(), Error>(())
    });
    runner.await??;
    syncer.await??;
    events.await??;
    Ok(())
}

