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

use async_std::{channel, task};
use crate::{
    config::{self, NetConfig},
    db,
    error::{Error, Result},
};
use stamp_core::{
    crypto::key::{SecretKey, SignKeypair, SignKeypairPublic},
    dag::{TransactionID, Transactions},
    identity::{
        keychain::{Key, RevocationReason},
    },
    private::Private,
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
use tracing::{debug, error, info};

/// Returns a private syncing key ([SecretKey][stamp_core::crypto::key::SecretKey])
/// and private syncing token token (an HMAC of our secret key and identity id). If
/// this key doesn't exist, we generate it and save it into the identity then use it
/// to generate the token.
///
/// Note that this function does NOT save the identity! It's up the to caller to
/// save the identity after return.
pub fn gen_token(master_key: &SecretKey, transactions: Transactions, do_regen: Option<RevocationReason>) -> Result<(Transactions, Key, SignKeypairPublic)> {
    let identity = transactions.build_identity()?;

    let is_regen = do_regen.is_some();
    let regen = |transactions: Transactions| -> Result<(Transactions, Key)> {
        let sync_key_maybe = identity.keychain()
            .subkey_by_name("stamp/sync");
        let now = Timestamp::now();
        let secretkey = SecretKey::new_xchacha20poly1305()?;
        let key = Key::new_secret(Private::seal(master_key, &secretkey)?);
        let new_key = |transactions: Transactions| -> stamp_core::error::Result<Transactions> {
            transactions
                .add_subkey(master_key, now.clone(), key.clone(), "stamp/sync", Some("The key used for syncing your private identity between your devices"))
        };
        let transactions = if sync_key_maybe.is_some() {
            // revoke it if it exists, then add it again
            new_key(
                transactions
                    .revoke_subkey(master_key, now.clone(), "stamp/sync", do_regen.unwrap_or(RevocationReason::Superseded), Some(&format!("revoked/stamp/sync/{}", now.timestamp())))?
            )?
        } else {
            new_key(transactions)?
        };
        Ok((transactions, key))
    };

    let (transactions, key) = if is_regen {
        regen(transactions)?
    } else {
        let sync_key_maybe = identity.keychain()
            .subkey_by_name("stamp/sync")
            .map(|s| s.key().clone());
        if let Some(sync_key) = sync_key_maybe {
            (transactions, sync_key)
        } else {
            regen(transactions)?
        }
    };

    let seckey = key.as_secretkey()
        .ok_or(Error::KeygenFailed)?
        .open(master_key)?;
    let sign_keypair = SignKeypair::new_ed25519_from_secret_key(&seckey, &seckey)?;
    let pubkey = SignKeypairPublic::from(sign_keypair);
    Ok((transactions, key, pubkey))
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
            let transactions = load_identity_by_prefix(identity_id)?;
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
#[tracing::instrument(skip(identity_id, shared_key))]
fn save_transaction(identity_id: &str, shared_key: &Option<SecretKey>, msg: TransactionMessageSigned) -> Result<()> {
    match shared_key {
        Some(seckey) => {
            let mut transactions = load_identity_by_prefix(identity_id)?;
            let exists = transactions.iter().find(|t| t.id() == msg.transaction().id());
            if exists.is_some() {
                return Ok(());
            }
            let transaction_versioned = msg.open(seckey)?;
            transactions.push_transaction_raw(transaction_versioned)?;
            transactions.build_identity()?;
            // TODO: decrypt and save into the identity
        }
        None => {
            db::save_sync_transaction(identity_id, msg)?;
        }
    }
    Ok(())
}

/// Process a sync event.
#[tracing::instrument(skip(event, identity_id, shared_key, sync_signkey, sync_incoming_send))]
async fn process_sync_event(event: sync::Event, identity_id: &str, shared_key: &Option<SecretKey>, sync_signkey: &Option<SignKeypair>, sync_incoming_send: &channel::Sender<sync::Command>) -> Result<()> {
    debug!("event: {}", event);
    match event {
        sync::Event::IdentityTransaction(msg) => {
            // if the transaction is valid and we have a shared key,
            // decrypt the transaction and push it onto the stinkin
            // list. otherwise, save the raw (encrypted) transaction
            // into the sync store.
            let id = String::from(msg.transaction().id());
            info!("Saving identity transaction: {}", id);
            match save_transaction(identity_id, shared_key, msg) {
                Err(e) => error!("Error saving identity transaction {}: {}", id, e),
                _ => {}
            }
        }
        sync::Event::MaybeRequestIdentity => {
            match request_identity(identity_id, shared_key) {
                Ok(req) => {
                    debug!("Requesting identity {} (have {} transactions)", identity_id, req.already_have().len());
                    match sync_incoming_send.send(sync::Command::RequestIdentity(req)).await {
                        Err(e) => error!("Error sending identity request: {}", e),
                        _ => {}
                    }
                }
                Err(e) => error!("Error grabbing identity transactions for request: {}", e),
            }
        }
        sync::Event::RequestIdentity(req) => {
            match load_local_transactions(identity_id, shared_key, sync_signkey, req.already_have()) {
                Ok(signed_messages) => {
                    for message in signed_messages {
                        match sync_incoming_send.send(sync::Command::SendTransaction(message)).await {
                            Err(e) => error!("Error sending transaction message: {}", e),
                            _ => {}
                        }
                    }
                }
                Err(e) => error!("Error loading transaction messages: {}", e),
            }
        }
        _ => {}
    }
    Ok(())
}

/// Create a long-lived sync listener.
///
/// This will join the larger StampNet network if given a set of nodes to join
/// and will help other nodes' discovery via DHT.
#[tracing::instrument(skip(id_str, channel, shared_key, bind, join))]
pub fn listen(id_str: &str, channel: &str, shared_key: Option<SecretKey>, bind: Multiaddr, join: Vec<Multiaddr>) -> Result<()> {
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
        .map(|seckey| SignKeypair::new_ed25519_from_secret_key(&seckey, &seckey))
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
    let (core_incoming_send, core_incoming_recv) = channel::bounded::<core::Command>(16);
    let (core_outgoing_send, core_outgoing_recv) = channel::bounded::<core::Event>(16);
    let (sync_incoming_send, sync_incoming_recv) = channel::bounded::<sync::Command>(16);
    let (sync_outgoing_send, sync_outgoing_recv) = channel::bounded::<sync::Event>(16);
    let channel = String::from(channel);
    let identity_id = String::from(id_str);
    async_std::task::block_on(async move {
        let runner = task::spawn(async move {
            stamp_net::core::run(swarm, core_incoming_recv, core_outgoing_send).await
        });
        // this MITMs the core events and spits out sync events (and takes sync commands)
        let syncer = task::spawn(async move {
            stamp_net::sync::run(&channel, &sync_pubkey, core_incoming_send, core_outgoing_recv, sync_incoming_recv, sync_outgoing_send).await
        });
        let events = task::spawn(async move {
            loop {
                let event = sync_outgoing_recv.recv().await?;
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
        runner.await?;
        syncer.await?;
        events.await?;
        Ok(())
    })
}

