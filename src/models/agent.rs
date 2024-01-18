/*
use axum::{
    routing::get,
    Router,
};
use crate::{
    db,
    error::Result,
    util::UIMessage,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc::Sender;
use tower_http::trace::TraceLayer;
use tracing::{info, error};

pub(crate) mod routes {
    //pub(crate) fn get_owned_identities() -> 
}

/// Run the Stamp agent. This allows third-party applications to securely manage subkeys
/// and create various transaction types.
#[tracing::instrument(skip(port, lock_after, notifications))]
pub async fn run(port: u32, lock_after: u64, notifications: Sender<UIMessage>) -> Result<()> {
    let not1 = notifications.clone();
    let app = Router::new()
        .route("/v1/identities", get(|| async move {
            //let ids = db::list_local_identities(None)
            //    .map_err(|e| format!("error listing identities: {}", e))?
            //    .iter()
            //    .filter(|x| x.is_owned())
            //    .collect::<Vec<_>>();
            //Ok(ids)
            not1.send(UIMessage::Notification { title: "New request".into(), body: "Turtl requires a key".into(), icon: None }).await
                .unwrap_or_else(|e| error!("Cannot send notification: {}", e));
            "Get a job."
        }))
        .layer(TraceLayer::new_for_http());
    info!("Listening -- port {}", port);
    axum::Server::bind(&format!("127.0.0.1:{}", port).parse().unwrap())
        .serve(app.into_make_service())
        .await
        .map_err(axum::Error::new)?;
    Ok(())
}
*/

