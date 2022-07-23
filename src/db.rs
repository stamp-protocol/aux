use crate::{
    error::{Result},
    util,
};
use rusqlite::{params, Connection};
use stamp_core::{
    dag::{TransactionID, Transactions},
    identity::IdentityID,
    util::SerdeBinary,
};
use stamp_net::sync::TransactionMessageSigned;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fs;

/// Open a db connection
fn conn() -> Result<Connection> {
    let dir = util::data_dir()?;
    fs::create_dir_all(&dir)?;
    let mut db_file = dir.clone();
    db_file.push("db.sqlite");
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE |
        rusqlite::OpenFlags::SQLITE_OPEN_CREATE |
        rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(&db_file, flags)?;
    Ok(conn)
}

/// Make sure our schema is applied
pub fn ensure_schema() -> Result<()> {
    let conn = conn()?;
    // holds local identities
    conn.execute("CREATE TABLE IF NOT EXISTS identities (id TEXT PRIMARY KEY, nickname TEXT, created TEXT NOT NULL, data BLOB NOT NULL, name_lookup JSON, email_lookup JSON, claim_lookup JSON, stamp_lookup JSON)", params![])?;
    // holds transactions for private syncing
    conn.execute("CREATE TABLE IF NOT EXISTS sync_transactions (transaction_id TEXT PIMARY KEY, identity_id TEXT NOT NULL, data BLOB NOT NULL)", params![])?;
    conn.execute("CREATE INDEX IF NOT EXISTS sync_transactions_identity ON sync_transactions (identity_id)", params![])?;
    Ok(())
}

/// Crappy util to turn a vec of strings into json
fn json_arr(vec: &Vec<String>) -> String {
    format!(r#"["{}"]"#, vec.join(r#"",""#))
}

/// Save an identity to local storage
pub fn save_identity(transactions: Transactions) -> Result<Transactions> {
    let identity = transactions.build_identity()?;
    let id_str = id_str!(identity.id())?;
    let nickname = identity.nickname_maybe();
    let created = format!("{}", identity.created().format("%+"));

    let name_lookup = identity.names();
    let email_lookup = identity.emails();
    let claim_lookup = identity.claims().iter()
        .map(|x| id_str!(x.claim().id()))
        .collect::<Result<Vec<String>>>()?;
    let stamp_lookup = identity.claims().iter()
        .map(|x| {
            x.stamps().iter().map(|x| { id_str!(x.id()) })
        })
        .flatten()
        .collect::<Result<Vec<String>>>()?;

    let serialized = transactions.serialize_binary()?;
    let conn = conn()?;
    conn.execute("BEGIN", params![])?;
    conn.execute("DELETE FROM identities WHERE id = ?1", params![id_str])?;
    conn.execute(
        r#"
            INSERT INTO identities
            (id, nickname, created, data, name_lookup, email_lookup, claim_lookup, stamp_lookup)
            VALUES (?1, ?2, ?3, ?4, json(?5), json(?6), json(?7), json(?8))
        "#,
        params![
            id_str,
            nickname,
            created,
            serialized,
            json_arr(&name_lookup),
            json_arr(&email_lookup),
            json_arr(&claim_lookup),
            json_arr(&stamp_lookup),
        ]
    )?;
    conn.execute("COMMIT", params![])?;
    Ok(transactions)
}

/// Load an identity by ID.
pub fn load_identity(id: &IdentityID) -> Result<Option<Transactions>> {
    let conn = conn()?;
    let id_str = id_str!(id)?;
    let qry_res = conn.query_row(
        "SELECT data FROM identities WHERE id = ?1 ORDER BY created ASC",
        params![id_str],
        |row| row.get(0)
    );
    let blob: Option<Vec<u8>> = match qry_res {
        Ok(blob) => Some(blob),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => Err(e)?,
    };
    match blob {
        Some(data) => {
            let transactions = Transactions::deserialize_binary(data.as_slice())?;
            Ok(Some(transactions))
        }
        None => Ok(None),
    }
}

/// Load an identity by ID.
pub fn load_identities_by_prefix(id_prefix: &str) -> Result<Vec<Transactions>> {
    let conn = conn()?;
    let mut stmt = conn.prepare("SELECT data FROM identities WHERE id like ?1 ORDER BY created ASC")?;
    let rows = stmt.query_map(params![format!("{}%", id_prefix)], |row| row.get(0))?;
    let mut identities = Vec::new();
    for data in rows {
        let data_bin: Vec<u8> = data?;
        let deserialized = Transactions::deserialize_binary(&data_bin)?;
        identities.push(deserialized);
    }
    Ok(identities)
}

/// List identities stored locally.
pub fn list_local_identities(search: Option<&str>) -> Result<Vec<Transactions>> {
    let conn = conn()?;
    let qry = if search.is_some() {
        r#"
            SELECT DISTINCT
                i.id, i.data
            FROM
                identities i,
                json_each(i.name_lookup) jnl,
                json_each(i.email_lookup) jel,
                json_each(i.claim_lookup) jcl,
                json_each(i.stamp_lookup) jsl
            WHERE
                i.id LIKE ?1 OR
                jnl.value LIKE ?1 OR
                jel.value LIKE ?1 OR
                jcl.value LIKE ?1 OR
                jsl.value LIKE ?1
            ORDER BY
                i.created ASC
        "#
    } else {
        r#"SELECT i.id, i.data FROM identities i ORDER BY i.created ASC"#
    };

    let mut stmt = conn.prepare(qry)?;
    let row_mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<_> { row.get(1) };
    let rows = if let Some(search) = search {
        let finder = format!("%{}%", search);
        stmt.query_map(params![finder], row_mapper)?
    } else {
        stmt.query_map(params![], row_mapper)?
    };
    let mut identities = Vec::new();
    for data in rows {
        let data_bin: Vec<u8> = data?;
        let deserialized = Transactions::deserialize_binary(&data_bin)?;
        identities.push(deserialized);
    }
    Ok(identities)
}

pub fn find_identity_by_prefix(ty: &str, id_prefix: &str) -> Result<Option<Transactions>> {
    let conn = conn()?;
    let qry = format!(r#"
        SELECT DISTINCT
            i.id, i.data
        FROM
            identities i,
            json_each(i.{}_lookup) jcl
        WHERE
            jcl.value LIKE ?1
        ORDER BY
            i.created ASC
    "#, ty);

    let finder = format!("{}%", id_prefix);
    let qry_res = conn.query_row(
        &qry,
        params![finder],
        |row| row.get(1)
    );
    let blob: Option<Vec<u8>> = match qry_res {
        Ok(blob) => Some(blob),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => Err(e)?,
    };
    match blob {
        Some(data) => {
            let transactions = Transactions::deserialize_binary(data.as_slice())?;
            Ok(Some(transactions))
        }
        None => Ok(None),
    }
}

/// Delete a local identity by id.
pub fn delete_identity(id: &str) -> Result<()> {
    let conn = conn()?;
    conn.execute("BEGIN", params![])?;
    conn.execute("DELETE FROM identities WHERE id = ?1", params![id])?;
    conn.execute("COMMIT", params![])?;
    Ok(())
}

/// Save a transaction from a private sync record
pub fn save_sync_transaction(id_str: &str, transaction: TransactionMessageSigned) -> Result<TransactionMessageSigned> {
    let serialized = transaction.serialize()?;
    let conn = conn()?;
    let transaction_id = String::from(transaction.transaction().id());
    conn.execute("BEGIN", params![])?;
    conn.execute("DELETE FROM sync_transactions WHERE transaction_id = ?1", params![transaction_id])?;
    conn.execute(
        r#"
            INSERT INTO sync_transactions
            (transaction_id, identity_id, data)
            VALUES (?1, ?2, ?3)
        "#,
        params![
            &transaction_id,
            id_str,
            &serialized,
        ]
    )?;
    conn.execute("COMMIT", params![])?;
    Ok(transaction)
}

/// Find all sync transactions for an identity, excluding the passed list of trans ids.
pub fn find_sync_transactions(id_str: &str, exclude: &Vec<TransactionID>) -> Result<Vec<TransactionMessageSigned>> {
    let conn = conn()?;
    // NOTE: we DO NOT filter out our excluded transaction IDs in the query because
    // rusqlite gets butthurt when we do dynamic params. instead we just filter the
    // results out by hand afterwards. dumb, but it works.
    let qry = r#"
        SELECT
            st.transaction_id, st.data
        FROM
            sync_transactions st
        WHERE
            st.identity_id LIKE ?1
    "#;
    let mut stmt = conn.prepare(qry)?;
    let rows = stmt.query_map(params![format!("{}%", id_str)], |row| -> rusqlite::Result<_> {
        let tid: String = row.get(0)?;
        let data: Vec<u8> = row.get(1)?;
        Ok((tid, data))
    })?;

    let exclude_set = exclude.iter()
        .map(|tid| String::from(tid))
        .collect::<HashSet<_>>();
    let mut transactions = Vec::new();
    for row in rows {
        let (tid, data) = row?;
        if !exclude_set.contains(&tid) {
            let message = TransactionMessageSigned::deserialize(data.as_slice())?;
            transactions.push(message);
        }
    }
    Ok(transactions)
}

