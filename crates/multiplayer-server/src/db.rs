use rusqlite::{Connection, params};
use std::sync::Mutex;

pub struct Db {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub token_hash: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: i64,
    pub session_id: String,
    pub user_id: i64,
    pub session_name: String,
    pub join_token_hash: String,
    pub host_wg_public_key: String,
    pub ssh_user: String,
    pub ssh_private_key_b64: String,
    pub wg_interface: String,
    pub subnet_index: i32,
    pub host_address: String,
    pub last_heartbeat: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: i64,
    pub session_id: i64,
    pub wg_public_key: String,
    pub address: String,
    pub peer_index: i32,
}

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Db { conn: Mutex::new(conn) };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let db = Db { conn: Mutex::new(conn) };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                token_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch())
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL REFERENCES users(id),
                session_name TEXT NOT NULL,
                join_token_hash TEXT NOT NULL,
                host_wg_public_key TEXT NOT NULL,
                ssh_user TEXT NOT NULL,
                ssh_private_key_b64 TEXT NOT NULL,
                wg_interface TEXT NOT NULL,
                subnet_index INTEGER NOT NULL,
                host_address TEXT NOT NULL,
                last_heartbeat INTEGER NOT NULL DEFAULT (unixepoch()),
                created_at INTEGER NOT NULL DEFAULT (unixepoch())
            );

            CREATE TABLE IF NOT EXISTS peers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                wg_public_key TEXT NOT NULL,
                address TEXT NOT NULL,
                peer_index INTEGER NOT NULL
            );"
        )?;
        Ok(())
    }

    // -- Users ----------------------------------------------------------------

    pub fn create_user(&self, username: &str, token_hash: &str) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (username, token_hash) VALUES (?1, ?2)",
            params![username, token_hash],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn find_user_by_token_hash(&self, token_hash: &str) -> rusqlite::Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, username, token_hash FROM users WHERE token_hash = ?1"
        )?;
        let mut rows = stmt.query(params![token_hash])?;
        match rows.next()? {
            Some(row) => Ok(Some(User {
                id: row.get(0)?,
                username: row.get(1)?,
                token_hash: row.get(2)?,
            })),
            None => Ok(None),
        }
    }

    pub fn username_exists(&self, username: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM users WHERE username = ?1",
            params![username],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    // -- Sessions -------------------------------------------------------------

    pub fn create_session(
        &self,
        session_id: &str,
        user_id: i64,
        session_name: &str,
        join_token_hash: &str,
        host_wg_public_key: &str,
        ssh_user: &str,
        ssh_private_key_b64: &str,
        wg_interface: &str,
        subnet_index: i32,
        host_address: &str,
    ) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions (session_id, user_id, session_name, join_token_hash,
             host_wg_public_key, ssh_user, ssh_private_key_b64, wg_interface, subnet_index,
             host_address)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                session_id, user_id, session_name, join_token_hash,
                host_wg_public_key, ssh_user, ssh_private_key_b64,
                wg_interface, subnet_index, host_address
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn find_session_by_session_id(&self, session_id: &str) -> rusqlite::Result<Option<Session>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, user_id, session_name, join_token_hash,
             host_wg_public_key, ssh_user, ssh_private_key_b64, wg_interface,
             subnet_index, host_address, last_heartbeat, created_at
             FROM sessions WHERE session_id = ?1"
        )?;
        let mut rows = stmt.query(params![session_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(Session {
                id: row.get(0)?,
                session_id: row.get(1)?,
                user_id: row.get(2)?,
                session_name: row.get(3)?,
                join_token_hash: row.get(4)?,
                host_wg_public_key: row.get(5)?,
                ssh_user: row.get(6)?,
                ssh_private_key_b64: row.get(7)?,
                wg_interface: row.get(8)?,
                subnet_index: row.get(9)?,
                host_address: row.get(10)?,
                last_heartbeat: row.get(11)?,
                created_at: row.get(12)?,
            })),
            None => Ok(None),
        }
    }

    pub fn update_heartbeat(&self, session_id: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "UPDATE sessions SET last_heartbeat = unixepoch() WHERE session_id = ?1",
            params![session_id],
        )?;
        Ok(rows > 0)
    }

    pub fn delete_session(&self, session_id: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "DELETE FROM sessions WHERE session_id = ?1",
            params![session_id],
        )?;
        Ok(rows > 0)
    }

    pub fn find_expired_sessions(&self, max_age_secs: i64) -> rusqlite::Result<Vec<Session>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, user_id, session_name, join_token_hash,
             host_wg_public_key, ssh_user, ssh_private_key_b64, wg_interface,
             subnet_index, host_address, last_heartbeat, created_at
             FROM sessions WHERE (unixepoch() - last_heartbeat) > ?1"
        )?;
        let rows = stmt.query_map(params![max_age_secs], |row| {
            Ok(Session {
                id: row.get(0)?,
                session_id: row.get(1)?,
                user_id: row.get(2)?,
                session_name: row.get(3)?,
                join_token_hash: row.get(4)?,
                host_wg_public_key: row.get(5)?,
                ssh_user: row.get(6)?,
                ssh_private_key_b64: row.get(7)?,
                wg_interface: row.get(8)?,
                subnet_index: row.get(9)?,
                host_address: row.get(10)?,
                last_heartbeat: row.get(11)?,
                created_at: row.get(12)?,
            })
        })?;
        rows.collect()
    }

    pub fn next_subnet_index(&self) -> rusqlite::Result<i32> {
        let conn = self.conn.lock().unwrap();
        let max: Option<i32> = conn.query_row(
            "SELECT MAX(subnet_index) FROM sessions",
            [],
            |row| row.get(0),
        )?;
        Ok(max.map_or(1, |m| m + 1))
    }

    pub fn user_active_session_count(&self, user_id: i64) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE user_id = ?1",
            params![user_id],
            |row| row.get(0),
        )
    }

    // -- Peers ----------------------------------------------------------------

    pub fn add_peer(
        &self,
        session_db_id: i64,
        wg_public_key: &str,
        address: &str,
        peer_index: i32,
    ) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO peers (session_id, wg_public_key, address, peer_index)
             VALUES (?1, ?2, ?3, ?4)",
            params![session_db_id, wg_public_key, address, peer_index],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn next_peer_index(&self, session_db_id: i64) -> rusqlite::Result<i32> {
        let conn = self.conn.lock().unwrap();
        let max: Option<i32> = conn.query_row(
            "SELECT MAX(peer_index) FROM peers WHERE session_id = ?1",
            params![session_db_id],
            |row| row.get(0),
        )?;
        // Peer indices start at 2 (host is 1, server is 254)
        Ok(max.map_or(2, |m| m + 1))
    }

    pub fn peers_for_session(&self, session_db_id: i64) -> rusqlite::Result<Vec<Peer>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, wg_public_key, address, peer_index
             FROM peers WHERE session_id = ?1"
        )?;
        let rows = stmt.query_map(params![session_db_id], |row| {
            Ok(Peer {
                id: row.get(0)?,
                session_id: row.get(1)?,
                wg_public_key: row.get(2)?,
                address: row.get(3)?,
                peer_index: row.get(4)?,
            })
        })?;
        rows.collect()
    }
}
