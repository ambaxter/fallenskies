use super::Argon2Config;
use anyhow::Result;
use rksuid::rksuid;
use serde::Serialize;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgPool, Row};
use tracing::instrument;

#[derive(Serialize, FromRow)]
pub struct Account {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
}

impl Account {
    #[instrument(skip(username, pool))]
    pub async fn username_exists(username: &str, pool: &PgPool) -> Result<bool> {
        let rec = sqlx::query("SELECT EXISTS(SELECT 1 FROM accounts where username = $1)")
            .bind(username)
            .map(|row: PgRow| row.get(0))
            .fetch_one(*&pool)
            .await
            .map_err(|e| {
                tracing::error!("{}", e);
                e
            })?;
        Ok(rec)
    }

    #[instrument(skip(username, password, argon_config, pool))]
    pub async fn password_check(
        username: &str,
        password: &str,
        argon_config: &Argon2Config,
        pool: &PgPool,
    ) -> Result<bool> {
        let rec: Option<String> =
            sqlx::query("SELECT password_hash FROM accounts WHERE username = $1")
                .bind(username)
                .map(|row: PgRow| row.get(0))
                .fetch_optional(*&pool)
                .await
                .map_err(|e| {
                    tracing::error!("{}", e);
                    e
                })?;
        if let Some(hash) = rec {
            let passwords_match = argon_config.verify_encoded(&hash, password)?;
            Ok(passwords_match)
        } else {
            Ok(false)
        }
    }

    #[instrument(skip(username, password, argon_config, pool))]
    pub async fn create(
        username: &str,
        password: &str,
        argon_config: &Argon2Config,
        pool: &PgPool,
    ) -> Result<i64> {
        let password_hash = argon_config.hash_encoded(password)?;
        let mut tx = pool.begin().await?;
        let account = sqlx::query(
            "INSERT INTO accounts (username, password_hash) VALUES ($1, $2) RETURNING id",
        )
        .bind(username)
        .bind(&password_hash)
        .map(|row: PgRow| row.get(0))
        .fetch_one(&mut tx)
        .await
        .map_err(|e| {
            tracing::error!("{}", e);
            e
        })?;
        tx.commit().await?;
        Ok(account)
    }
}

#[derive(Serialize, FromRow)]
pub struct UserSession {
    pub id: i64,
    pub accounts_id: i64,
    pub session_id: String,
}

impl UserSession {
    #[instrument(skip(username, session_id, pool))]
    pub async fn validate_session(username: &str, session_id: &str, pool: &PgPool) -> Result<bool> {
        rksuid::deserialize(session_id);
        let rec: Option<(Option<i64>, Option<i64>)> = sqlx::query("SELECT sessions.id, accounts.id FROM sessions LEFT OUTER JOIN accounts ON accounts.id = sessions.accounts_id where accounts.username = $1 AND sessions.session_id = $2")
            .bind(username)
            .bind(session_id)
            .map(|row: PgRow| (row.get(0), row.get(1)))
            .fetch_optional(*&pool)
            .await
            .map_err(|e| {
                tracing::error!("{}", e);
                e
            })?;
        match rec {
            Some((Some(_), Some(_))) => Ok(true),
            _ => Ok(false),
        }
    }

    #[instrument(skip(username, password, argon_config, pool))]
    pub async fn login(
        username: &str,
        password: &str,
        argon_config: &Argon2Config,
        pool: &PgPool,
    ) -> Result<Option<String>> {
        let rec: Option<(i64, String)> =
            sqlx::query("SELECT id, password_hash FROM accounts WHERE username = $1")
                .bind(username)
                .map(|row: PgRow| (row.get(0), row.get(1)))
                .fetch_optional(*&pool)
                .await
                .map_err(|e| {
                    tracing::error!("{}", e);
                    e
                })?;
        if let Some((accounts_id, hash)) = rec {
            let passwords_match = argon_config.verify_encoded(&hash, password)?;
            if passwords_match {
                let tx = pool.begin().await?;
                let session_id = rksuid::new(None, None).serialize();
                sqlx::query("INSERT INTO sessions (accounts_id, session_id) VALUES ($1, $2) ON CONFLICT (accounts_id) DO UPDATE SET session_id = $2")
                    .bind(accounts_id)
                    .bind(&session_id)
                    .execute(*&pool)
                    .await
                    .map_err(|e| {
                        tracing::error!("{}", e);
                        e
                    })?;
                tx.commit().await?;
                return Ok(Some(session_id));
            }
        }
        Ok(None)
    }
}
