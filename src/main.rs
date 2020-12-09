extern crate actix_web;
extern crate argon2;
extern crate dotenv;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
#[macro_use]
extern crate erased_serde;

use actix_files::Files;
use actix_session::CookieSession;
use actix_web::cookie::SameSite;
use actix_web::{
    web, App, HttpServer,
};
use anyhow::Context;
use base64;
use dotenv::dotenv;
use handlebars::Handlebars;
use listenfd::ListenFd;
use sqlx::postgres::PgPool;
use std::env;
use tracing;
use tracing_actix_web::TracingLogger;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Registry};

mod fs;
use fs::Argon2Builder;

// TODO: Character Creation, World creation, Yahweh Dance
fn base64_decode_env(var: &str) -> anyhow::Result<Vec<u8>> {
    let encoded = env::var(var).with_context(|| format!("{} not set in .env file", var))?;
    let decoded = base64::decode(encoded).with_context(|| format!("{} not base64 encoded", var))?;
    Ok(decoded)
}

fn base64_decode_opt_env(var: &str) -> anyhow::Result<Vec<u8>> {
    let encoded = env::var(var).unwrap_or_else(|_| String::new());
    if !encoded.is_empty() {
        let decoded =
            base64::decode(encoded).with_context(|| format!("{} not base64 encoded", var))?;
        Ok(decoded)
    } else {
        Ok(Vec::new())
    }
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    // this will enable us to keep application running during recompile: systemfd --no-pid -s http::5000 -- cargo watch -x run
    let mut listenfd = ListenFd::from_env();

    // Needs to be in main for some reason
    LogTracer::init().expect("Unable to setup log tracer!");
    let app_name = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION")).to_string();
    let (non_blocking_writer, _guard) = tracing_appender::non_blocking(std::io::stdout());
    let bunyan_formatting_layer = BunyanFormattingLayer::new(app_name, non_blocking_writer);
    let subscriber = Registry::default()
        .with(EnvFilter::new("INFO"))
        .with(JsonStorageLayer)
        .with(bunyan_formatting_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL not set in .env file");
    let db_pool = PgPool::connect(&database_url)
        .await
        .expect("Unable to connect to database");

    let password_salt = base64_decode_env("PASSWORD_SALT")?;
    let argon_secret = base64_decode_opt_env("ARGON_SECRET")?;
    let argon_associated_data = base64_decode_opt_env("ARGON_ASSOCIATED_DATA")?;

    assert_eq!(
        32,
        password_salt.len(),
        "Password salt should be 32 bytes long. Is {}",
        password_salt.len()
    );

    let a2config = Argon2Builder::new()
        .salt(password_salt)
        .secret(argon_secret)
        .associated_data(argon_associated_data)
        .build();

    {
        let password = "password";
        let hash = a2config.hash_encoded(password).unwrap();
        assert!(
            hash.len() < 255,
            "Hash encoded hash is too long. It will not fit in the database"
        );
        let matches = a2config.verify_encoded(&hash, password).unwrap();
        assert!(matches, "Password verification should be true");
    }

    let mut handlebars = Handlebars::new();
    handlebars.set_strict_mode(true);
    handlebars
        .register_templates_directory(".hbs", "./static/templates")
        .unwrap();
    let handlebars_ref = web::Data::new(handlebars);

    let mut server = HttpServer::new(move || {
        let session_key: Vec<u8> = (0..32).collect();
        let cookie_session = CookieSession::signed(&session_key)
            .name("fallenskies")
            .path("/")
            .secure(false)
            .same_site(SameSite::Strict);

        App::new()
            .wrap(TracingLogger)
            .wrap(cookie_session)
            .data(db_pool.clone())
            .data(a2config.clone())
            .app_data(handlebars_ref.clone())
            .configure(fs::init)
            .service(Files::new("/", "./static/root").prefer_utf8(true))
    });
    server = match listenfd.take_tcp_listener(0)? {
        Some(listener) => server.listen(listener)?,
        None => {
            let host = env::var("HOST").expect("HOST is not set in .env file");
            let port = env::var("PORT").expect("PORT is not set in .env file");
            server.bind(format!("{}:{}", host, port))?
        }
    };

    Ok(server.run().await?)
}
