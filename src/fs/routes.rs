use crate::fs::{Account, Argon2Config, UserSession};
use actix_session::Session;
use actix_web::{
    get, post, web, Error, HttpResponse, Responder, Result,
};
use handlebars::Handlebars;
use sqlx::PgPool;
use std::fmt::Debug;

#[derive(Deserialize, Debug)]
struct LoginCredentials {
    username: String,
    password: String,
}

trait Renderable: erased_serde::Serialize + Debug {}

#[derive(Serialize, Debug)]
struct Section<'a> {
    template: &'a str,
    data: Box<dyn Renderable + 'a>,
}

impl<'a> Section<'a> {
    fn new<T: Renderable + 'a>(template: &'a str, data: T) -> Section<'a> {
        Section {
            template,
            data: Box::new(data),
        }
    }
}

#[derive(Serialize, Debug)]
struct PageTemplate<'a> {
    title: &'a str,
    header: Section<'a>,
    body: Section<'a>,
    footer: Section<'a>,
}

#[derive(Serialize, Debug)]
struct BannerWithLogin<'a> {
    username: Option<&'a str>,
}

#[derive(Serialize, Debug)]
struct Registration<'a> {
    is_registered: bool,
    errors: Option<Vec<&'a str>>,
}

#[derive(Serialize, Debug)]
struct EmptyF {}

impl<'a> Renderable for BannerWithLogin<'a> {}
impl<'a> Renderable for Registration<'a> {}
impl Renderable for EmptyF {}

serialize_trait_object!(Renderable);

#[get("/")]
async fn index(
    session: Session,
    pg_pool: web::Data<PgPool>,
    hb: web::Data<Handlebars<'_>>,
) -> Result<impl Responder, Error> {
    let username_k = session.get::<String>("username")?;
    let session_id_k = session.get::<String>("session_id")?;

    let mut header = BannerWithLogin { username: None };

    if let (Some(ref username), Some(ref session_id)) = (&username_k, &session_id_k) {
        let ok_result = UserSession::validate_session(&username, &session_id, &pg_pool).await;
        if let Err(_) = ok_result {
            return Ok(HttpResponse::InternalServerError().finish());
        }
        let ok = ok_result.unwrap();
        if ok {
            header.username = Some(username);
        } else {
            tracing::error!(
                "Incorrect session match between {} and {}",
                username,
                session_id
            );
            session.clear();
        }
    }

    let template = PageTemplate {
        title: "Index",
        header: Section::new("banner_with_login", header),
        body: Section::new("game_port", EmptyF {}),
        footer: Section::new("dummy_footer", EmptyF {}),
    };

    let body = hb.render("main", &template).unwrap();
    Ok(HttpResponse::Ok().body(body))
}

#[post("/register")]
async fn post_register(
    form: web::Form<LoginCredentials>,
    argon_config: web::Data<Argon2Config>,
    pg_pool: web::Data<PgPool>,
    hb: web::Data<Handlebars<'_>>,
) -> Result<impl Responder, Error> {
    let username_result = Account::username_exists(&form.username, &pg_pool).await;
    if let Err(_) = username_result {
        return Ok(HttpResponse::BadRequest().finish());
    }
    let username_exists = username_result.unwrap();

    let mut error_list = Vec::new();
    let mut is_registered = false;
    {
        if username_exists {
            tracing::info!("This account already exists!");
            error_list.push("This account already exists");
        } else {
            let create_result =
                Account::create(&form.username, &form.password, &argon_config, &pg_pool).await;
            if let Err(_) = create_result {
                return Ok(HttpResponse::InternalServerError().finish());
            }
            let _id = create_result.unwrap();
            is_registered = true;
        }
    };
    let errors = if error_list.is_empty() {
        None
    } else {
        Some(error_list)
    };
    let template = PageTemplate {
        title: "Registration",
        header: Section::new("dummy_header", EmptyF {}),
        body: Section::new(
            "registration",
            Registration {
                is_registered,
                errors,
            },
        ),
        footer: Section::new("dummy_footer", EmptyF {}),
    };
    let body = hb.render("main", &template).unwrap();
    Ok(HttpResponse::Ok().body(body))
}

#[get("/register")]
async fn get_register(
    hb: web::Data<Handlebars<'_>>,
) -> Result<impl Responder, Error> {
    let template = PageTemplate {
        title: "Registration",
        header: Section::new("dummy_header", EmptyF {}),
        body: Section::new(
            "registration",
            Registration {
                is_registered: false,
                errors: None,
            },
        ),
        footer: Section::new("dummy_footer", EmptyF {}),
    };
    let body = hb.render("main", &template).unwrap();
    Ok(HttpResponse::Ok().body(body))
}

#[post("/login")]
async fn login(
    session: Session,
    form: web::Form<LoginCredentials>,
    argon_config: web::Data<Argon2Config>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder, Error> {
    let login_result =
        UserSession::login(&form.username, &form.password, &argon_config, &pg_pool).await;
    if let Err(_) = login_result {
        return Ok(HttpResponse::BadRequest().finish());
    }
    if let Some(session_id) = login_result.unwrap() {
        tracing::info!("Password matches: {}", true);
        session.set("username", &form.username)?;
        session.set("session_id", session_id)?;
        Ok(HttpResponse::Found().header("Location", "/").finish())
    } else {
        tracing::info!("Password matches: {}", false);
        Ok(HttpResponse::BadRequest().finish())
    }
}

#[post("/logout")]
async fn logout(session: Session) -> Result<impl Responder, Error> {
    session.clear();
    Ok(HttpResponse::Found().header("Location", "/").finish())
}

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(index);
    cfg.service(login);
    cfg.service(logout);
    cfg.service(post_register);
    cfg.service(get_register);
}
