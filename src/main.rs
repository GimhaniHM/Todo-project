
use actix_cors::Cors;
use actix_web::{web::Data, HttpServer, App, http::header};

use crate::repository::mongodb_repo::MongoRepo;


mod models;
mod api;
mod middleware;
mod repository;

use api::{user_api, todo_api};


#[actix_web::main]
async fn main() -> std::io::Result<()>{
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }
    env_logger::init();

    let db = MongoRepo::init().await;
    let db_data = Data::new(db);

    println!("🚀 Server started successfully");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::ACCEPT,
            ])
            .supports_credentials();

        App::new()
            .app_data(db_data.clone())
            .configure(user_api::config)
            .configure(todo_api::config)
    
        })
        .bind(("127.0.0.1", 8070))?
        .run()
        .await
}
