            //// _____________ Todo Api____________  ////

////----------------------  START - Initial routes ----------------------------- ////

use actix_web::{HttpResponse, Responder, get, web::{self, Data, Json}, post, HttpRequest};
use serde_json::json;

use crate::{repository::mongodb_repo::MongoRepo, models::{user_models::{User, LoginUserSchema}, todo_models::{TodoList, Todo}}};


////----------------------  END - Initial routes ----------------------------- ////


////----------------------  START - User routes ----------------------------- ////


//user register handler function
#[post("/todo-create")]
pub async fn create_todolist(_req: HttpRequest, db: Data<MongoRepo>, new_list: Json<Todo>) -> HttpResponse {

    let _auth = _req.headers().get("Authorization");
    let _split: Vec<&str> = _auth.unwrap().to_str().unwrap().split("Bearer").collect();
    let token = _split[1].trim();

    println!("token: {:?}",token);

    let data = Todo {
        id: None,
        description: new_list.description.to_owned(),
        created_at: None,
    };

    match db.create_todolist(token, data).await {
        Ok(list) => HttpResponse::Ok().json(json!({"status" : "success", "result" : list})),
        Err(err) => HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : err})),
    }
}

// //user login handler function
// #[post("/user-login")]
// pub async fn login_user(user: web::Json<LoginUserSchema>, db: Data<MongoRepo>) -> HttpResponse {
    
//     let user_details = db.login_user(user.into_inner());
    
//     user_details.await

// }

////----------------------  END - User routes ----------------------------- ////


pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(create_todolist);
}

////////----------------------  END  ----------------------------- ////////

