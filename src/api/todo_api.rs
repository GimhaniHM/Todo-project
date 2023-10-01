            //// _____________ Todo Api____________  ////

////----------------------  START - Initial routes ----------------------------- ////

use actix_web::{HttpResponse, Responder, get, web::{self, Data, Json}, post, HttpRequest, put, delete};
use mongodb::bson::oid::ObjectId;
use serde_json::json;

use crate::{repository::mongodb_repo::MongoRepo, models::{user_models::{User, LoginUserSchema}, todo_models::Todo}};


////----------------------  END - Initial routes ----------------------------- ////


////----------------------  START - User routes ----------------------------- ////


//user register handler function
#[post("/todo-create")]
pub async fn create_todolist(req: HttpRequest, db: Data<MongoRepo>, new_list: Json<Todo>) -> HttpResponse {

    let auth = req.headers().get("Authorization");
    let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();
    let token = split[1].trim();

    println!("token: {:?}",token);

    let data = Todo {
        id: None,
        user_id: None,
        description: new_list.description.to_owned(),
        created_at: None,
    };

    match db.create_todolist(token, data).await {
        Ok(list) => HttpResponse::Ok().json(json!({"status" : "success", "result" : list})),
        Err(err) => HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : err})),
    }
}

//Find all todos by id
#[get("/all-todos")]
pub async fn get_all_todos(req: HttpRequest, db: Data<MongoRepo>) -> HttpResponse {

    let auth = req.headers().get("Authorization");
    let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();
    let token = split[1].trim();

    match db.list_all_todos_by_user(token).await {
        Ok(result) => HttpResponse::Ok().json(json!({"status" : "success", "result" : result})),
        Err(error) =>  HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : error})), 
    }
}

//handler to update the todo
#[put("/update-todo/{id}")]
pub async fn update_todolist(req: HttpRequest, data: Json<Todo>, id: web::Path<String>, db: Data<MongoRepo>) -> HttpResponse {

    let todo_id = id.into_inner();

    let auth = req.headers().get("Authorization");
    let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();    
    let token = split[1].trim();

    let doc = Todo {
        id: None,
        user_id: None,
        description: data.description.clone(),
        created_at: None
    };

    match db.update_todo(token, doc, todo_id).await {
        Ok(result) => HttpResponse::Ok().json(json!({"result": result})),
        Err(err) => HttpResponse::Ok().json(err),
    }
}

//handler to delete the todo
#[delete("/delete-todo/{id}")]
pub async fn delete_todo(req: HttpRequest ,db: Data<MongoRepo>, id: web::Path<String>) -> HttpResponse {

    let delete_id = id.into_inner();
    let auth = req.headers().get("Authorization");
    let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();    
    let token = split[1].trim();

    match db.delete_todo(token, delete_id).await {
        Ok(result) => HttpResponse::Ok().json(json!({"status" : "success", "result" : result})),
        Err(error) =>  HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : error})),
    }
}


//handler to get todo list
#[get("/get-todo/{id}")]
pub async fn get_todo(req: HttpRequest, db: Data<MongoRepo>, id: web::Path<String>) -> HttpResponse {
    let get_id = id.into_inner();
    let todo_id = ObjectId::parse_str(get_id).unwrap();
    let auth = req.headers().get("Authorization");
    let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();    
    let token = split[1].trim();

    match db.finding_todo(token, &todo_id).await {
        Ok(result) => HttpResponse::Ok().json(json!({"status" : "success", "result" : result})),
        Err(error) =>  HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : error})),
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
    cfg.service(create_todolist)
    .service(get_all_todos)
    .service(update_todolist)
    .service(delete_todo)
    .service(get_todo);
}

////////----------------------  END  ----------------------------- ////////

