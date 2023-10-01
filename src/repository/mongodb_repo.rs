use std::{env, collections::HashMap};
use actix_web::{
    HttpResponse,
    cookie::time::Duration as ActixWebDuration,
    cookie::Cookie, dev::Response, web::{Json, self, Data, JsonBody}, HttpRequest, put
};
use chrono::{prelude::*, Duration};
use dotenv::dotenv;

use futures::StreamExt;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm, encode, Header, EncodingKey};

use mongodb::{
    Collection, 
    Client, 
    bson::{doc,extjson::de::Error, oid::ObjectId, self}, results::{InsertOneResult, UpdateResult, DeleteResult}
};

use crate::models::{
    user_models::{User, LoginUserSchema, TokenClaims}, 
    todo_models::Todo,
    response_model::ErrorResponse
};

extern crate dotenv;

use serde_json::json;

#[derive(Debug,Clone)]
pub struct MongoRepo {
    u_col: Collection<User>,
    list_col: Collection<Todo>,

}

impl MongoRepo {

    pub async fn init() -> Self {
        dotenv().ok();
        let uri = match env::var("MONGOURI") {
            Ok(v) => v.to_string(),
            Err(_) => format!("Error loading env variable"),
        };

        let client = Client::with_uri_str(uri).await.unwrap();
        let db = client.database("todo-db");
        let u_col: Collection<User> = db.collection("User");
        let list_col: Collection<Todo> = db.collection("Todo-List");


        println!("✅ Database connected successfully");


        MongoRepo { 
            u_col,
            list_col
        }
    }

    ////----------------------  START - User handler function ----------------------------- ////

    //user find by email handler
    pub async fn find_by_email(&self, email: &String) -> Result<Option<User>, Error> {

        // let check_email = email;

        let user = self
            .u_col
            .find_one( doc! {"email" : email}, None)
            .await.ok()
            .expect("Error finding user");

        
        Ok(user)

    }

//handler to create the user
    pub async fn register_user(&self, new_user: User) -> Result<InsertOneResult, ErrorResponse> {
        match self.find_by_email(&new_user.email.to_string()).await.unwrap(){
            Some(_x) => {
                Err(
                    ErrorResponse{
                        status: false,
                        message: "Email already exists".to_owned()
                    }
                )
            
            }

            None => {

                let doc = User {
                    id: None,
                    name: new_user.name,
                    email: new_user.email,
                    password: new_user.password,
                    created_at: None,
                }; 

                let user = self
                    .u_col
                    .insert_one(doc, None)
                    .await.ok()
                    .expect("Error creating user");
            

                    // let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
                    //     "User": user
                    // })});
        
                    //return HttpResponse::Ok().json(user_response);

                    Ok(user)

            }
            
        }
    }


    pub async fn login_user(&self, user: LoginUserSchema) -> HttpResponse {
        match self.find_by_email(&user.email).await.unwrap() {
            Some(x) => {

                let jwt_secret = "secret".to_owned();

                let id = x.id.unwrap();  //Convert Option<ObjectId> to ObjectId using unwrap()

                let now = Utc::now();
                let iat = now.timestamp() as usize;
                
                let exp = (now + Duration::minutes(60)).timestamp() as usize;
                let claims: TokenClaims = TokenClaims {
                    sub: id.to_string(),
                    exp,
                    iat,
                };

                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(jwt_secret.as_ref()),
                )
                .unwrap();

                let cookie = Cookie::build("token", token.to_owned())
                    .path("/")
                    .max_age(ActixWebDuration::new(60 * 60, 0))
                    .http_only(true)
                    .finish();

                // Ok(LoginResponse {
                //     status: true,
                //     token,
                //     message: "You have successfully logged in.".to_string(),
                // })
                

                HttpResponse::Ok()
                    .cookie(cookie)
                    .json(json!({"status" :  "success", "token": token}))
            },

            None => {
                return HttpResponse::BadRequest()
                .json(ErrorResponse{
                    status: false,
                    message: "Invalid username or password".to_owned()
                })
            }
        }

    }

    ////----------------------  END - User handler function ----------------------------- ////



    ////----------------------  START - Todo List handler function ----------------------------- ////

    //handler to validate the user
    pub async fn validate_user(&self, token: &str) -> Result<Option<User>, HttpResponse>{
        let secret_key = "secret".to_owned();
    
        let var = secret_key;
        let key = var.as_bytes();
        let decode = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(key),
            &Validation::new(Algorithm::HS256),
        ); 

        println!("decode: {:?}", decode);

        match decode {
            Ok(decoded) => {

                println!("object_id{:?}", decoded.claims.sub.to_owned());

                let id = decoded.claims.sub;

                let bson_id = ObjectId::parse_str(id).unwrap(); //used to convert <String> to <bjectId>

                let user = self
                    .u_col
                    .find_one( doc! {"_id" : bson_id }, None)
                    .await.ok()
                    .expect("Error finding");

                println!("{:?}", user);
        
                Ok(user)

            }
            Err(_) => Err(
                //HttpResponse::BadRequest().json(json!({"status" :  "fail", "message": "Invalid token"})))
                HttpResponse::BadRequest().json(ErrorResponse{
                    status: false,
                    message: "Invalid token".to_owned()
                }))
            
        }
    }

    //create todo list
    pub async fn create_todolist(&self, token: &str, new_list: Todo) -> Result<InsertOneResult, ErrorResponse> {
        match self.validate_user(token).await.unwrap(){
            Some(x) => {
                let user_id = x.id.unwrap().to_string();

                let new_data = Todo {
                    id: None,
                    user_id: Some(user_id),
                    description: new_list.description,
                    created_at: Some(Utc::now())
                };

                // // Create a HashMap and insert the new_todo into it
                // let mut todo_list = HashMap::new();
                // todo_list.insert(user_id, new_data);

                // let doc = TodoList {
                //     list: todo_list,
                // };

                let todo_doc = self 
                    .list_col
                    .insert_one(new_data, None)
                    .await
                    .ok()
                    .expect("Error creating list");

                println!("{:?}", todo_doc);
                Ok(todo_doc)
            },
            None => {
                Err(ErrorResponse {
                    status: false,
                    message: "Not found user".to_string(),
                })
            }
        }
    }

//handler to list all the Todos specified to User
    pub async fn list_all_todos_by_user(&self, token: &str) -> Result<Vec<Todo>, ErrorResponse> {
        match self.validate_user(token).await.unwrap(){
            Some(x) => {

                let user_id = x.id.unwrap().to_string();

                let doc = doc! {
                    "_uid": user_id
                };

                let mut todo_doc = self 
                    .list_col
                    .find(doc, None)
                    .await
                    .ok()
                    .expect("Error geting todo list");

                    let mut todo_vec = Vec::new();

                    while let Some(doc) = todo_doc.next().await {

                        println!("Hiiii {:?}", doc);

                        match doc {
                            Ok(todo) => {
                                todo_vec.push(todo)
                            },
                            Err(err) => {
                                eprintln!("Error finding todo: {:?}", err)
                            },
                        }
                    }    

                println!("{:?}", todo_doc);
                Ok(todo_vec)
            },
            None => {
                Err(ErrorResponse {
                    status: false,
                    message: "Not found user".to_string(),
                })
            }
        }
    }

    //handler to update todo list
    pub async fn update_todo(&self, token: &str, todo_list: Todo, todo_id: String ) -> Result<UpdateResult, ErrorResponse> {
        match self.validate_user(token).await.unwrap(){
            Some(x) => {

                //let _user_id = x.id.unwrap().to_string();

                let todo_id = ObjectId::parse_str(todo_id).unwrap();

                match self.finding_todo(&token, &todo_id).await.unwrap() {
                    Some(_) => {

                        let filter = doc! {"_id": todo_id};
    
                        let new_doc = doc! {
                            "$set":
                                {
                                    "description": todo_list.description
                                },
                        };
                        let updated_doc = self
                            .list_col
                            .update_one(filter, new_doc, None)
                            .await
                            .ok()
                            .expect("Error updating todo");
                
                        Ok(updated_doc)
                    },
                    None => {
                        return Err(ErrorResponse {
                                message: "Todo Not found".to_owned(),
                                status: false
                        })
                    }
                }
            },
            None => {
                Err(ErrorResponse {
                    status: false,
                    message: "Not found user".to_string(),
                })
            }
        }
    }

    //handler for finding todo list
    pub async fn finding_todo(&self, token: &str, todo_id: &ObjectId) -> Result<Option<Todo>, ErrorResponse> {
        match self.validate_user(token).await.unwrap(){
            Some(x) => {

                let user_id = x.id.unwrap().to_string();

                let todo = self
                .list_col
                .find_one(doc! {
                    "_id" : todo_id,
                    "_uid" : user_id
                }, None)
                .await.ok()
                .expect("Error finding todo");

                Ok(todo)
            },
            None => Err(ErrorResponse {
                status: false,
                message: "Not found user".to_string(),
            })
        }
        
    }

    //handler for delete the todo list
    pub async fn delete_todo(&self, token: &str, todo_id: String) -> Result<DeleteResult, ErrorResponse> {
        match self.validate_user(token).await.unwrap(){
            Some(x) => {

                let _user_id = x.id.unwrap().to_string();

                let todo_id = ObjectId::parse_str(&todo_id).unwrap();

                match self.finding_todo(&token, &todo_id).await.unwrap() {
                    Some(_) => {

                        let filter = doc! {"_id": todo_id};
    
                        let delete_doc = self
                                .list_col
                                .delete_one(filter, None)
                                .await
                                .ok()
                                .expect("Error deleting todos");
                
                        Ok(delete_doc)
                    },
                    None => {
                        return Err(ErrorResponse {
                                message: "Todo Not found".to_owned(),
                                status: false
                        })
                    }
                }
            },
            None => Err(ErrorResponse {
                status: false,
                message: "Not found user".to_string(),
            })
        }
    }

    




    ////----------------------  END - Todo List handler function ----------------------------- ////








}
