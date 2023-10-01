
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use chrono::prelude::*;

//Todo structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Todo {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    #[serde(rename = "_uid", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub description: String,
    #[serde(rename = "createdAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    
}

//Todo list structure
// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub struct TodoList {
//     pub list: Vec<Todo>
// }