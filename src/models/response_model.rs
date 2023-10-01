use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use chrono::prelude::*;

//Error response structure
#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    pub message: String,
    pub status: bool
}

//Success response structure
#[derive(Serialize, Deserialize, Debug)]
pub struct SuccessResponse {
    pub message: String,
    pub status: bool
}