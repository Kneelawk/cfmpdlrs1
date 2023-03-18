use crate::json::get_files::{JsonFile, JsonFileReleaseType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonGetModsRequest {
    pub mod_ids: Vec<u32>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonGetModsResponse {
    pub data: Vec<JsonMod>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonMod {
    pub id: u32,
    pub game_id: u32,
    pub name: String,
    pub slug: String,
    pub links: JsonModLinks,
    pub summary: String,
    pub status: JsonModStatus,
    pub download_count: u64,
    pub is_featured: bool,
    pub primary_category_id: u32,
    pub categories: Vec<JsonCategory>,
    pub class_id: Option<u32>,
    pub authors: Vec<JsonModAuthor>,
    pub logo: JsonModAsset,
    pub screenshots: Vec<JsonModAsset>,
    pub main_file_id: u32,
    pub latest_files: Vec<JsonFile>,
    pub latest_files_indexes: Vec<JsonFileIndex>,
    pub date_created: DateTime<Utc>,
    pub date_modified: DateTime<Utc>,
    pub date_released: DateTime<Utc>,
    pub allow_mod_distribution: Option<bool>,
    pub game_popularity_rank: u32,
    pub is_available: bool,
    pub thumbs_up_count: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonModLinks {
    pub website_url: String,
    pub wiki_url: Option<String>,
    pub issues_url: Option<String>,
    pub source_url: Option<String>,
}

#[derive(
    Default,
    Debug,
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Serialize_repr,
    Deserialize_repr,
)]
#[repr(u8)]
pub enum JsonModStatus {
    New = 1,
    ChangesRequired = 2,
    UnderSoftReview = 3,
    #[default]
    Approved = 4,
    Rejected = 5,
    ChangesMade = 6,
    Inactive = 7,
    Abandoned = 8,
    Deleted = 9,
    UnderReview = 10,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonCategory {
    pub id: u32,
    pub game_id: u32,
    pub name: String,
    pub slug: String,
    pub url: String,
    pub icon_url: String,
    pub date_modified: DateTime<Utc>,
    pub is_class: Option<bool>,
    pub class_id: Option<u32>,
    pub parent_category_id: Option<u32>,
    pub display_index: Option<u32>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonModAuthor {
    pub id: u32,
    pub name: String,
    pub url: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonModAsset {
    pub id: u32,
    pub mod_id: u32,
    pub title: String,
    pub description: String,
    pub thumbnail_url: String,
    pub url: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonFileIndex {
    pub game_version: String,
    pub file_id: u32,
    pub filename: String,
    pub release_type: JsonFileReleaseType,
    pub game_version_type_id: Option<u32>,
    pub mod_loader: Option<JsonModLoaderType>,
}

#[derive(
    Default,
    Debug,
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Serialize_repr,
    Deserialize_repr,
)]
#[repr(u8)]
pub enum JsonModLoaderType {
    #[default]
    Any = 0,
    Forge = 1,
    Cauldron = 2,
    LiteLoader = 3,
    Fabric = 4,
    Quilt = 5,
}
