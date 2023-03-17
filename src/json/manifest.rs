use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonManifest {
    pub minecraft: JsonMinecraft,
    pub manifest_type: String,
    pub overrides: String,
    pub manifest_version: i64,
    pub version: String,
    pub author: String,
    pub name: String,
    pub files: Vec<JsonFile>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonMinecraft {
    pub version: String,
    pub mod_loaders: Vec<JsonModLoader>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonModLoader {
    pub id: String,
    pub primary: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonFile {
    #[serde(rename = "projectID")]
    pub project_id: i64,
    #[serde(rename = "fileID")]
    pub file_id: i64,
    pub required: bool,
}
