#![feature(let_chains)]
#![feature(is_some_and)]

mod json;
mod utils;

#[macro_use]
extern crate tracing;
#[macro_use]
extern crate anyhow;

use crate::json::get_files::{JsonGetFilesRequest, JsonGetFilesResponse, JsonHashAlgo};
use crate::json::manifest::JsonManifest;
use crate::utils::ResultExt;
use anyhow::Context;
use async_zip::read::fs::ZipFileReader;
use bytes::{Buf, Bytes};
use clap::Parser;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use reqwest::{Client, Url};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

const MAX_CONCURRENT_DOWNLOADS: usize = 100;
const DOWNLOAD_COOLDOWN: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
struct Args {
    /// Input modpack file.
    file: PathBuf,

    /// Output location to store the downloaded modpack at.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    let Args { file, output } = Args::parse();

    let curse_api_key = std::env::var("CURSE_API_TOKEN")
        .ok()
        .or(option_env!("CURSE_API_TOKEN").map(String::from))
        .ok_or(anyhow!(
            "No CURSE_API_TOKEN env variable specified. \
            For developing on this application, \
            a developer curse API token can be obtained at:\n\
            https://console.curseforge.com/?#/login"
        ))?;

    if !tokio::fs::try_exists(&file).await? {
        error!("Modpack file: {:?} does not exist!", &file);
        bail!("Modpack file: {:?} does not exist!", &file);
    }

    let default_output = file
        .parent()
        .ok_or(anyhow!("Modpack file has no parent dir"))?
        .join(
            file.file_stem()
                .ok_or(anyhow!("Modpack file is missing .zip extension"))?,
        );
    let output_dir = output.unwrap_or(default_output);

    info!("Opening Modpack: {:?}", &file);
    info!("Outputting to: {:?}", &output_dir);

    let client = Arc::new(Client::new());

    if !tokio::fs::try_exists(&output_dir).await? {
        tokio::fs::create_dir_all(&output_dir).await?;
    }

    if tokio::fs::read_dir(&output_dir)
        .await?
        .next_entry()
        .await?
        .is_some()
    {
        error!(
            "Output directory: {:?} exists but is not empty!",
            &output_dir
        );
        bail!(
            "Output directory: {:?} exists but is not empty!",
            &output_dir
        );
    }

    let mods_dir = output_dir.join("mods");
    if !tokio::fs::try_exists(&mods_dir).await? {
        tokio::fs::create_dir_all(&mods_dir).await?;
    }

    let zip = Arc::new(ZipFileReader::new(&file).await.unwrap());

    let manifest = extract_manifest(&zip)
        .await
        .context("Error extracting manifest")?;

    extract_overrides(output_dir, zip.clone())
        .await
        .context("Error extracting overrides")?;

    {
        let files = get_mod_data(&curse_api_key, client.clone(), manifest)
            .await
            .context("Error getting mod data")?;

        let automatic_files: Vec<_> = files
            .iter()
            .filter_map(|file| match file {
                DownloadFile::Automatic(download) => Some(download),
                DownloadFile::Manual(_) => None,
            })
            .collect();
        let manual_files: Vec<_> = files
            .iter()
            .filter_map(|file| match file {
                DownloadFile::Automatic(_) => None,
                DownloadFile::Manual(manual) => Some(manual),
            })
            .collect();

        info!("To download:");
        info!("    {} automatic downloads", automatic_files.len());
        info!("    {} manual downloads", manual_files.len());

        download_automatic_mods(client.clone(), &automatic_files, mods_dir.clone())
            .await
            .context("Error downloading automatic mods")?;
    }

    Ok(())
}

async fn extract_manifest(zip: &Arc<ZipFileReader>) -> anyhow::Result<JsonManifest> {
    info!("Extracting manifest...");
    let manifest_index = zip
        .file()
        .entries()
        .iter()
        .enumerate()
        .find_map(|(index, entry)| {
            let entry_name = entry.entry().filename().replace('\\', "/");
            if entry_name == "manifest.json" || entry_name == "/manifest.json" {
                Some(index)
            } else {
                None
            }
        })
        .ok_or(anyhow!("Modpack zip does not contain manifest.json file"))?;
    let mut manifest_reader = zip
        .entry(manifest_index)
        .await
        .context("Error getting manifest reader")?;
    let manifest_entry = zip
        .get_entry(manifest_index)
        .context("Error getting manifest entry")?;
    let mut manifest_str = String::new();
    manifest_reader
        .read_to_string_checked(&mut manifest_str, manifest_entry)
        .await
        .context("Error reading manifest")?;
    Ok(serde_json::from_str::<JsonManifest>(&manifest_str).context("Error parsing manifest")?)
}

async fn extract_overrides(output_dir: PathBuf, zip: Arc<ZipFileReader>) -> anyhow::Result<()> {
    info!("Extracting overrides...");
    let entries = zip.file().entries();
    let entries_len = entries.len();
    let mut extracted_count = 0;

    for index in 0..entries_len {
        let entry = &entries[index];
        let entry_filename = entry.entry().filename().replace('\\', "/");
        if !entry_filename.starts_with("overrides/") && !entry_filename.starts_with("/overrides/") {
            continue;
        }

        let extract_path = output_dir.join(sanitize_override_path(&entry_filename));

        if !entry_filename.ends_with('/') {
            let extract_parent = extract_path
                .parent()
                .ok_or_else(|| anyhow!("Unable to find parent for {:?}", &extract_path))?;
            if !tokio::fs::try_exists(&extract_parent).await? {
                tokio::fs::create_dir_all(&extract_parent).await?;
            }

            let mut entry_reader = zip.entry(index).await?;
            let mut writer = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&extract_path)
                .await?;

            tokio::io::copy(&mut entry_reader, &mut writer).await?;

            extracted_count += 1;
        } else if !tokio::fs::try_exists(&extract_path).await? {
            tokio::fs::create_dir_all(&extract_path).await?
        }
    }

    info!("Extracted {} files.", extracted_count);

    Ok(())
}

fn sanitize_override_path(path: &str) -> PathBuf {
    // Backslash replacement is done earlier.
    // We also want to remove the first element, as that corresponds to the 'overrides' directory.
    path.split('/')
        .map(sanitize_filename::sanitize)
        .skip(1)
        .collect()
}

#[derive(Debug, Clone)]
enum DownloadFile {
    Automatic(AutomaticFile),
    Manual(ManualFile),
}

#[derive(Debug, Clone)]
struct AutomaticFile {
    download_url: String,
    filename: String,
    file_length: u64,
    sha1: Option<String>,
    md5: Option<String>,
}

#[derive(Debug, Clone)]
struct ManualFile {
    file_id: u32,
    mod_id: u32,
    filename: String,
    file_length: u64,
    sha1: Option<String>,
    md5: Option<String>,
}

#[derive(Debug, Clone)]
struct BrowserFile {
    file_id: u32,
    mod_id: u32,
    browser_url: String,
    filename: String,
    file_length: u64,
    sha1: Option<String>,
    md5: Option<String>,
}

async fn get_mod_data(
    curse_api_key: &str,
    client: Arc<Client>,
    manifest: JsonManifest,
) -> anyhow::Result<Vec<DownloadFile>> {
    info!("Downloading mod data...");
    let file_ids = manifest.files.iter().map(|file| file.file_id).collect();

    let response = client
        .post("https://api.curseforge.com/v1/mods/files")
        .header("x-api-key", curse_api_key)
        .json(&JsonGetFilesRequest { file_ids })
        .send()
        .await?;

    info!("Got response: {}", response.status());
    response.error_for_status_ref()?;

    let files_res = response.json::<JsonGetFilesResponse>().await?;
    let files: Vec<_> = files_res
        .data
        .iter()
        .map(|file| {
            if let Some(ref download_url) = file.download_url && file.is_available {
                DownloadFile::Automatic(AutomaticFile {
                    download_url: download_url.clone(),
                    filename: file.file_name.clone(),
                    file_length: file.file_length,
                    sha1: file.hash(JsonHashAlgo::Sha1).map(String::from),
                    md5: file.hash(JsonHashAlgo::Md5).map(String::from),
                })
            } else {
                DownloadFile::Manual(ManualFile {
                    file_id: file.id,
                    mod_id: file.mod_id,
                    filename: file.file_name.clone(),
                    file_length: file.file_length,
                    sha1: file.hash(JsonHashAlgo::Sha1).map(String::from),
                    md5: file.hash(JsonHashAlgo::Md5).map(String::from),
                })
            }
        })
        .collect();
    Ok(files)
}

async fn download_automatic_mods(
    client: Arc<Client>,
    mods: &[&AutomaticFile],
    mods_path: PathBuf,
) -> anyhow::Result<()> {
    info!("Downloading {} files automatically.", mods.len());

    // Lazy concurrency limiter
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_DOWNLOADS));

    let cancelled = Arc::new(AtomicBool::new(false));
    let files_complete = Arc::new(AtomicUsize::new(0));
    let mut futures = FuturesUnordered::<JoinHandle<anyhow::Result<()>>>::new();

    let total_mods = mods.len();

    for &file in mods {
        let client = client.clone();
        let file = file.clone();
        let mods_path = mods_path.clone();
        let semaphore = semaphore.clone();
        let files_complete = files_complete.clone();
        let cancelled = cancelled.clone();

        futures.push(tokio::spawn(async move {
            let _permit = semaphore
                .acquire()
                .await
                .context("Error acquiring semaphore permit")?;

            let download_url = &file.download_url;
            let url = Url::from_str(download_url)
                .with_context(|| format!("Error parsing url {}", download_url))
                .cancel(&cancelled)?;
            let mod_path = mods_path.join(&file.filename);

            let mut writer = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&mod_path)
                .await
                .with_context(|| {
                    format!(
                        "Error opening destination mod file {}",
                        mod_path.to_string_lossy()
                    )
                })
                .cancel(&cancelled)?;

            download_file(
                client,
                &url,
                &mut writer,
                Duration::from_secs(20),
                files_complete,
                total_mods,
                cancelled.clone(),
            )
            .await
            .with_context(|| format!("Error downloading mod file {}", &url))
            .cancel(&cancelled)?;

            Ok(())
        }));
    }

    while let Some(res) = futures.next().await {
        res.context("Error waiting for file download")?
            .context("Error downloading file")?;
    }

    info!("Downloaded {} mods", total_mods);

    Ok(())
}

async fn download_file(
    client: Arc<Client>,
    url: &Url,
    output: &mut File,
    conn_timeout: Duration,
    files_complete: Arc<AtomicUsize>,
    total_mods: usize,
    cancelled: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut final_url = url.clone();

    let mut full_length = None;
    let mut offset = 0u64;

    // Do the actual download
    loop {
        let res = download_file_part(
            client.clone(),
            &mut final_url,
            output,
            conn_timeout,
            &mut full_length,
            &mut offset,
            cancelled.clone(),
        )
        .await;

        match res {
            Ok(res) => break res,
            Err(err) => {
                debug!(
                    "# Download {} handling error: {:?}\nWaiting for connection to cool down...",
                    &url, err
                );
                sleep(DOWNLOAD_COOLDOWN).await;
            }
        }
    }
    .with_context(|| format!("Error downloading mod file {}", &url))
    .cancel(&cancelled)?;

    let files_complete = files_complete.fetch_add(1, Ordering::AcqRel) + 1;

    debug!(
        "# Downloaded mod '{}' with data: {}/{:?} mod {}/{}",
        &url, offset, full_length, files_complete, total_mods
    );
    info!("Downloaded {}/{} mods.", files_complete, total_mods);

    Ok(())
}

async fn download_file_part(
    client: Arc<Client>,
    url: &mut Url,
    output: &mut File,
    conn_timeout: Duration,
    full_length: &mut Option<u64>,
    offset: &mut u64,
    cancelled: Arc<AtomicBool>,
) -> anyhow::Result<anyhow::Result<()>> {
    if cancelled.load(Ordering::Acquire) {
        info!("Cancelled {}", &url);
        return Ok(Err(anyhow!("Cancelled.")));
    }

    let mut builder = client.get(url.clone());

    if *offset > 0u64 {
        builder = builder.header("range", format!("bytes={}-", offset));
    }

    let res = timeout(conn_timeout, builder.send())
        .await
        .context("Connection timeout")?
        .context("Error connecting to server")?;

    if res.status().is_client_error() || res.status().is_server_error() {
        return Ok(Err(anyhow!(
            "Server gave bad response code: {}",
            res.status()
        )));
    }

    *url = res.url().clone();

    let length = res.content_length();
    let mut downloaded = 0u64;
    if full_length.is_none() {
        *full_length = length.map(|len| *offset + len);
    }

    let mut stream = res.bytes_stream();

    while let Some(item) = timeout(conn_timeout, stream.next())
        .await
        .context("Chunk download timeout")?
    {
        let chunk: Bytes = item.context("Error downloading byte chunk")?;

        output
            .write_all(chunk.chunk())
            .await
            .context("Error writing to file")?;

        let len = chunk.len() as u64;
        *offset += len;
        downloaded += len;

        if cancelled.load(Ordering::Acquire) {
            info!("Cancelled {}", &url);
            return Ok(Err(anyhow!("Cancelled.")));
        }
    }

    if length.is_some_and(|length| downloaded < length)
        || full_length.is_some_and(|full_length| *offset < full_length)
    {
        debug!(
            "# Incomplete download {} {}/{} ({}/{})",
            &url,
            downloaded,
            length.unwrap(),
            offset,
            full_length.unwrap()
        );
        bail!("Incomplete download");
    } else {
        debug!(
            "# Complete download {} {}/{:?} ({}/{:?})",
            &url, downloaded, length, offset, full_length
        );
    }

    Ok(Ok(()))
}
