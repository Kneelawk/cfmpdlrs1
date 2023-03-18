#![feature(let_chains)]
#![feature(is_some_and)]

mod json;
mod utils;

#[macro_use]
extern crate tracing;
#[macro_use]
extern crate anyhow;

use crate::json::get_files::{JsonGetFilesRequest, JsonGetFilesResponse, JsonHashAlgo};
use crate::json::get_mods::{JsonGetModsRequest, JsonGetModsResponse};
use crate::json::manifest::JsonManifest;
use crate::utils::{OptionExt, ResultExt};
use anyhow::Context;
use async_zip::read::fs::ZipFileReader;
use bytes::{Buf, Bytes, BytesMut};
use clap::Parser;
use digest::{Digest, FixedOutput};
use directories::UserDirs;
use futures::executor::block_on;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use md5::Md5;
use notify::{RecursiveMode, Watcher};
use reqwest::{Client, Url};
use sha1::Sha1;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    /// Directories to look for manually-downloaded files in.
    /// If empty, the user's `Downloads` directory is used.
    #[arg(short, long)]
    manual_dir: Vec<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    let Args {
        file,
        output,
        manual_dir: mut manual_dirs,
    } = Args::parse();

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

    if manual_dirs.is_empty() {
        if let Some(user_dirs) = UserDirs::new() {
            if let Some(downloads_path) = user_dirs.download_dir() {
                manual_dirs.push(downloads_path.to_path_buf());
            } else {
                warn!(
                    "No manual download dirs specified and the user has no Downloads dir! \
                    This program will be unable to handle files that require a manual download."
                );
            }
        } else {
            warn!(
                "No manual download dirs specified and a user could not be found! \
                This program will be unable to handle files that require a manual download."
            );
        }
    }

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
                DownloadFile::Automatic(download) => Some(download.clone()),
                DownloadFile::Manual(_) => None,
            })
            .collect();
        let manual_files: Vec<_> = files
            .iter()
            .filter_map(|file| match file {
                DownloadFile::Automatic(_) => None,
                DownloadFile::Manual(manual) => Some(manual.clone()),
            })
            .collect();

        info!("To download:");
        info!("    {} automatic downloads", automatic_files.len());
        info!("    {} manual downloads", manual_files.len());

        download_automatic_mods(client.clone(), &automatic_files, mods_dir.clone())
            .await
            .context("Error downloading automatic mods")?;

        if manual_dirs.is_empty() && !manual_files.is_empty() {
            error!(
                "This modpack requires manual downloading of some files \
                but no location was specified to search for said files. \
                Please use the --manual-dir option to specify some."
            );
            bail!(
                "This modpack requires manual downloading of some files \
                but no location was specified to search for said files. \
                Please use the --manual-dir option to specify some."
            );
        }

        download_manual_mods(&manual_files, mods_dir.clone(), &manual_dirs)
            .await
            .context("Error manually downloading mods")?;
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
    sha1: Option<Vec<u8>>,
    md5: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct ManualFile {
    file_id: u32,
    mod_id: u32,
    browser_url: String,
    filename: String,
    file_length: u64,
    sha1: Option<Vec<u8>>,
    md5: Option<Vec<u8>>,
}

async fn get_mod_data(
    curse_api_key: &str,
    client: Arc<Client>,
    manifest: JsonManifest,
) -> anyhow::Result<Vec<DownloadFile>> {
    info!("Downloading mod data...");

    let mods_res = {
        let mod_ids = manifest.files.iter().map(|file| file.project_id).collect();
        let response = client
            .post("https://api.curseforge.com/v1/mods")
            .header("x-api-key", curse_api_key)
            .json(&JsonGetModsRequest { mod_ids })
            .send()
            .await
            .context("Error getting mod project data")?;

        info!("Got mods response: {}", response.status());
        response
            .error_for_status_ref()
            .context("Get mods endpoint returned a bad status code")?;

        response
            .json::<JsonGetModsResponse>()
            .await
            .context("Error getting and parsing mods response body")?
    };

    info!(
        "Modpack mods: {}, received mods: {}",
        manifest.files.len(),
        mods_res.data.len()
    );

    let disallowed_mods: HashSet<_> = mods_res
        .data
        .iter()
        .filter_map(|m| {
            if m.allow_mod_distribution == Some(false) {
                Some(m.id)
            } else {
                None
            }
        })
        .collect();
    let ids_2_slugs: HashMap<_, _> = mods_res
        .data
        .iter()
        .map(|m| (m.id, m.slug.clone()))
        .collect();

    let files_res = {
        let file_ids = manifest.files.iter().map(|file| file.file_id).collect();
        let response = client
            .post("https://api.curseforge.com/v1/mods/files")
            .header("x-api-key", curse_api_key)
            .json(&JsonGetFilesRequest { file_ids })
            .send()
            .await
            .context("Error getting mod file data")?;

        info!("Got files response: {}", response.status());
        response
            .error_for_status_ref()
            .context("Get files endpoint returned a bad status code")?;

        response
            .json::<JsonGetFilesResponse>()
            .await
            .context("Error getting and parsing files response body")?
    };

    info!(
        "Modpack files: {}, received files: {}",
        manifest.files.len(),
        files_res.data.len()
    );

    let mut file_ids = HashSet::new();

    let files: Vec<_> = files_res
        .data
        .iter()
        .filter(|file| file_ids.insert(file.id))
        .map(|file| {
            let sha1 = file.hash(JsonHashAlgo::Sha1).and_then(|s| match hex::decode(s) {
                Ok(vec) => Some(vec),
                Err(err) => {
                    warn!("Error decoding SHA1 file hash for {}: {:?}", &file.file_name, err);
                    None
                }
            });
            let md5 = file.hash(JsonHashAlgo::Md5).and_then(|s| match hex::decode(s) {
                Ok(vec) => Some(vec),
                Err(err) => {
                    warn!("Error decoding MD5 file hash for {}: {:?}", &file.file_name, err);
                    None
                }
            });
            if let Some(ref download_url) = file.download_url && !disallowed_mods.contains(&file.mod_id) {
                DownloadFile::Automatic(AutomaticFile {
                    download_url: download_url.clone(),
                    filename: file.file_name.clone(),
                    file_length: file.file_length,
                    sha1,
                    md5,
                })
            } else {
                DownloadFile::Manual(ManualFile {
                    file_id: file.id,
                    mod_id: file.mod_id,
                    browser_url: format!(
                        "https://www.curseforge.com/minecraft/mc-mods/{}/download/{}",
                        ids_2_slugs.get(&file.mod_id).expect("File project id mismatch!"),
                        file.id
                    ),
                    filename: file.file_name.clone(),
                    file_length: file.file_length,
                    sha1,
                    md5,
                })
            }
        })
        .collect();

    info!(
        "Modpack entries: {}, result entries: {}",
        manifest.files.len(),
        files.len()
    );

    Ok(files)
}

async fn download_automatic_mods(
    client: Arc<Client>,
    mods: &[AutomaticFile],
    mods_path: PathBuf,
) -> anyhow::Result<()> {
    let total_mods = mods.len();

    info!("Downloading {total_mods} files automatically.");

    // Lazy concurrency limiter
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_DOWNLOADS));

    let cancelled = Arc::new(AtomicBool::new(false));
    let files_complete = Arc::new(AtomicUsize::new(0));
    let mut futures = FuturesUnordered::<JoinHandle<anyhow::Result<()>>>::new();

    for file in mods {
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

async fn download_manual_mods(
    manual_files: &[ManualFile],
    mods_dir: PathBuf,
    manual_dirs: &[PathBuf],
) -> anyhow::Result<()> {
    let total_mods = manual_files.len();
    info!("Manually downloading {total_mods} mods.");

    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let mut watcher = notify::recommended_watcher(move |res| {
        block_on(tx.send(res)).ok();
    })
    .context("Error directory creating watcher")?;

    for manual_dir in manual_dirs {
        watcher
            .watch(manual_dir, RecursiveMode::Recursive)
            .with_context(|| format!("Error watching directory {:?}", manual_dir))?;
    }

    info!("Scanning existing files...");

    let mut lengths = HashSet::new();
    let mut to_download = HashSet::new();

    for file in manual_files {
        lengths.insert(file.file_length);
        to_download.insert(file.filename.clone());
    }

    let walking_dirs = manual_dirs.to_vec();
    let paths = tokio::task::spawn_blocking::<_, anyhow::Result<Vec<PathBuf>>>(move || {
        let mut paths = vec![];

        for manual_dir in walking_dirs.iter() {
            for entry in walkdir::WalkDir::new(manual_dir) {
                let dir_entry = entry?;
                let metadata = dir_entry.metadata()?;
                if lengths.contains(&metadata.len()) {
                    paths.push(dir_entry.path().to_path_buf());
                }
            }
        }

        Ok(paths)
    })
    .await??;

    let mut successful = 0usize;

    for path in paths.iter() {
        if let Some(file) = try_copy_mod(manual_files, &to_download, &mods_dir, path).await {
            to_download.remove(&file.filename);
            successful += 1;

            info!("Found mod {}/{}: {}", successful, total_mods, file.filename);

            if successful >= total_mods {
                info!("Manually downloaded {} mods.", successful);
                return Ok(());
            }
        }
    }

    info!("Please download the following mods:");
    for file in manual_files {
        if to_download.contains(&file.filename) {
            info!("    {}", file.browser_url);
        }
    }

    info!("To one of the following directories:");
    for manual_dir in manual_dirs {
        info!("    {}", manual_dir.to_string_lossy());
    }

    while let Some(res) = rx.recv().await {
        let event = res.context("Error while watching")?;

        if event.kind.is_create() || event.kind.is_modify() {
            for path in event.paths.iter() {
                if let Some(file) = try_copy_mod(manual_files, &to_download, &mods_dir, path).await
                {
                    to_download.remove(&file.filename);
                    successful += 1;

                    info!("Found mod {}/{}: {}", successful, total_mods, file.filename);

                    if successful >= total_mods {
                        info!("Manually downloaded {} mods.", successful);
                        return Ok(());
                    }
                }
            }
        }
    }

    error!(
        "Stopped waiting for manually downloaded mods with {} mods remaining.",
        total_mods - successful
    );

    Ok(())
}

async fn try_copy_mod<'a>(
    manual_files: &'a [ManualFile],
    to_download: &HashSet<String>,
    mods_dir: &Path,
    path: &Path,
) -> Option<&'a ManualFile> {
    match hash_file(path).await {
        Ok(hashes) => {
            for file in manual_files {
                if to_download.contains(&file.filename)
                    && file.file_length == hashes.file_length
                    && file.sha1.as_ref().is_none_or(|sha1| sha1 == &hashes.sha1)
                    && file.md5.as_ref().is_none_or(|md5| md5 == &hashes.md5)
                {
                    let to_path = mods_dir.join(&file.filename);

                    match tokio::fs::copy(path, &to_path).await {
                        Ok(_) => {
                            return Some(file);
                        }
                        Err(err) => {
                            warn!(
                                "Found correct file {} but failed to copy it: {:?}",
                                &file.filename, err
                            );
                        }
                    }
                }
            }
        }
        Err(err) => {
            warn!("Error hashing files: {:?}", err);
        }
    }

    None
}

struct FileHash {
    file_length: u64,
    sha1: Vec<u8>,
    md5: Vec<u8>,
}

async fn hash_file(path: &Path) -> anyhow::Result<FileHash> {
    let mut file = File::open(path).await?;
    let metadata = file.metadata().await?;

    let mut sha1 = Sha1::new();
    let mut md5 = Md5::new();

    let mut bytes = BytesMut::new();
    let mut read = 0usize;

    while (read as u64) < metadata.len() {
        file.read_buf(&mut bytes).await?;
        sha1.update(&bytes[..]);
        md5.update(&bytes[..]);
        read += bytes.len();
        bytes.clear();
    }

    Ok(FileHash {
        file_length: metadata.len(),
        sha1: sha1.finalize_fixed().to_vec(),
        md5: md5.finalize_fixed().to_vec(),
    })
}
