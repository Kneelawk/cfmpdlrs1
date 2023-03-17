mod json;

#[macro_use]
extern crate tracing;
#[macro_use]
extern crate anyhow;

use async_zip::read::fs::ZipFileReader;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::OpenOptions;

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

    info!("Extracting overrides.");
    {
        let entries = zip.file().entries();
        let entries_len = entries.len();
        let mut extracted_count = 0;

        for index in 0..entries_len {
            let entry = &entries[index];
            let entry_filename = entry.entry().filename().replace('\\', "/");
            if !entry_filename.starts_with("overrides/")
                && !entry_filename.starts_with("/overrides/")
            {
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
    }

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
