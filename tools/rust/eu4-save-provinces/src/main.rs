use eu4save::file::{Eu4FileEntryName, Eu4SliceFileKind};
use eu4save::models::SavegameVersion;
use eu4save::{CountryTag, Encoding, Eu4Date, Eu4File, PdsDate, SegmentedResolver};
use jomini::JominiDeserialize;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserializer, Serialize};
use std::collections::HashSet;
use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process;

const DEFAULT_MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_STDOUT_BYTES: usize = 32 * 1024 * 1024;
const SCHEMA: &str = "eu4.save_provinces_snapshot.v1";

#[derive(JominiDeserialize)]
struct RawMeta {
    player: CountryTag,
    date: Eu4Date,
    savegame_version: SavegameVersion,
}

#[derive(JominiDeserialize)]
struct RawProvince {
    #[jomini(default)]
    cores: Vec<CountryTag>,
    #[jomini(default)]
    claims: Vec<CountryTag>,
    #[jomini(default)]
    discovered_by: Option<Vec<CountryTag>>,
}

#[derive(JominiDeserialize)]
struct RawGame {
    #[jomini(default, deserialize_with = "eu4save::de::deserialize_vec_pair")]
    countries: Vec<(CountryTag, IgnoredAny)>,
    #[jomini(deserialize_with = "deserialize_province_entries")]
    provinces: Vec<(i32, RawProvince)>,
}

#[derive(JominiDeserialize)]
struct RawTextSave {
    player: CountryTag,
    date: Eu4Date,
    savegame_version: SavegameVersion,
    #[jomini(default, deserialize_with = "eu4save::de::deserialize_vec_pair")]
    countries: Vec<(CountryTag, IgnoredAny)>,
    #[jomini(deserialize_with = "deserialize_province_entries")]
    provinces: Vec<(i32, RawProvince)>,
}

struct ProvinceEntriesVisitor;

impl<'de> Visitor<'de> for ProvinceEntriesVisitor {
    type Value = Vec<(i32, RawProvince)>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map of serialized province keys to province data")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut rows = Vec::with_capacity(map.size_hint().unwrap_or(5000));
        while let Some(row) = map.next_entry::<i32, RawProvince>()? {
            rows.push(row);
        }
        Ok(rows)
    }
}

fn deserialize_province_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<(i32, RawProvince)>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(ProvinceEntriesVisitor)
}

#[derive(Serialize)]
struct SaveVersion {
    first: u16,
    second: u16,
    third: u16,
    fourth: u16,
    name: String,
}

#[derive(Serialize)]
struct ProvinceRow {
    province_id: u16,
    serialized_key: i32,
    cores: Vec<String>,
    claims: Vec<String>,
    discovered_by: Option<Vec<String>>,
}

#[derive(Serialize)]
struct Snapshot {
    schema: &'static str,
    saved_date: String,
    saved_version: SaveVersion,
    saved_player: String,
    country_tags: Vec<String>,
    provinces: Vec<ProvinceRow>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("eu4-save-provinces: {error}");
        process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let (path, max_bytes) = parse_args()?;
    let bytes = read_input(&path, max_bytes)?;
    let file = Eu4File::from_slice(&bytes)?;
    match file.encoding() {
        Encoding::Text | Encoding::TextZip => {}
        encoding => return Err(format!("unsupported_encoding:{encoding}").into()),
    }

    let expanded_size_hint = file.size() as u64;
    if expanded_size_hint > max_bytes {
        return Err(format!(
            "expanded_size_limit_exceeded:{expanded_size_hint}>{max_bytes}"
        )
        .into());
    }

    let (meta, game) = match file.kind() {
        Eu4SliceFileKind::Text(text) => {
            let mut deserializer = text.deserializer();
            let flat = deserializer.deserialize::<RawTextSave>()?;
            (
                RawMeta {
                    player: flat.player,
                    date: flat.date,
                    savegame_version: flat.savegame_version,
                },
                RawGame {
                    countries: flat.countries,
                    provinces: flat.provinces,
                },
            )
        }
        Eu4SliceFileKind::Zip(zip) => {
            let mut meta_entry = zip.get(Eu4FileEntryName::Meta)?;
            let meta = meta_entry.deserialize::<RawMeta, _>(SegmentedResolver::empty())?;
            let mut game_entry = zip.get(Eu4FileEntryName::Gamestate)?;
            let game = game_entry.deserialize::<RawGame, _>(SegmentedResolver::empty())?;
            (meta, game)
        }
        Eu4SliceFileKind::Binary(_) => return Err("unsupported_encoding:Binary".into()),
    };

    let mut country_tags = game
        .countries
        .into_iter()
        .filter_map(|(tag, _)| (!tag.is_none()).then(|| tag.to_string()))
        .collect::<Vec<_>>();
    country_tags.sort();
    if country_tags.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("duplicate_country_tag".into());
    }

    let mut provinces = Vec::with_capacity(game.provinces.len());
    let mut seen_ids = HashSet::with_capacity(game.provinces.len());
    let mut seen_keys = HashSet::with_capacity(game.provinces.len());
    for (serialized_key, province) in game.provinces {
        if !seen_keys.insert(serialized_key) {
            return Err(format!("duplicate_serialized_province_key:{serialized_key}").into());
        }
        let canonical_id = serialized_key
            .checked_abs()
            .ok_or("province_key_abs_overflow")?;
        if canonical_id <= 0 || canonical_id > i32::from(u16::MAX) {
            return Err(format!("province_id_out_of_range:{canonical_id}").into());
        }
        let province_id = canonical_id as u16;
        if !seen_ids.insert(province_id) {
            return Err(format!("duplicate_normalized_province_id:{province_id}").into());
        }
        provinces.push(ProvinceRow {
            province_id,
            serialized_key,
            cores: province.cores.into_iter().map(|tag| tag.to_string()).collect(),
            claims: province.claims.into_iter().map(|tag| tag.to_string()).collect(),
            discovered_by: province
                .discovered_by
                .map(|tags| tags.into_iter().map(|tag| tag.to_string()).collect()),
        });
    }
    provinces.sort_by_key(|row| row.province_id);

    let snapshot = Snapshot {
        schema: SCHEMA,
        saved_date: meta.date.game_fmt().to_string(),
        saved_version: SaveVersion {
            first: meta.savegame_version.first,
            second: meta.savegame_version.second,
            third: meta.savegame_version.third,
            fourth: meta.savegame_version.fourth,
            name: meta.savegame_version.name,
        },
        saved_player: meta.player.to_string(),
        country_tags,
        provinces,
    };
    let encoded = serde_json::to_vec(&snapshot)?;
    if encoded.len() + 1 > MAX_STDOUT_BYTES {
        return Err(format!(
            "stdout_size_limit_exceeded:{}>{MAX_STDOUT_BYTES}",
            encoded.len() + 1
        )
        .into());
    }
    let stdout = io::stdout();
    let mut locked = stdout.lock();
    locked.write_all(&encoded)?;
    locked.write_all(b"\n")?;
    Ok(())
}

fn parse_args() -> Result<(PathBuf, u64), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let mut max_bytes = DEFAULT_MAX_BYTES;
    let first = args
        .next()
        .ok_or("usage: eu4-save-provinces [--max-bytes N] <save-path>")?;
    let path = if first == "--max-bytes" {
        let value = args.next().ok_or("missing_max_bytes")?;
        let value = value.to_str().ok_or("max_bytes_not_utf8")?.parse::<u64>()?;
        if value == 0 || value > DEFAULT_MAX_BYTES {
            return Err("max_bytes_out_of_range".into());
        }
        max_bytes = value;
        PathBuf::from(args.next().ok_or("missing_save_path")?)
    } else {
        PathBuf::from(first)
    };
    if args.next().is_some() {
        return Err("unexpected_extra_argument".into());
    }
    if path.as_os_str().is_empty() || path.as_os_str() == "-" {
        return Err("save_path_must_be_explicit_file".into());
    }
    Ok((path, max_bytes))
}

fn read_input(path: &PathBuf, max_bytes: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err("save_path_not_regular_file".into());
    }
    if before.len() > max_bytes {
        return Err(format!("input_size_limit_exceeded:{}>{max_bytes}", before.len()).into());
    }

    let capacity = usize::try_from(before.len())?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("input_size_limit_exceeded:{}>{max_bytes}", bytes.len()).into());
    }
    let after = file.metadata()?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err("save_changed_during_read".into());
    }
    if bytes.len() as u64 != after.len() {
        return Err("save_read_size_mismatch".into());
    }
    Ok(bytes)
}
