use eu4save::file::{Eu4FileEntryName, Eu4SliceFileKind};
use eu4save::models::SavegameVersion;
use eu4save::{CountryTag, Encoding, Eu4Date, Eu4File, PdsDate, SegmentedResolver};
use jomini::JominiDeserialize;
use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process;

const DEFAULT_MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_STDOUT_BYTES: usize = 4 * 1024 * 1024;
const SCHEMA: &str = "eu4.save_empire_snapshot.v1";

#[derive(JominiDeserialize)]
struct RawMeta {
    player: CountryTag,
    date: Eu4Date,
    savegame_version: SavegameVersion,
}

/// A presence-aware view of the save's optional empire block.
///
/// `passed_reform` is intentionally collected from repeated scalar entries.
/// Singular fields reject duplicate map entries instead of applying last-wins.
#[derive(Debug, PartialEq)]
struct RawEmpire {
    emperor: Option<CountryTag>,
    electors: Option<Vec<CountryTag>>,
    passed_reforms: Option<Vec<String>>,
}

struct RawEmpireVisitor;

impl<'de> Visitor<'de> for RawEmpireVisitor {
    type Value = RawEmpire;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an empire object with optional emperor, electors, and repeated passed_reform entries")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut emperor = None;
        let mut emperor_seen = false;
        let mut electors = None;
        let mut electors_seen = false;
        let mut passed_reforms: Option<Vec<String>> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "emperor" => {
                    if emperor_seen {
                        return Err(de::Error::custom("duplicate_empire_emperor"));
                    }
                    emperor_seen = true;
                    emperor = map.next_value::<Option<CountryTag>>()?;
                }
                "electors" => {
                    if electors_seen {
                        return Err(de::Error::custom("duplicate_empire_electors"));
                    }
                    electors_seen = true;
                    electors = map.next_value::<Option<Vec<CountryTag>>>()?;
                }
                "passed_reform" | "passed_reforms" => {
                    let value = map.next_value::<String>()?;
                    passed_reforms.get_or_insert_with(Vec::new).push(value);
                }
                _ => {
                    let _: IgnoredAny = map.next_value()?;
                }
            }
        }

        Ok(RawEmpire {
            emperor,
            electors,
            passed_reforms,
        })
    }
}

impl<'de> Deserialize<'de> for RawEmpire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RawEmpireVisitor)
    }
}

#[derive(JominiDeserialize)]
struct RawGame {
    #[jomini(default, deserialize_with = "eu4save::de::deserialize_vec_pair")]
    countries: Vec<(CountryTag, IgnoredAny)>,
    #[jomini(default)]
    empire: Option<RawEmpire>,
}

#[derive(JominiDeserialize)]
struct RawTextSave {
    player: CountryTag,
    date: Eu4Date,
    savegame_version: SavegameVersion,
    #[jomini(default, deserialize_with = "eu4save::de::deserialize_vec_pair")]
    countries: Vec<(CountryTag, IgnoredAny)>,
    #[jomini(default)]
    empire: Option<RawEmpire>,
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
struct EmpireSnapshot {
    emperor: Option<String>,
    electors: Option<Vec<String>>,
    passed_reforms: Option<Vec<String>>,
}

#[derive(Serialize)]
struct Snapshot {
    schema: &'static str,
    saved_date: String,
    saved_version: SaveVersion,
    saved_player: String,
    country_tags: Vec<String>,
    empire: Option<EmpireSnapshot>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("eu4-save-empire: {error}");
        process::exit(2);
    }
}

fn project_empire(raw: Option<RawEmpire>) -> Option<EmpireSnapshot> {
    raw.map(|empire| EmpireSnapshot {
        emperor: empire
            .emperor
            .and_then(|tag| (!tag.is_none()).then(|| tag.to_string())),
        electors: empire.electors.map(|tags| tags.into_iter().map(|tag| tag.to_string()).collect()),
        passed_reforms: empire.passed_reforms,
    })
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
                    empire: flat.empire,
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
        empire: project_empire(game.empire),
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
        .ok_or("usage: eu4-save-empire [--max-bytes N] <save-path>")?;
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

#[cfg(test)]
mod tests {
    use super::{project_empire, RawEmpire};
    use jomini::text::de::from_windows1252_slice;
    use serde_json::json;

    fn parse_empire(input: &[u8]) -> Result<RawEmpire, jomini::Error> {
        from_windows1252_slice(input)
    }

    #[test]
    fn repeated_passed_reforms_are_preserved_and_missing_fields_stay_null() {
        let raw = parse_empire(
            b"emperor = FRA passed_reform = reform_a passed_reform = reform_b",
        )
        .unwrap();
        let projected = project_empire(Some(raw)).unwrap();
        assert_eq!(projected.emperor.as_deref(), Some("FRA"));
        assert_eq!(projected.electors, None);
        assert_eq!(
            projected.passed_reforms.as_ref().unwrap(),
            &vec![String::from("reform_a"), String::from("reform_b")]
        );
        assert_eq!(serde_json::to_value(projected).unwrap(), json!({
            "emperor": "FRA", "electors": null,
            "passed_reforms": ["reform_a", "reform_b"]
        }));
    }

    #[test]
    fn explicit_empty_electors_differ_from_a_missing_field() {
        let raw = parse_empire(b"electors = {}").unwrap();
        let projected = project_empire(Some(raw)).unwrap();
        assert_eq!(projected.emperor, None);
        assert_eq!(projected.electors, Some(Vec::new()));
        assert_eq!(projected.passed_reforms, None);
        assert_eq!(serde_json::to_value(projected).unwrap(), json!({
            "emperor": null, "electors": [], "passed_reforms": null
        }));
    }

    #[test]
    fn empty_emperor_is_null_without_a_vacancy_inference() {
        let raw = parse_empire(b"emperor = ---").unwrap();
        let projected = project_empire(Some(raw)).unwrap();
        assert_eq!(projected.emperor, None);
        assert_eq!(serde_json::to_value(projected).unwrap(), json!({
            "emperor": null, "electors": null, "passed_reforms": null
        }));
    }

    #[test]
    fn duplicate_singular_empire_fields_are_rejected() {
        assert!(parse_empire(b"emperor = FRA emperor = ENG").is_err());
        assert!(parse_empire(b"electors = { FRA } electors = { ENG }").is_err());
    }

    #[test]
    fn absent_empire_remains_null() {
        assert!(project_empire(None).is_none());
    }
}
