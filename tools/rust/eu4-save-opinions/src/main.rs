use eu4save::file::{Eu4FileEntryName, Eu4SliceFileKind};
use eu4save::models::SavegameVersion;
use eu4save::{CountryTag, Encoding, Eu4Date, Eu4File, PdsDate, SegmentedResolver};
use jomini::JominiDeserialize;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process;
use std::rc::Rc;

const DEFAULT_MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_COUNTRIES: usize = 4096;
const MAX_RAW_RELATIONS_PER_COUNTRY: usize = 4096;
const MAX_RAW_RELATION_ROWS: usize = MAX_COUNTRIES * MAX_RAW_RELATIONS_PER_COUNTRY;
const MAX_RETAINED_RELATION_ROWS: usize = 65_536;
const MAX_OPINION_ROWS: usize = 65_536;
const MAX_STRING_BYTES: usize = 256;
const MAX_DECIMAL_BYTES: usize = 64;
const SCHEMA: &str = "eu4.save_opinion_snapshot.v1";
const RELATION_PROJECTION: &str = "serialized_opinion_entries_only";

#[derive(Clone, Default)]
struct RowCounters {
    raw_relations: Rc<Cell<usize>>,
    retained_relations: Rc<Cell<usize>>,
    opinions: Rc<Cell<usize>>,
    relation_targets: Rc<RefCell<HashSet<String>>>,
}

fn bump<E: de::Error>(counter: &Cell<usize>, limit: usize, name: &str) -> Result<(), E> {
    let current = counter.get();
    if current >= limit {
        return Err(E::custom(format!("{name}_limit_exceeded")));
    }
    counter.set(current + 1);
    Ok(())
}

#[derive(JominiDeserialize)]
struct RawMeta {
    player: CountryTag,
    date: Eu4Date,
    savegame_version: SavegameVersion,
}

#[derive(JominiDeserialize)]
struct RawGame {
    #[jomini(default)]
    countries: Option<RawCountries>,
}

#[derive(JominiDeserialize)]
struct RawTextSave {
    player: CountryTag,
    date: Eu4Date,
    savegame_version: SavegameVersion,
    #[jomini(default)]
    countries: Option<RawCountries>,
}

#[derive(Debug)]
struct RawCountries {
    country_tags: Vec<String>,
    countries: Vec<CountrySnapshot>,
    relation_targets: HashSet<String>,
    raw_relation_rows_scanned: usize,
    retained_relation_rows: usize,
    opinion_rows: usize,
}

impl<'de> Deserialize<'de> for RawCountries {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CountriesVisitor;

        impl<'de> Visitor<'de> for CountriesVisitor {
            type Value = RawCountries;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("the saved country map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let counters = RowCounters::default();
                let mut country_tags = Vec::new();
                let mut seen_tags = HashSet::new();
                let mut countries = Vec::new();
                let mut raw_country_count = 0usize;

                while let Some(tag) = map.next_key::<CountryTag>()? {
                    if raw_country_count >= MAX_COUNTRIES {
                        return Err(de::Error::custom("country_count_limit_exceeded"));
                    }
                    raw_country_count += 1;
                    let name = (!tag.is_none()).then(|| tag.to_string());
                    if let Some(name) = name.as_ref() {
                        if !seen_tags.insert(name.clone()) {
                            return Err(de::Error::custom("duplicate_country_tag"));
                        }
                        country_tags.push(name.clone());
                        let country = map.next_value_seed(RawCountrySeed {
                            counters: counters.clone(),
                        })?;
                        countries.push(CountrySnapshot {
                            country: name.clone(),
                            active_relations: country.active_relations,
                        });
                    } else {
                        let _: IgnoredAny = map.next_value()?;
                    }
                }

                country_tags.sort();
                countries.sort_by(|left, right| left.country.cmp(&right.country));
                let relation_targets = counters.relation_targets.borrow().clone();
                Ok(RawCountries {
                    country_tags,
                    countries,
                    relation_targets,
                    raw_relation_rows_scanned: counters.raw_relations.get(),
                    retained_relation_rows: counters.retained_relations.get(),
                    opinion_rows: counters.opinions.get(),
                })
            }
        }

        deserializer.deserialize_map(CountriesVisitor)
    }
}

#[derive(Debug)]
struct RawCountry {
    active_relations: Option<Vec<RelationSnapshot>>,
}

struct RawCountrySeed {
    counters: RowCounters,
}

impl<'de> DeserializeSeed<'de> for RawCountrySeed {
    type Value = RawCountry;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CountryVisitor {
            counters: RowCounters,
        }

        impl<'de> Visitor<'de> for CountryVisitor {
            type Value = RawCountry;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a country record")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut active_seen = false;
                let mut active_relations = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "active_relations" {
                        if active_seen {
                            return Err(de::Error::custom("duplicate_country_active_relations"));
                        }
                        active_seen = true;
                        active_relations = map.next_value_seed(OptionalRelationsSeed {
                            counters: self.counters.clone(),
                        })?;
                    } else {
                        let _: IgnoredAny = map.next_value()?;
                    }
                }
                Ok(RawCountry { active_relations })
            }
        }

        deserializer.deserialize_map(CountryVisitor { counters: self.counters })
    }
}

struct OptionalRelationsSeed {
    counters: RowCounters,
}

impl<'de> DeserializeSeed<'de> for OptionalRelationsSeed {
    type Value = Option<Vec<RelationSnapshot>>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptionalRelationsVisitor {
            counters: RowCounters,
        }

        impl<'de> Visitor<'de> for OptionalRelationsVisitor {
            type Value = Option<Vec<RelationSnapshot>>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("null or an active-relations map")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer
                    .deserialize_map(RelationsVisitor { counters: self.counters })
                    .map(Some)
            }
        }

        deserializer.deserialize_option(OptionalRelationsVisitor { counters: self.counters })
    }
}

struct RelationsVisitor {
    counters: RowCounters,
}

impl<'de> Visitor<'de> for RelationsVisitor {
    type Value = Vec<RelationSnapshot>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("active relations keyed by country tag")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut rows = Vec::new();
        let mut seen = HashSet::new();
        let mut raw_relation_count = 0usize;
        while let Some(tag) = map.next_key::<CountryTag>()? {
            if raw_relation_count >= MAX_RAW_RELATIONS_PER_COUNTRY {
                return Err(de::Error::custom("raw_relation_rows_per_country_limit_exceeded"));
            }
            raw_relation_count += 1;
            bump::<A::Error>(&self.counters.raw_relations, MAX_RAW_RELATION_ROWS, "raw_relation_row")?;
            if tag.is_none() {
                return Err(de::Error::custom("active_relation_target_is_none"));
            }
            let name = tag.to_string();
            if !seen.insert(name.clone()) {
                return Err(de::Error::custom("duplicate_active_relation_country"));
            }
            {
                let mut targets = self.counters.relation_targets.borrow_mut();
                targets.insert(name.clone());
                if targets.len() > MAX_COUNTRIES {
                    return Err(de::Error::custom("relation_target_tag_set_limit_exceeded"));
                }
            }
            let relation = map.next_value_seed(RawRelationBodySeed {
                counters: self.counters.clone(),
                country: name.clone(),
            })?;
            if relation.opinions.as_ref().is_some_and(|opinions| !opinions.is_empty()) {
                rows.push(relation);
            }
        }
        Ok(rows)
    }
}

#[derive(Debug, Serialize)]
struct RelationSnapshot {
    country: String,
    opinions: Option<Vec<OpinionSnapshot>>,
}

#[derive(Debug, Serialize)]
struct OpinionSnapshot {
    modifier: String,
    date: Option<String>,
    current_opinion: Option<String>,
    expiry_date: Option<bool>,
}

#[derive(Debug)]
struct RawOpinion {
    modifier: Option<String>,
    date: Option<String>,
    current_opinion: Option<String>,
    expiry_date: Option<bool>,
}

impl RawOpinion {
    fn validate(&self) -> Result<(), String> {
        let modifier = self.modifier.as_ref()
            .ok_or_else(|| "opinion_modifier_missing".to_string())?;
        if modifier.is_empty() || modifier.len() > MAX_STRING_BYTES {
            return Err("opinion_modifier_invalid".into());
        }
        if let Some(value) = self.date.as_ref() {
            if value.len() > MAX_STRING_BYTES || !valid_game_date(value) {
                return Err("opinion_date_invalid".into());
            }
        }
        if let Some(value) = self.current_opinion.as_ref() {
            if value.len() > MAX_DECIMAL_BYTES || !valid_decimal(value) {
                return Err("current_opinion_decimal_invalid".into());
            }
        }
        Ok(())
    }

    fn into_snapshot(self) -> Result<OpinionSnapshot, String> {
        self.validate()?;
        Ok(OpinionSnapshot {
            modifier: self.modifier.ok_or_else(|| "opinion_modifier_missing".to_string())?,
            date: self.date,
            current_opinion: self.current_opinion,
            expiry_date: self.expiry_date,
        })
    }
}

impl<'de> Deserialize<'de> for RawOpinion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OpinionVisitor;

        impl<'de> Visitor<'de> for OpinionVisitor {
            type Value = RawOpinion;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one active opinion modifier row")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut modifier = None;
                let mut date = None;
                let mut current_opinion = None;
                let mut expiry_date = None;
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom(format!("duplicate_opinion_field:{key}")));
                    }
                    match key.as_str() {
                        "modifier" => modifier = map.next_value::<Option<String>>()?,
                        "date" => date = map.next_value::<Option<String>>()?,
                        "current_opinion" => current_opinion = map.next_value::<Option<String>>()?,
                        "expiry_date" => expiry_date = map.next_value::<Option<bool>>()?,
                        _ => {
                            let _: IgnoredAny = map.next_value()?;
                        }
                    }
                }
                let raw = RawOpinion { modifier, date, current_opinion, expiry_date };
                raw.validate().map_err(de::Error::custom)?;
                Ok(raw)
            }
        }

        deserializer.deserialize_map(OpinionVisitor)
    }
}

struct RawRelationBodySeed {
    counters: RowCounters,
    country: String,
}

impl<'de> DeserializeSeed<'de> for RawRelationBodySeed {
    type Value = RelationSnapshot;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RelationBodyVisitor {
            counters: RowCounters,
            country: String,
        }

        impl<'de> Visitor<'de> for RelationBodyVisitor {
            type Value = RelationSnapshot;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an active relation record")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut opinions: Option<Vec<OpinionSnapshot>> = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "opinion" {
                        if opinions.is_none() {
                            bump::<A::Error>(
                                &self.counters.retained_relations,
                                MAX_RETAINED_RELATION_ROWS,
                                "retained_relation_row",
                            )?;
                            opinions = Some(Vec::new());
                        }
                        bump::<A::Error>(&self.counters.opinions, MAX_OPINION_ROWS, "opinion_row")?;
                        let raw = map.next_value::<RawOpinion>()?;
                        let item = raw.into_snapshot().map_err(de::Error::custom)?;
                        if let Some(rows) = opinions.as_mut() {
                            rows.push(item);
                        } else {
                            return Err(de::Error::custom("opinion_vector_initialization_failed"));
                        }
                    } else {
                        if !seen.insert(key.clone()) {
                            return Err(de::Error::custom(format!("duplicate_relation_field:{key}")));
                        }
                        let _: IgnoredAny = map.next_value()?;
                    }
                }
                Ok(RelationSnapshot { country: self.country, opinions })
            }
        }

        deserializer.deserialize_map(RelationBodyVisitor {
            counters: self.counters,
            country: self.country,
        })
    }
}

fn valid_game_date(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(year) = parts.next() else { return false };
    let Some(month) = parts.next() else { return false };
    let Some(day) = parts.next() else { return false };
    parts.next().is_none()
        && !year.is_empty() && year.len() <= 4 && year.bytes().all(|b| b.is_ascii_digit())
        && !month.is_empty() && month.len() <= 2 && month.bytes().all(|b| b.is_ascii_digit())
        && !day.is_empty() && day.len() <= 2 && day.bytes().all(|b| b.is_ascii_digit())
}

fn valid_decimal(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_DECIMAL_BYTES {
        return false;
    }
    let mut index = usize::from(bytes[0] == b'-' || bytes[0] == b'+');
    if index == bytes.len() {
        return false;
    }
    let mut before = 0usize;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        before += 1;
        index += 1;
    }
    if before == 0 {
        return false;
    }
    if index == bytes.len() {
        return true;
    }
    if bytes[index] != b'.' {
        return false;
    }
    index += 1;
    let start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    index == bytes.len() && index > start
}

#[derive(Serialize)]
struct SaveVersion {
    first: u16,
    second: u16,
    third: u16,
    fourth: u16,
    name: String,
}

#[derive(Debug, Serialize)]
struct CountrySnapshot {
    country: String,
    active_relations: Option<Vec<RelationSnapshot>>,
}

#[derive(Serialize)]
struct Snapshot {
    schema: &'static str,
    relation_projection: &'static str,
    raw_relation_rows_scanned: usize,
    retained_relation_rows: usize,
    opinion_rows: usize,
    saved_date: String,
    saved_version: SaveVersion,
    saved_player: String,
    country_tags: Vec<String>,
    countries: Vec<CountrySnapshot>,
}

fn project_countries(raw: Option<RawCountries>) -> Result<(Vec<String>, Vec<CountrySnapshot>), String> {
    let raw = raw.ok_or_else(|| "country_map_missing".to_string())?;
    if raw.country_tags.len() > MAX_COUNTRIES {
        return Err("country_count_limit_exceeded".into());
    }
    let known: HashSet<&str> = raw.country_tags.iter().map(String::as_str).collect();
    if raw.countries.len() != known.len()
        || raw.countries.iter().any(|country| !known.contains(country.country.as_str()))
    {
        return Err("country_rows_do_not_match_country_tags".into());
    }
    if let Some(missing) = raw.relation_targets.iter().find(|target| !known.contains(target.as_str())) {
        return Err(format!("relation_target_missing_from_country_tags:{missing}"));
    }
    Ok((raw.country_tags, raw.countries))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("eu4-save-opinions: {error}");
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
    if file.size() as u64 > max_bytes {
        return Err(format!("expanded_size_limit_exceeded:{}>{max_bytes}", file.size()).into());
    }

    let (meta, countries) = match file.kind() {
        Eu4SliceFileKind::Text(text) => {
            let mut deserializer = text.deserializer();
            let flat = deserializer.deserialize::<RawTextSave>()?;
            (
                RawMeta { player: flat.player, date: flat.date,
                          savegame_version: flat.savegame_version },
                flat.countries,
            )
        }
        Eu4SliceFileKind::Zip(zip) => {
            let mut meta_entry = zip.get(Eu4FileEntryName::Meta)?;
            let meta = meta_entry.deserialize::<RawMeta, _>(SegmentedResolver::empty())?;
            let mut game_entry = zip.get(Eu4FileEntryName::Gamestate)?;
            let game = game_entry.deserialize::<RawGame, _>(SegmentedResolver::empty())?;
            (meta, game.countries)
        }
        Eu4SliceFileKind::Binary(_) => return Err("unsupported_encoding:Binary".into()),
    };

    let raw_countries = countries.ok_or("country_map_missing")?;
    let raw_relation_rows_scanned = raw_countries.raw_relation_rows_scanned;
    let retained_relation_rows = raw_countries.retained_relation_rows;
    let opinion_rows = raw_countries.opinion_rows;
    let (country_tags, countries) = project_countries(Some(raw_countries))?;
    let snapshot = Snapshot {
        schema: SCHEMA,
        relation_projection: RELATION_PROJECTION,
        raw_relation_rows_scanned,
        retained_relation_rows,
        opinion_rows,
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
        countries,
    };
    let encoded = serde_json::to_vec(&snapshot)?;
    if encoded.len() + 1 > MAX_STDOUT_BYTES {
        return Err(format!("stdout_size_limit_exceeded:{}>{MAX_STDOUT_BYTES}", encoded.len() + 1).into());
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
    let first = args.next().ok_or("usage: eu4-save-opinions [--max-bytes N] <save-path>")?;
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
    Read::by_ref(&mut file).take(max_bytes + 1).read_to_end(&mut bytes)?;
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
    use super::*;
    use jomini::text::de::from_windows1252_slice;
    use serde_json::json;

    fn parse_countries(input: &[u8]) -> Result<RawCountries, jomini::Error> {
        from_windows1252_slice(input)
    }

    #[test]
    fn preserves_relation_and_repeated_opinion_order_with_decimal_text_and_bools() {
        let raw = parse_countries(br#"FRA = { active_relations = {
            ENG = { opinion = { modifier = improved_relation date = 1446.5.18 current_opinion = 58.000 expiry_date = yes } opinion = { modifier = other date = 1450.1.2 current_opinion = -0.125 expiry_date = no } cached_sum = 77 trust_value = 10 attitude = friendly }
            BUR = { opinion = { modifier = rival date = 1446.5.18 current_opinion = 4 expiry_date = yes } }
        } } BUR = { } POR = { active_relations = { ENG = { opinion = { modifier = ignored } } } } ENG = { active_relations = { FRA = { opinion = { modifier = eng_supported_rebels_during_war_of_the_roses date = 1503.9.2 current_opinion = -44.788 expiry_date = no } } } }"#).unwrap();
        let (tags, countries) = project_countries(Some(raw)).unwrap();
        assert_eq!(tags, vec!["BUR", "ENG", "FRA", "POR"]);
        assert_eq!(countries.iter().map(|row| row.country.as_str()).collect::<Vec<_>>(), vec!["BUR", "ENG", "FRA", "POR"]);
        let fra = countries.iter().find(|row| row.country == "FRA").unwrap();
        let relations = fra.active_relations.as_ref().unwrap();
        assert_eq!(relations.iter().map(|row| row.country.as_str()).collect::<Vec<_>>(), vec!["ENG", "BUR"]);
        let opinions = relations[0].opinions.as_ref().unwrap();
        assert_eq!(opinions[0].modifier, "improved_relation");
        assert_eq!(opinions[0].date.as_deref(), Some("1446.5.18"));
        assert_eq!(opinions[0].current_opinion.as_deref(), Some("58.000"));
        assert_eq!(opinions[0].expiry_date, Some(true));
        assert_eq!(opinions[1].current_opinion.as_deref(), Some("-0.125"));
        assert_eq!(opinions[1].expiry_date, Some(false));
        let encoded = serde_json::to_value(&countries).unwrap();
        let encoded_fra = encoded.as_array().unwrap().iter().find(|row| row["country"] == "FRA").unwrap();
        assert_eq!(encoded_fra["active_relations"][0]["opinions"][0], json!({
            "modifier":"improved_relation", "date":"1446.5.18",
            "current_opinion":"58.000", "expiry_date":true
        }));
        assert!(encoded.to_string().contains("improved_relation"));
        assert!(!encoded.to_string().contains("cached_sum"));
        assert!(!encoded.to_string().contains("trust_value"));
        assert!(!encoded.to_string().contains("attitude"));
        let eng = countries.iter().find(|row| row.country == "ENG").unwrap();
        let reverse = &eng.active_relations.as_ref().unwrap()[0].opinions.as_ref().unwrap()[0];
        assert_eq!(reverse.modifier, "eng_supported_rebels_during_war_of_the_roses");
        assert_eq!(reverse.date.as_deref(), Some("1503.9.2"));
        assert_eq!(reverse.current_opinion.as_deref(), Some("-44.788"));
        assert_eq!(reverse.expiry_date, Some(false));
    }

    #[test]
    fn missing_and_explicitly_empty_relations_remain_distinct_from_empty_opinions() {
        let missing = parse_countries(b"FRA = { } POR = { active_relations = { } }").unwrap();
        let (_, projected) = project_countries(Some(missing)).unwrap();
        assert!(projected.iter().find(|row| row.country == "FRA").unwrap().active_relations.is_none());

        let empty = parse_countries(b"FRA = { active_relations = { } }").unwrap();
        let (_, projected) = project_countries(Some(empty)).unwrap();
        assert!(projected[0].active_relations.as_ref().unwrap().is_empty());

        let no_opinion = parse_countries(b"FRA = { active_relations = { ENG = { cached_sum = 1 } } } ENG = { }").unwrap();
        assert_eq!(no_opinion.raw_relation_rows_scanned, 1);
        assert_eq!(no_opinion.retained_relation_rows, 0);
        assert_eq!(no_opinion.opinion_rows, 0);
        let (_, projected) = project_countries(Some(no_opinion)).unwrap();
        assert!(projected.iter().find(|row| row.country == "FRA").unwrap().active_relations.as_ref().unwrap().is_empty());
    }

    #[test]
    fn singular_duplicates_and_duplicate_relation_targets_are_rejected() {
        for input in [
            b"FRA = { active_relations = { ENG = { opinion = { modifier = a modifier = b } } } }".as_slice(),
            b"FRA = { active_relations = { ENG = { cached_sum = 1 cached_sum = 2 } } }",
            b"FRA = { active_relations = { ENG = { } ENG = { } } }",
            b"FRA = { } FRA = { }",
        ] {
            assert!(parse_countries(input).is_err(), "accepted invalid input: {input:?}");
        }
    }

    #[test]
    fn malformed_decimal_date_boolean_and_input_are_rejected() {
        for input in [
            b"FRA = { active_relations = { ENG = { opinion = { current_opinion = 5e2 } } } }".as_slice(),
            b"FRA = { active_relations = { ENG = { opinion = { date = not_a_date } } } }",
            b"FRA = { active_relations = { ENG = { opinion = { expiry_date = 58.000 } } } }",
            b"FRA = { active_relations = {",
        ] {
            assert!(parse_countries(input).is_err(), "accepted invalid input: {input:?}");
        }
    }

    #[test]
    fn none_country_tags_are_filtered_and_invalid_relation_targets_fail_closed() {
        let raw = parse_countries(b"--- = { active_relations = { ENG = { } } } FRA = { active_relations = { ENG = { } } } ENG = { }").unwrap();
        let (tags, rows) = project_countries(Some(raw)).unwrap();
        assert_eq!(tags, vec!["ENG", "FRA"]);
        assert_eq!(rows.len(), 2);
        assert!(parse_countries(b"FRA = { active_relations = { --- = { } } }").is_err());
        assert!(project_countries(parse_countries(b"FRA = { active_relations = { ENG = { } } }").ok()).is_err());
    }

    #[test]
    fn explicit_country_and_opinion_row_limits_are_enforced_during_deserialization() {
        let mut country_text = String::new();
        for n in 0..=MAX_COUNTRIES {
            let tag = format!("{:03}", n);
            country_text.push_str(&format!("{tag} = {{ }} "));
        }
        assert!(parse_countries(country_text.as_bytes()).is_err());

        let mut opinion_text = String::from("FRA = { active_relations = { ENG = { ");
        for _ in 0..=MAX_OPINION_ROWS {
            opinion_text.push_str("opinion = { modifier = test } ");
        }
        opinion_text.push_str("} } }");
        assert!(parse_countries(opinion_text.as_bytes()).is_err());

        let relation_counter = Cell::new(MAX_RETAINED_RELATION_ROWS);
        assert!(bump::<serde::de::value::Error>(
            &relation_counter, MAX_RETAINED_RELATION_ROWS, "retained_relation_row"
        ).is_err());
    }

    fn synthetic_tags(count: usize) -> Vec<String> {
        (0..count).map(|value| {
            let first = (value / (26 * 26)) % 26;
            let second = (value / 26) % 26;
            let third = value % 26;
            format!("{}{}{}", (b'A' + first as u8) as char,
                    (b'A' + second as u8) as char, (b'A' + third as u8) as char)
        }).collect()
    }

    fn large_relation_fixture(retain_every_row: bool) -> String {
        let tags = synthetic_tags(MAX_COUNTRIES);
        let source_count = 17usize;
        let mut save = String::with_capacity(2_000_000);
        for (country_index, country_tag) in tags.iter().enumerate() {
            save.push_str(country_tag);
            save.push_str(" = { ");
            if country_index < source_count {
                save.push_str("active_relations = { ");
                for (target_index, target_tag) in tags.iter().enumerate() {
                    save.push_str(target_tag);
                    save.push_str(" = { ");
                    if retain_every_row || (country_index == 0 && target_index == 0) {
                        save.push_str("opinion = { modifier = sample } ");
                    }
                    save.push_str("} ");
                }
                save.push_str("} ");
            }
            save.push_str("} ");
        }
        save
    }

    #[test]
    fn raw_relation_rows_over_old_retained_limit_are_scanned_but_empty_rows_are_not_output() {
        let fixture = large_relation_fixture(false);
        let raw = parse_countries(fixture.as_bytes()).unwrap();
        let raw_rows = raw.raw_relation_rows_scanned;
        let target_tags = raw.relation_targets.len();
        let reported_retained = raw.retained_relation_rows;
        let (_, countries) = project_countries(Some(raw)).unwrap();
        assert_eq!(countries.len(), MAX_COUNTRIES);
        let retained_rows: usize = countries.iter().map(|row|
            row.active_relations.as_ref().map_or(0, Vec::len)
        ).sum();
        assert!(17 * MAX_COUNTRIES > MAX_RETAINED_RELATION_ROWS);
        assert_eq!(raw_rows, 17 * MAX_COUNTRIES);
        assert!(raw_rows > MAX_RETAINED_RELATION_ROWS);
        assert_eq!(target_tags, MAX_COUNTRIES);
        assert_eq!(reported_retained, 1);
        assert_eq!(retained_rows, 1);
        let first = countries.iter().find(|row| row.country == "AAA").unwrap();
        assert_eq!(first.active_relations.as_ref().unwrap().len(), 1);
        let next = countries.iter().find(|row| row.country == "AAB").unwrap();
        assert!(next.active_relations.as_ref().unwrap().is_empty());
    }

    #[test]
    fn retained_relation_limit_is_enforced_before_the_equal_opinion_limit() {
        let fixture = large_relation_fixture(true);
        let error = parse_countries(fixture.as_bytes()).unwrap_err().to_string();
        assert!(error.contains("retained_relation_row_limit_exceeded"), "{error}");
    }

    #[test]
    fn per_country_raw_relation_limit_is_enforced() {
        let tags = synthetic_tags(MAX_RAW_RELATIONS_PER_COUNTRY + 1);
        let mut relations = String::from("FRA = { active_relations = { ");
        for tag in tags {
            relations.push_str(&tag);
            relations.push_str(" = { } ");
        }
        relations.push_str("} }");
        let error = parse_countries(relations.as_bytes()).unwrap_err().to_string();
        assert!(error.contains("raw_relation_rows_per_country_limit_exceeded"), "{error}");
    }
}
