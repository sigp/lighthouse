/// Serialise and deserialise `std::time::Instant`s
/// 
/// Due to David Tolnay via: https://github.com/serde-rs/serde/issues/1375#issuecomment-419688068
use std::time::{Instant, SystemTime};
use serde::{Serialize, Serializer, Deserialize, Deserializer, de::Error};

pub fn serialize<S>(instant: &Instant, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let system_now = SystemTime::now();
    let instant_now = Instant::now();
    let approx = system_now - (instant_now - *instant);
    approx.serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Instant, D::Error>
where
    D: Deserializer<'de>,
{
    let de = SystemTime::deserialize(deserializer)?;
    let system_now = SystemTime::now();
    let instant_now = Instant::now();
    let duration = system_now.duration_since(de).map_err(Error::custom)?;
    let approx = instant_now - duration;
    Ok(approx)
}