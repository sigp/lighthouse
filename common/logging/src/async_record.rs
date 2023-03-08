//! An object that can be used to pass through a channel and be cloned. It can therefore be used
//! via the broadcast channel.

use slog::{
    BorrowedKV, Drain, Key, Level, OwnedKVList, Record, RecordStatic, Serializer, SingleKV, KV,
};
use std::fmt;
use std::sync::Arc;
use take_mut::take;

/// Serialized record.
#[derive(Clone)]
pub struct AsyncRecord {
    msg: String,
    level: Level,
    location: Box<slog::RecordLocation>,
    tag: String,
    logger_values: OwnedKVList,
    kv: Arc<dyn KV + Send>,
}

impl AsyncRecord {
    /// Serializes a `Record` and an `OwnedKVList`.
    pub fn from(record: &Record, logger_values: &OwnedKVList) -> Self {
        let mut ser = ToSendSerializer::new();
        record
            .kv()
            .serialize(record, &mut ser)
            .expect("`ToSendSerializer` can't fail");

        AsyncRecord {
            msg: fmt::format(*record.msg()),
            level: record.level(),
            location: Box::new(*record.location()),
            tag: String::from(record.tag()),
            logger_values: logger_values.clone(),
            kv: Arc::new(ser.finish()),
        }
    }

    /// Writes the record to a `Drain`.
    pub fn log_to<D: Drain>(self, drain: &D) -> Result<D::Ok, D::Err> {
        let rs = RecordStatic {
            location: &*self.location,
            level: self.level,
            tag: &self.tag,
        };

        drain.log(
            &Record::new(&rs, &format_args!("{}", self.msg), BorrowedKV(&self.kv)),
            &self.logger_values,
        )
    }

    /// Deconstruct this `AsyncRecord` into a record and `OwnedKVList`.
    pub fn as_record_values(&self, mut f: impl FnMut(&Record, &OwnedKVList)) {
        let rs = RecordStatic {
            location: &*self.location,
            level: self.level,
            tag: &self.tag,
        };

        f(
            &Record::new(&rs, &format_args!("{}", self.msg), BorrowedKV(&self.kv)),
            &self.logger_values,
        )
    }
}

pub struct ToSendSerializer {
    kv: Box<dyn KV + Send>,
}

impl ToSendSerializer {
    fn new() -> Self {
        ToSendSerializer { kv: Box::new(()) }
    }

    fn finish(self) -> Box<dyn KV + Send> {
        self.kv
    }
}

impl Serializer for ToSendSerializer {
    fn emit_bool(&mut self, key: Key, val: bool) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_unit(&mut self, key: Key) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, ()))));
        Ok(())
    }
    fn emit_none(&mut self, key: Key) -> slog::Result {
        let val: Option<()> = None;
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_char(&mut self, key: Key, val: char) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_u8(&mut self, key: Key, val: u8) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_i8(&mut self, key: Key, val: i8) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_u16(&mut self, key: Key, val: u16) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_i16(&mut self, key: Key, val: i16) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_u32(&mut self, key: Key, val: u32) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_i32(&mut self, key: Key, val: i32) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_f32(&mut self, key: Key, val: f32) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_u64(&mut self, key: Key, val: u64) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_i64(&mut self, key: Key, val: i64) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_f64(&mut self, key: Key, val: f64) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    #[cfg(integer128)]
    fn emit_u128(&mut self, key: Key, val: u128) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    #[cfg(integer128)]
    fn emit_i128(&mut self, key: Key, val: i128) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_usize(&mut self, key: Key, val: usize) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_isize(&mut self, key: Key, val: isize) -> slog::Result {
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_str(&mut self, key: Key, val: &str) -> slog::Result {
        let val = val.to_owned();
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
    fn emit_arguments(&mut self, key: Key, val: &fmt::Arguments) -> slog::Result {
        let val = fmt::format(*val);
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }

    #[cfg(feature = "nested-values")]
    fn emit_serde(&mut self, key: Key, value: &slog::SerdeValue) -> slog::Result {
        let val = value.to_sendable();
        take(&mut self.kv, |kv| Box::new((kv, SingleKV(key, val))));
        Ok(())
    }
}
