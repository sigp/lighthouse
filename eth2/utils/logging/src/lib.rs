use std::io::{Result, Write};

pub const MAX_MESSAGE_WIDTH: usize = 40;

pub struct AlignedTermDecorator {
    wrapped: slog_term::TermDecorator,
    message_width: usize,
}

impl AlignedTermDecorator {
    pub fn new(decorator: slog_term::TermDecorator, message_width: usize) -> AlignedTermDecorator {
        AlignedTermDecorator {
            wrapped: decorator,
            message_width,
        }
    }
}

impl slog_term::Decorator for AlignedTermDecorator {
    fn with_record<F>(
        &self,
        _record: &slog::Record,
        _logger_values: &slog::OwnedKVList,
        f: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut dyn slog_term::RecordDecorator) -> std::io::Result<()>,
    {
        self.wrapped.with_record(_record, _logger_values, |deco| {
            f(&mut AlignedRecordDecorator::new(deco, self.message_width))
        })
    }
}

struct AlignedRecordDecorator<'a> {
    wrapped: &'a mut dyn slog_term::RecordDecorator,
    message_count: usize,
    message_active: bool,
    ignore_comma: bool,
    message_width: usize,
}

impl<'a> AlignedRecordDecorator<'a> {
    fn new(
        decorator: &'a mut dyn slog_term::RecordDecorator,
        message_width: usize,
    ) -> AlignedRecordDecorator<'a> {
        AlignedRecordDecorator {
            wrapped: decorator,
            message_count: 0,
            ignore_comma: false,
            message_active: false,
            message_width,
        }
    }
}

impl<'a> Write for AlignedRecordDecorator<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.ignore_comma {
            //don't write comma
            self.ignore_comma = false;
            Ok(buf.len())
        } else if self.message_active {
            self.wrapped.write(buf).map(|n| {
                self.message_count += n;
                n
            })
        } else {
            self.wrapped.write(buf)
        }
    }

    fn flush(&mut self) -> Result<()> {
        self.wrapped.flush()
    }
}

impl<'a> slog_term::RecordDecorator for AlignedRecordDecorator<'a> {
    fn reset(&mut self) -> Result<()> {
        self.message_active = false;
        self.message_count = 0;
        self.ignore_comma = false;
        self.wrapped.reset()
    }

    fn start_whitespace(&mut self) -> Result<()> {
        self.wrapped.start_whitespace()
    }

    fn start_msg(&mut self) -> Result<()> {
        self.message_active = true;
        self.ignore_comma = false;
        self.wrapped.start_msg()
    }

    fn start_timestamp(&mut self) -> Result<()> {
        self.wrapped.start_timestamp()
    }

    fn start_level(&mut self) -> Result<()> {
        self.wrapped.start_level()
    }

    fn start_comma(&mut self) -> Result<()> {
        if self.message_active && self.message_count + 1 < self.message_width {
            self.ignore_comma = true;
        }
        self.wrapped.start_comma()
    }

    fn start_key(&mut self) -> Result<()> {
        if self.message_active && self.message_count + 1 < self.message_width {
            write!(
                self,
                "{}",
                std::iter::repeat(' ')
                    .take(self.message_width - self.message_count)
                    .collect::<String>()
            )?;
            self.message_active = false;
            self.message_count = 0;
            self.ignore_comma = false;
        }
        self.wrapped.start_key()
    }

    fn start_value(&mut self) -> Result<()> {
        self.wrapped.start_value()
    }

    fn start_separator(&mut self) -> Result<()> {
        self.wrapped.start_separator()
    }
}
