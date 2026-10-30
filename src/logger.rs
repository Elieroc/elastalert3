//! stderr logger: `LEVEL:elastalert:message` as upstream, plus opt-in timestamps, ANSI colors on a terminal and the
//! name of the rule being processed when the message does not already mention it.
use log::{Level, LevelFilter};
use std::io::IsTerminal;

tokio::task_local! {
    /// Rule whose run (or alert delivery) the current task is executing.
    pub static RULE: String;
}

pub struct Logger {
    level: LevelFilter,
    timestamps: bool,
    color: bool,
}

impl Logger {
    pub fn new(level: LevelFilter, timestamps: bool) -> Self {
        let forced = std::env::var_os("CLICOLOR_FORCE").is_some_and(|v| v != "0");
        let color = forced || (std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()));
        Logger { level, timestamps, color }
    }

    /// `--log-level` wins over `RUST_LOG` (only a bare level is read, no per-module filters).
    pub fn parse_level(arg: Option<&str>) -> Option<LevelFilter> {
        let env = std::env::var("RUST_LOG").ok();
        arg.or(env.as_deref()).and_then(|s| s.trim().parse().ok())
    }

    pub fn install(self, es_debug: bool) {
        let max = if es_debug { self.level.max(LevelFilter::Info) } else { self.level };
        log::set_logger(Box::leak(Box::new(self))).expect("logger set once");
        log::set_max_level(max);
    }

    fn paint(&self, code: &str, s: &str) -> String {
        if self.color { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
}

impl log::Log for Logger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= self.level || (m.target() == "elasticsearch" && m.level() <= log::max_level())
    }
    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let name = if r.target() == "elasticsearch" { "elasticsearch" } else { "elastalert" };
        let (level, code) = match r.level() {
            Level::Error => ("ERROR", "1;31"),
            Level::Warn => ("WARNING", "33"),
            Level::Info => ("INFO", "32"),
            Level::Debug => ("DEBUG", "36"),
            Level::Trace => ("TRACE", "2"),
        };
        let msg = r.args().to_string();
        // ponytail: substring check, a rule named like a word in the message hides the prefix; fine for a log hint.
        let rule = RULE.try_with(|n| if msg.contains(n.as_str()) { String::new() } else { format!("[{n}] ") }).unwrap_or_default();
        let ts = if self.timestamps { format!("{} ", self.paint("2", &chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string())) } else { String::new() };
        let rule = if rule.is_empty() { rule } else { self.paint("35", &rule) };
        eprintln!("{ts}{}:{}:{rule}{msg}", self.paint(code, level), self.paint("2", name));
    }
    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_argument_is_parsed() {
        assert_eq!(Logger::parse_level(Some("debug")), Some(LevelFilter::Debug));
        assert_eq!(Logger::parse_level(Some(" WARN ")), Some(LevelFilter::Warn));
        assert_eq!(Logger::parse_level(Some("bogus")), None);
    }
}
