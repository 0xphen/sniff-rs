use fern::{
    colors::{Color, ColoredLevelConfig},
    Dispatch, InitError,
};
use humantime;
use log::{debug, error, info, trace, warn};
use std::time::SystemTime;

pub fn setup_logger() -> Result<(), InitError> {
    let colors_line = ColoredLevelConfig::new()
        .info(Color::White)
        .warn(Color::Yellow)
        .error(Color::Red)
        .debug(Color::Blue)
        .trace(Color::Magenta);

    let colors_level = colors_line.info(Color::Green);
    Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{color_line}[{date} {level} {color_line}] {message}\x1B[0m",
                color_line = format_args!(
                    "\x1B[{}m",
                    colors_line.get_color(&record.level()).to_fg_str()
                ),
                date = humantime::format_rfc3339_seconds(SystemTime::now()),
                level = colors_level.color(record.level()),
                message = message,
            ));
        })
        .level(log::LevelFilter::Debug)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}
