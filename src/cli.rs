use clap::{Arg, Command};

pub fn build_cli() -> Command<'static> {
    Command::new("extract-chrome-cookies")
        .version("0.0.1")
        .about("Getting cookies by reading Chrome's cookie database on your computer.")
        .arg(
            Arg::new("url")
                .required(true)
                .help("Extract the cookie of this URL"),
        )
        // .arg(
        //     Arg::new("format")
        //         .short('f')
        //         .takes_value(true)
        //         .default_value("header")
        //         .validator(|v| {
        //             if FORMATS.contains(&v) {
        //                 return Ok(());
        //             }
        //             Err(format!("{}{:?}", "Must One of ", &FORMATS))
        //         })
        //         .help(FORMAT_HELP),
        // )
        .arg(
            Arg::new("browser")
                .short('b')
                .takes_value(true)
                .default_value("chrome")
                .help("Browser Name: chrome[default], edge"),
        )
        .arg(
            Arg::new("profile_name")
                .short('n')
                .takes_value(true)
                .default_value("Default")
                .help("Chrome Profile Name"),
        )
        .arg(
            Arg::new("profile_path")
                .short('p')
                .takes_value(true)
                .help("Direct pass chrome profile path"),
        )
}
