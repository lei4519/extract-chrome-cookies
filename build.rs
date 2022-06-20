use clap_complete::{
    generate_to,
    shells::{Bash, Fish, Zsh},
};
use std::{env, io::Error};

include!("src/cli.rs");

fn main() -> Result<(), Error> {
    let name = "extract-chrome-cookies";

    let mut release_dir = env::current_dir()?;
    release_dir.push("target/release");

    let mut cmd = build_cli();

    generate_to(Bash, &mut cmd, name, &release_dir)?;

    generate_to(Zsh, &mut cmd, name, &release_dir)?;

    generate_to(Fish, &mut cmd, name, &release_dir)?;

    Ok(())
}
