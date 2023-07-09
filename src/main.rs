use clap::{Args, Parser, Subcommand};
use passwds::{Error, Keystore, UnlockedKeystore};
use rpassword::read_password;
use std::io::{stdout, Write};
use std::path::Path;
use std::process::exit;

#[derive(Debug, Parser)]
struct Arguments {
    #[arg(index = 1)]
    filename: String,
    #[command(subcommand)]
    action: Action,
}

impl Arguments {
    pub fn run(&self) {
        self.action.run(self.filename.as_str());
    }
}

#[derive(Debug, Subcommand)]
enum Action {
    #[command(long_about = "Show entries")]
    Show,
    #[command(long_about = "Add a new entry")]
    Add(Add),
}

impl Action {
    pub fn run(&self, filename: &str) {
        match self {
            Self::Show => {
                println!("{}", unlock_or_exit(&open_or_exit(filename)));
            }
            Self::Add(args) => {
                let mut unlocked;

                if let Some(keystore) = open_or_new_or_exit(filename) {
                    unlocked = unlock_or_exit(&keystore);
                } else {
                    unlocked = UnlockedKeystore::default();
                }

                unlocked.add(
                    args.password.as_str(),
                    args.login.as_deref(),
                    args.url.as_deref(),
                );
                save_or_exit(&lock_or_exit(unlocked), filename);
            }
        }
    }
}

#[derive(Debug, Args)]
struct Add {
    #[arg(index = 1, name = "password")]
    password: String,
    #[arg(long, short)]
    login: Option<String>,
    #[arg(long, short)]
    url: Option<String>,
}

fn main() {
    Arguments::parse().run();
}

fn open_or_exit(filename: impl AsRef<Path>) -> Keystore {
    Keystore::load(filename).unwrap_or_else(|error| {
        eprintln!("{error}");
        exit(1);
    })
}

fn open_or_new_or_exit(filename: impl AsRef<Path>) -> Option<Keystore> {
    match Keystore::load(filename) {
        Ok(keystore) => Some(keystore),
        Err(error) => {
            if let Error::IoError(_) = error {
                None
            } else {
                eprintln!("{error}");
                exit(1);
            }
        }
    }
}

fn save_or_exit(keystore: &Keystore, filename: impl AsRef<Path>) {
    keystore.save(filename).unwrap_or_else(|error| {
        eprintln!("{error:?}");
        exit(1);
    });
}

fn unlock_or_exit(keystore: &Keystore) -> UnlockedKeystore {
    keystore
        .unlock(read_password_or_exit().as_str())
        .unwrap_or_else(|error| {
            eprintln!("{error:?}");
            exit(1);
        })
}

fn lock_or_exit(unlocked: UnlockedKeystore) -> Keystore {
    unlocked
        .lock(read_password_or_exit().as_str())
        .unwrap_or_else(|error| {
            eprintln!("{error}");
            exit(1);
        })
}

fn read_password_or_exit() -> String {
    print!("Enter password: ");
    stdout().flush().unwrap_or_else(drop);
    read_password().unwrap_or_else(|error| {
        eprintln!("{error}");
        exit(2);
    })
}
