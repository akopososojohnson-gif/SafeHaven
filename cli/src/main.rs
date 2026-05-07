mod api;
mod commands;
mod config;
mod storage;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "safehaven")]
#[command(about = "SafeHaven CLI — zero-knowledge secrets vault")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authentication commands
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// Vault commands
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    /// Share commands
    Share {
        #[command(subcommand)]
        command: ShareCommands,
    },
    /// Generate secure passwords
    Generate {
        #[command(subcommand)]
        command: GenerateCommands,
    },
    /// Show current user
    Me,
    /// Check server health
    Health {
        /// Server URL override
        #[arg(long)]
        server: Option<String>,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Log in to SafeHaven
    Login {
        /// Email address
        email: String,
        /// Server URL
        #[arg(long)]
        server: Option<String>,
    },
    /// Register a new account
    Register {
        /// Email address
        email: String,
        /// Server URL
        #[arg(long)]
        server: Option<String>,
    },
    /// Log out
    Logout,
}

#[derive(Subcommand)]
enum VaultCommands {
    /// List vault items
    List,
    /// Add an item to the vault
    Add {
        /// Item type (password, secure_note, etc.)
        #[arg(short, long, default_value = "password")]
        item_type: String,
        /// Blob content (base64 or raw string)
        blob: String,
    },
    /// Delete a vault item
    Delete {
        /// Item ID
        id: String,
    },
}

#[derive(Subcommand)]
enum ShareCommands {
    /// Create a share link
    Create {
        /// Blob to share
        blob: String,
        /// Expiry in hours
        #[arg(short, long, default_value = "24")]
        expiry: u32,
    },
    /// Redeem a share link
    Redeem {
        /// Share ID
        share_id: String,
    },
}

#[derive(Subcommand)]
enum GenerateCommands {
    /// Generate a random password
    Password {
        /// Password length
        #[arg(short, long, default_value = "32")]
        length: usize,
        /// Include symbols
        #[arg(short, long, default_value = "true")]
        symbols: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Auth { command } => match command {
            AuthCommands::Login { email, server } => {
                let password = rpassword::prompt_password("Password: ")?;
                commands::auth::login(&email, &password, server.as_deref()).await
            }
            AuthCommands::Register { email, server } => {
                let password = rpassword::prompt_password("Password: ")?;
                let confirm = rpassword::prompt_password("Confirm: ")?;
                if password != confirm {
                    anyhow::bail!("passwords do not match");
                }
                commands::auth::register(&email, &password, server.as_deref()).await
            }
            AuthCommands::Logout => commands::auth::logout().await,
        },
        Commands::Vault { command } => match command {
            VaultCommands::List => commands::vault::list().await,
            VaultCommands::Add { item_type, blob } => commands::vault::add(&item_type, &blob).await,
            VaultCommands::Delete { id } => commands::vault::delete(&id).await,
        },
        Commands::Share { command } => match command {
            ShareCommands::Create { blob, expiry } => {
                commands::share::create(&blob, expiry).await
            }
            ShareCommands::Redeem { share_id } => {
                commands::share::redeem(&share_id).await
            }
        },
        Commands::Generate { command } => match command {
            GenerateCommands::Password { length, symbols } => {
                commands::generate::password(length, symbols)
            }
        },
        Commands::Me => {
            let token = storage::get_token()?.ok_or_else(|| anyhow::anyhow!("not logged in"))?;
            let cfg = config::Config::load();
            let client = api::ApiClient::with_token(&cfg.server_url, &token);
            let me = client.me().await?;
            println!("Email:        {}", me.email);
            println!("ID:           {}", me.id);
            println!("MFA Enabled:  {}", me.mfa_enabled);
            println!("Storage:      {} / {} bytes", me.storage_used_bytes, me.storage_quota_bytes);
            Ok(())
        }
        Commands::Health { server } => {
            let cfg = config::Config::load();
            let base = server.as_deref().unwrap_or(&cfg.server_url);
            let client = api::ApiClient::new(base);
            let health = client.health().await?;
            println!("Server: {}", base);
            println!("Health: {}", health);
            Ok(())
        }
    }
}
