#[macro_use]
extern crate rust_i18n;

use anyhow::{Context, Result};
use clap::{Arg, ArgAction, Command, Subcommand};
use lettre::{
    SmtpTransport, Transport,
    message::{Mailbox, Message, MultiPart, SinglePart, header::ContentType},
    transport::smtp::authentication::Credentials,
};
use magic_crypt::{MagicCryptTrait, new_magic_crypt};
use serde::Deserialize;
use std::{fs, path::PathBuf};

i18n!("locales", fallback = "en");

const ENCRYPTION_HEADER: &str = "RUSTMAIL_ENCRYPTED_V1\n";

/// Represents the final, validated arguments for the application.
struct Args {
    smtp_server: String,
    smtp_port: u16,
    smtp_username: String,
    smtp_password: String,
    from_name: Option<String>,
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    subject: String,
    body: String,
    body_html: Option<String>,
    attachment: Vec<PathBuf>,
    smtps: bool,
}

/// Represents the structure of the YAML config file. All fields are optional.
#[derive(Deserialize, Default, Debug)]
struct ConfigFile {
    smtp_server: Option<String>,
    smtp_port: Option<u16>,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
    from_name: Option<String>,
    to: Option<Vec<String>>,
    cc: Option<Vec<String>>,
    bcc: Option<Vec<String>>,
}

#[derive(Subcommand, Debug)]
enum CliSubCommand {
    /// Encrypts a configuration file.
    Encrypt {
        /// The configuration file to encrypt.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Decrypts a configuration file.
    Decrypt {
        /// The configuration file to decrypt.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Sends an email with the given options.
    Send {
        #[arg(long, env = "SMTP_SERVER", help_heading = "SMTP")]
        smtp_server: Option<String>,
        #[arg(long, env = "SMTP_PORT", help_heading = "SMTP")]
        smtp_port: Option<u16>,
        #[arg(long, env = "SMTP_USERNAME", help_heading = "SMTP")]
        smtp_username: Option<String>,
        #[arg(long, env = "SMTP_PASSWORD", help_heading = "SMTP")]
        smtp_password: Option<String>,
        #[arg(long, help_heading = "Email")]
        from_name: Option<String>,
        #[arg(long, action = ArgAction::Append, value_delimiter = ',', help_heading = "Email")]
        to: Vec<String>,
        #[arg(long, action = ArgAction::Append, value_delimiter = ',', help_heading = "Email")]
        cc: Vec<String>,
        #[arg(long, action = ArgAction::Append, value_delimiter = ',', help_heading = "Email")]
        bcc: Vec<String>,
        #[arg(long, required = true, help_heading = "Content")]
        subject: String,
        #[arg(long, required = true, help_heading = "Content")]
        body: String,
        #[arg(long, help_heading = "Content")]
        body_html: Option<String>,
        #[arg(long, action = ArgAction::Append, value_parser = clap::value_parser!(PathBuf), help_heading = "Content")]
        attachment: Vec<PathBuf>,
        #[arg(long, action = ArgAction::SetTrue, help_heading = "SMTP")]
        smtps: bool,
    },
}

fn main() -> Result<()> {
    let cli = build_cli().get_matches();

    match cli.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let file = sub_matches.get_one::<PathBuf>("file").unwrap();
            handle_encrypt(file)
        }
        Some(("decrypt", sub_matches)) => {
            let file = sub_matches.get_one::<PathBuf>("file").unwrap();
            handle_decrypt(file)
        }
        Some(("send", sub_matches)) => handle_send(sub_matches),
        _ => {
            build_cli().print_help()?;
            Ok(())
        }
    }
}

fn handle_encrypt(file: &PathBuf) -> Result<()> {
    let content = fs::read_to_string(file)
        .with_context(|| format!("Failed to read file for encryption: {:?}", file))?;

    if content.starts_with(ENCRYPTION_HEADER) {
        println!("{}", t!("already_encrypted"));
        return Ok(());
    }

    println!("{}", t!("enter_password_encrypt"));
    let password = rpassword::prompt_password("Password: ")?;
    let confirm_password = rpassword::prompt_password("Confirm Password: ")?;

    if password != confirm_password {
        return Err(anyhow::anyhow!(t!("password_mismatch")));
    }

    let crypter = new_magic_crypt!(&password, 256);
    let encrypted_string = crypter.encrypt_str_to_base64(content);

    let final_content = format!("{}{}", ENCRYPTION_HEADER, encrypted_string);
    fs::write(file, final_content)
        .with_context(|| format!("Failed to write encrypted file: {:?}", file))?;

    println!("{}", t!("encrypt_success", file = file.to_string_lossy()));
    Ok(())
}

fn handle_decrypt(file: &PathBuf) -> Result<()> {
    let content = fs::read_to_string(file)
        .with_context(|| format!("Failed to read file for decryption: {:?}", file))?;

    if !content.starts_with(ENCRYPTION_HEADER) {
        println!("{}", t!("not_encrypted"));
        return Ok(());
    }

    let encrypted_b64 = content.strip_prefix(ENCRYPTION_HEADER).unwrap();

    println!("{}", t!("enter_password_decrypt"));
    let password = rpassword::prompt_password("Password: ")?;

    let crypter = new_magic_crypt!(&password, 256);
    let decrypted_string = crypter
        .decrypt_base64_to_string(encrypted_b64)
        .map_err(|e| anyhow::anyhow!(t!("decryption_failed")).context(e))?;

    fs::write(file, decrypted_string)
        .with_context(|| format!("Failed to write decrypted file: {:?}", file))?;

    println!("{}", t!("decrypt_success", file = file.to_string_lossy()));
    Ok(())
}

fn handle_send(cli_matches: &clap::ArgMatches) -> Result<()> {
    let args = parse_and_merge_args(cli_matches)?;
    let mailer = build_mailer(&args)?;
    let email = build_message(&args)?;

    match mailer.send(&email) {
        Ok(_) => {
            println!("{}", t!("success_sent"));
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!(t!("fail_sent")).context(e)),
    }
}

/// Loads configuration from the YAML file if it exists.
fn load_config() -> Result<ConfigFile> {
    let config_path = dirs::config_dir()
        .context("Could not find config directory")?
        .join("rustmail/mail.yaml");

    if !config_path.exists() {
        return Ok(ConfigFile::default());
    }

    let mut content = fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file at {:?}", config_path))?;

    if content.starts_with(ENCRYPTION_HEADER) {
        println!("{}", t!("config_encrypted_prompt"));
        let password = rpassword::prompt_password("Password: ")?;
        let encrypted_b64 = content.strip_prefix(ENCRYPTION_HEADER).unwrap();
        let crypter = new_magic_crypt!(&password, 256);
        content = crypter
            .decrypt_base64_to_string(encrypted_b64)
            .map_err(|e| anyhow::anyhow!(t!("decryption_failed")).context(e))?;
    }

    let config: ConfigFile = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse config file at {:?}", config_path))?;

    Ok(config)
}

/// Parses CLI arguments, loads config file, and merges them.
fn parse_and_merge_args(cli_matches: &clap::ArgMatches) -> Result<Args> {
    let config = load_config()?;

    // Merge and validate required fields
    let smtp_server = cli_matches
        .get_one::<String>("smtp_server")
        .cloned()
        .or(config.smtp_server)
        .context(t!("arg_error.missing_server"))?;

    let smtp_username = cli_matches
        .get_one::<String>("smtp_username")
        .cloned()
        .or(config.smtp_username)
        .context(t!("arg_error.missing_username"))?;

    let smtp_password = cli_matches
        .get_one::<String>("smtp_password")
        .cloned()
        .or(config.smtp_password)
        .context(t!("arg_error.missing_password"))?;

    // Merge optional fields
    let smtp_port = cli_matches
        .get_one::<u16>("smtp_port")
        .copied()
        .or(config.smtp_port)
        .unwrap_or(587);

    let from_name = cli_matches
        .get_one::<String>("from_name")
        .cloned()
        .or(config.from_name);

    let to = cli_matches
        .get_many::<String>("to")
        .map(|vals| vals.cloned().collect())
        .filter(|v: &Vec<String>| !v.is_empty())
        .or(config.to)
        .unwrap_or_default();

    let cc = cli_matches
        .get_many::<String>("cc")
        .map(|vals| vals.cloned().collect())
        .filter(|v: &Vec<String>| !v.is_empty())
        .or(config.cc)
        .unwrap_or_default();

    let bcc = cli_matches
        .get_many::<String>("bcc")
        .map(|vals| vals.cloned().collect())
        .filter(|v: &Vec<String>| !v.is_empty())
        .or(config.bcc)
        .unwrap_or_default();

    let args = Args {
        smtp_server,
        smtp_port,
        smtp_username,
        smtp_password,
        from_name,
        to,
        cc,
        bcc,
        subject: cli_matches.get_one::<String>("subject").cloned().unwrap(),
        body: cli_matches.get_one::<String>("body").cloned().unwrap(),
        body_html: cli_matches.get_one::<String>("body_html").cloned(),
        attachment: cli_matches
            .get_many::<PathBuf>("attachment")
            .unwrap_or_default()
            .cloned()
            .collect(),
        smtps: cli_matches.get_flag("smtps"),
    };

    if args.to.is_empty() && args.cc.is_empty() && args.bcc.is_empty() {
        return Err(anyhow::anyhow!(t!("arg_error.missing_recipient")));
    }

    Ok(args)
}

fn build_cli() -> Command {
    Command::new("rustmail")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(t!("app_about"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("send")
                .about("Sends an email")
                .arg(
                    Arg::new("smtp_server")
                        .long("smtp-server")
                        .env("SMTP_SERVER")
                        .help(t!("smtp_server_help")),
                )
                .arg(
                    Arg::new("smtp_port")
                        .long("smtp-port")
                        .env("SMTP_PORT")
                        .value_parser(clap::value_parser!(u16))
                        .help(t!("smtp_port_help")),
                )
                .arg(
                    Arg::new("smtp_username")
                        .long("smtp-username")
                        .env("SMTP_USERNAME")
                        .help(t!("smtp_username_help")),
                )
                .arg(
                    Arg::new("smtp_password")
                        .long("smtp-password")
                        .env("SMTP_PASSWORD")
                        .help(t!("smtp_password_help")),
                )
                .arg(
                    Arg::new("from_name")
                        .long("from-name")
                        .help(t!("from_name_help")),
                )
                .arg(
                    Arg::new("to")
                        .long("to")
                        .action(ArgAction::Append)
                        .value_delimiter(',')
                        .help(t!("to_help")),
                )
                .arg(
                    Arg::new("cc")
                        .long("cc")
                        .action(ArgAction::Append)
                        .value_delimiter(',')
                        .help(t!("cc_help")),
                )
                .arg(
                    Arg::new("bcc")
                        .long("bcc")
                        .action(ArgAction::Append)
                        .value_delimiter(',')
                        .help(t!("bcc_help")),
                )
                .arg(
                    Arg::new("subject")
                        .long("subject")
                        .required(true)
                        .help(t!("subject_help")),
                )
                .arg(
                    Arg::new("body")
                        .long("body")
                        .required(true)
                        .help(t!("body_help")),
                )
                .arg(
                    Arg::new("body_html")
                        .long("body-html")
                        .help(t!("body_html_help")),
                )
                .arg(
                    Arg::new("attachment")
                        .long("attachment")
                        .action(ArgAction::Append)
                        .value_parser(clap::value_parser!(PathBuf))
                        .help(t!("attachment_help")),
                )
                .arg(
                    Arg::new("smtps")
                        .long("smtps")
                        .action(ArgAction::SetTrue)
                        .help(t!("smtps_help")),
                ),
        )
        .subcommand(
            Command::new("encrypt")
                .about("Encrypts a configuration file")
                .arg(
                    Arg::new("file")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf)),
                ),
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypts a configuration file")
                .arg(
                    Arg::new("file")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf)),
                ),
        )
}

/// Configures and builds the SMTP transport (mailer).
fn build_mailer(args: &Args) -> Result<SmtpTransport> {
    let creds = Credentials::new(args.smtp_username.clone(), args.smtp_password.clone());

    let relay_builder = if args.smtps {
        SmtpTransport::relay(&args.smtp_server)?
    } else {
        SmtpTransport::starttls_relay(&args.smtp_server)?
    };

    let mailer = relay_builder
        .port(args.smtp_port)
        .credentials(creds)
        .build();

    Ok(mailer)
}

/// Constructs the email message from arguments.
fn build_message(args: &Args) -> Result<Message> {
    let from_mailbox = if let Some(name) = &args.from_name {
        Mailbox::new(
            Some(name.clone()),
            args.smtp_username
                .parse()
                .context("Invalid 'from' email address")?,
        )
    } else {
        args.smtp_username
            .parse()
            .context("Invalid 'from' email address")?
    };

    let mut builder = Message::builder().from(from_mailbox);

    for recipient in &args.to {
        builder = builder.to(recipient.parse().context("Invalid 'to' email address")?);
    }
    for recipient in &args.cc {
        builder = builder.cc(recipient.parse().context("Invalid 'cc' email address")?);
    }
    for recipient in &args.bcc {
        builder = builder.bcc(recipient.parse().context("Invalid 'bcc' email address")?);
    }

    builder = builder.subject(&args.subject);

    let body_text = read_content(&args.body).context(t!("fail_read_text"))?;
    let body_html = args
        .body_html
        .as_ref()
        .map(|s| read_content(s))
        .transpose()
        .context(t!("fail_read_html"))?;

    let multipart = build_multipart(body_text, body_html, &args.attachment)?;

    Ok(builder.multipart(multipart)?)
}

/// Reads content from a string, interpreting a leading '@' as a file path.
fn read_content(content_or_path: &str) -> Result<String> {
    if let Some(path) = content_or_path.strip_prefix('@') {
        fs::read_to_string(path).with_context(|| t!("fail_read_content", path = path))
    } else {
        Ok(content_or_path.to_string())
    }
}

/// Builds the multipart body, handling text, HTML, and attachments.
fn build_multipart(
    text: String,
    html: Option<String>,
    attachments: &[PathBuf],
) -> Result<MultiPart> {
    let multipart = if let Some(html_content) = html {
        MultiPart::alternative()
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_PLAIN)
                    .body(text),
            )
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_HTML)
                    .body(html_content),
            )
    } else {
        MultiPart::alternative().singlepart(
            SinglePart::builder()
                .header(ContentType::TEXT_PLAIN)
                .body(text),
        )
    };

    let mut root = MultiPart::mixed().multipart(multipart);

    for path in attachments {
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("attachment")
            .to_string();
        let content = fs::read(path)
            .with_context(|| t!("fail_read_attachment", path = path.to_string_lossy()))?;
        let content_type = mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string();

        let attachment = lettre::message::Attachment::new(filename)
            .body(content, ContentType::parse(&content_type)?);

        root = root.singlepart(attachment);
    }

    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_content_from_string() {
        assert_eq!(read_content("Hello World").unwrap(), "Hello World");
    }

    #[test]
    fn test_read_content_from_file() {
        // Create a dummy test file
        fs::create_dir_all("tests").unwrap();
        fs::write("tests/test_file.txt", "This is a test file.").unwrap();
        let result = read_content("@tests/test_file.txt");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().trim(), "This is a test file.");
        fs::remove_file("tests/test_file.txt").unwrap();
    }

    #[test]
    fn test_read_content_from_nonexistent_file() {
        let result = read_content("@nonexistent.txt");
        assert!(result.is_err());
    }
}
