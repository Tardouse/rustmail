#[macro_use]
extern crate rust_i18n;

use anyhow::{Context, Result};
use clap::{Arg, ArgAction, Command, Subcommand};
use lettre::{
    message::{header::ContentType, Mailbox, Message, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    transport::smtp::client::{Tls, TlsParameters},
    SmtpTransport, Transport,
};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use serde::Deserialize;
use std::{fs, path::PathBuf};

i18n!("locales", fallback = "en");

const ENCRYPTION_HEADER: &str = "RUSTMAIL_ENCRYPTED_V1\n";

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
    smtps: Option<bool>,
}

#[derive(Subcommand, Debug)]
enum CliSubCommand {
    Encrypt { #[arg(value_name = "FILE")] file: PathBuf },
    Decrypt { #[arg(value_name = "FILE")] file: PathBuf },
    Send {
        #[arg(long, env = "SMTP_SERVER")] smtp_server: Option<String>,
        #[arg(long, env = "SMTP_PORT")] smtp_port: Option<u16>,
        #[arg(long, env = "SMTP_USERNAME")] smtp_username: Option<String>,
        #[arg(long, env = "SMTP_PASSWORD")] smtp_password: Option<String>,
        #[arg(long)] from_name: Option<String>,
        #[arg(long, action = ArgAction::Append, value_delimiter = ',')] to: Vec<String>,
        #[arg(long, action = ArgAction::Append, value_delimiter = ',')] cc: Vec<String>,
        #[arg(long, action = ArgAction::Append, value_delimiter = ',')] bcc: Vec<String>,
        #[arg(long, required = true)] subject: String,
        #[arg(long, required = true)] body: String,
        #[arg(long)] body_html: Option<String>,
        #[arg(long, action = ArgAction::Append, value_parser = clap::value_parser!(PathBuf))]
        attachment: Vec<PathBuf>,
        #[arg(long, action = ArgAction::SetTrue)] smtps: bool,
        #[arg(long)] key: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = build_cli().get_matches();

    match cli.subcommand() {
        Some(("encrypt", sub)) => handle_encrypt(sub.get_one::<PathBuf>("file").unwrap()),
        Some(("decrypt", sub)) => handle_decrypt(sub.get_one::<PathBuf>("file").unwrap()),
        Some(("send", sub)) => handle_send(sub),
        _ => {
            build_cli().print_help()?;
            Ok(())
        }
    }
}

fn handle_encrypt(file: &PathBuf) -> Result<()> {
    let content = fs::read_to_string(file)?;
    if content.starts_with(ENCRYPTION_HEADER) {
        println!("{}", t!("already_encrypted"));
        return Ok(());
    }

    println!("{}", t!("enter_password_encrypt"));
    let password = rpassword::prompt_password("Password: ")?;
    let confirm = rpassword::prompt_password("Confirm Password: ")?;
    if password != confirm {
        return Err(anyhow::anyhow!(t!("password_mismatch")));
    }

    let crypter = new_magic_crypt!(&password, 256);
    let encrypted = crypter.encrypt_str_to_base64(content);
    fs::write(file, format!("{}{}", ENCRYPTION_HEADER, encrypted))?;

    println!("{}", t!("encrypt_success", file = file.to_string_lossy()));
    Ok(())
}

fn handle_decrypt(file: &PathBuf) -> Result<()> {
    let content = fs::read_to_string(file)?;
    if !content.starts_with(ENCRYPTION_HEADER) {
        println!("{}", t!("not_encrypted"));
        return Ok(());
    }

    let encrypted_b64 = content.strip_prefix(ENCRYPTION_HEADER).unwrap();
    println!("{}", t!("enter_password_decrypt"));
    let password = rpassword::prompt_password("Password: ")?;

    let crypter = new_magic_crypt!(&password, 256);
    let decrypted = crypter
        .decrypt_base64_to_string(encrypted_b64)
        .context("Decryption failed")?;

    fs::write(file, decrypted)?;
    println!("{}", t!("decrypt_success", file = file.to_string_lossy()));
    Ok(())
}

fn handle_send(matches: &clap::ArgMatches) -> Result<()> {
    let args = parse_and_merge_args(matches)?;
    let mailer = build_mailer(&args)?;
    let email = build_message(&args)?;

    mailer.send(&email).context("Failed to send email")?;
    println!("{}", t!("success_sent"));
    Ok(())
}

fn load_config(key: Option<String>) -> Result<ConfigFile> {
    let config_path = dirs::config_dir()
        .context("Cannot find config dir")?
        .join("rustmail/mail.yaml");

    if !config_path.exists() {
        return Ok(ConfigFile::default());
    }

    let mut content = fs::read_to_string(&config_path)?;
    if content.starts_with(ENCRYPTION_HEADER) {
        let password = key.unwrap_or_else(|| {
            println!("{}", t!("config_encrypted_prompt"));
            rpassword::prompt_password("Password: ").unwrap()
        });
        let crypter = new_magic_crypt!(&password, 256);
        let encrypted_b64 = content.strip_prefix(ENCRYPTION_HEADER).unwrap();
        content = crypter
            .decrypt_base64_to_string(encrypted_b64)
            .context("Decryption failed")?;
    }

    Ok(serde_yaml::from_str(&content)?)
}

fn parse_and_merge_args(matches: &clap::ArgMatches) -> Result<Args> {
    let key = matches.get_one::<String>("key").cloned();
    let config = load_config(key)?;

    let smtp_server = matches
        .get_one::<String>("smtp_server")
        .cloned()
        .or(config.smtp_server)
        .context("Missing smtp_server")?;

    let smtp_username = matches
        .get_one::<String>("smtp_username")
        .cloned()
        .or(config.smtp_username)
        .context("Missing smtp_username")?;

    let smtp_password = matches
        .get_one::<String>("smtp_password")
        .cloned()
        .or(config.smtp_password)
        .context("Missing smtp_password")?;

    let smtp_port = matches
        .get_one::<u16>("smtp_port")
        .copied()
        .or(config.smtp_port)
        .unwrap_or(587);

    Ok(Args {
        smtp_server,
        smtp_port,
        smtp_username,
        smtp_password,
        from_name: matches.get_one::<String>("from_name").cloned().or(config.from_name),
        to: collect_vec(matches, "to").or(config.to).unwrap_or_default(),
        cc: collect_vec(matches, "cc").or(config.cc).unwrap_or_default(),
        bcc: collect_vec(matches, "bcc").or(config.bcc).unwrap_or_default(),
        subject: matches
            .get_one::<String>("subject")
            .cloned()
            .context("Missing subject")?,
        body: matches
            .get_one::<String>("body")
            .cloned()
            .context("Missing body")?,
        body_html: matches.get_one::<String>("body_html").cloned(),
        attachment: matches
            .get_many::<PathBuf>("attachment")
            .unwrap_or_default()
            .cloned()
            .collect(),
        smtps: matches.get_flag("smtps") || config.smtps.unwrap_or(false),
    })
}

fn collect_vec(matches: &clap::ArgMatches, name: &str) -> Option<Vec<String>> {
    matches
        .get_many::<String>(name)
        .map(|vals| vals.cloned().collect::<Vec<_>>())
        .filter(|v| !v.is_empty())
}

fn build_mailer(args: &Args) -> Result<SmtpTransport> {
    let creds = Credentials::new(args.smtp_username.clone(), args.smtp_password.clone());

    if args.smtps || args.smtp_port == 465 {
        // SMTPS 模式（465）
        let tls_params = TlsParameters::new(args.smtp_server.clone())
            .context("Failed to build TLS parameters for SMTPS")?;
        let mailer = SmtpTransport::relay(&args.smtp_server)
            .context("Failed to create relay for SMTPS")?
            .port(args.smtp_port)
            .credentials(creds)
            .tls(Tls::Wrapper(tls_params))
            .build();
        Ok(mailer)
    } else {
        // STARTTLS 模式（587）
        let mailer = SmtpTransport::starttls_relay(&args.smtp_server)
            .context("Failed to create starttls relay")?
            .port(args.smtp_port)
            .credentials(creds)
            .build();
        Ok(mailer)
    }
}

fn build_message(args: &Args) -> Result<Message> {
    let from = if let Some(name) = &args.from_name {
        Mailbox::new(Some(name.clone()), args.smtp_username.parse()?)
    } else {
        args.smtp_username.parse()?
    };

    let mut builder = Message::builder().from(from);
    for to in &args.to {
        builder = builder.to(to.parse()?);
    }
    for cc in &args.cc {
        builder = builder.cc(cc.parse()?);
    }
    for bcc in &args.bcc {
        builder = builder.bcc(bcc.parse()?);
    }

    builder = builder.subject(&args.subject);
    let text = read_content(&args.body)?;
    let html = args
        .body_html
        .as_ref()
        .map(|s| read_content(s))
        .transpose()?;

    let multipart = build_multipart(text, html, &args.attachment)?;
    Ok(builder.multipart(multipart)?)
}

fn read_content(input: &str) -> Result<String> {
    if let Some(path) = input.strip_prefix('@') {
        Ok(fs::read_to_string(path)?)
    } else {
        Ok(input.to_string())
    }
}

fn build_multipart(
    text: String,
    html: Option<String>,
    attachments: &[PathBuf],
) -> Result<MultiPart> {
    let mut multipart = if let Some(html_body) = html {
        MultiPart::alternative()
            .singlepart(SinglePart::builder().header(ContentType::TEXT_PLAIN).body(text))
            .singlepart(SinglePart::builder().header(ContentType::TEXT_HTML).body(html_body))
    } else {
        MultiPart::alternative()
            .singlepart(SinglePart::builder().header(ContentType::TEXT_PLAIN).body(text))
    };

    for path in attachments {
        let filename = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let content = fs::read(path)?;
        let content_type = mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string();
        let attachment =
            lettre::message::Attachment::new(filename).body(content, ContentType::parse(&content_type)?);
        multipart = multipart.singlepart(attachment);
    }

    Ok(MultiPart::mixed().multipart(multipart))
}

fn build_cli() -> Command {
    Command::new("rustmail")
        .version(env!("CARGO_PKG_VERSION"))
        .about(t!("app_about"))
        .subcommand_required(true)
        .subcommand(
            Command::new("send")
                .about("Send email")
                .arg(Arg::new("smtp_server").long("smtp-server"))
                .arg(Arg::new("smtp_port").long("smtp-port"))
                .arg(Arg::new("smtp_username").long("smtp-username"))
                .arg(Arg::new("smtp_password").long("smtp-password"))
                .arg(Arg::new("from_name").long("from-name"))
                .arg(Arg::new("to").long("to").action(ArgAction::Append))
                .arg(Arg::new("cc").long("cc").action(ArgAction::Append))
                .arg(Arg::new("bcc").long("bcc").action(ArgAction::Append))
                .arg(Arg::new("subject").long("subject").required(true))
                .arg(Arg::new("body").long("body").required(true))
                .arg(Arg::new("body_html").long("body-html"))
                .arg(Arg::new("attachment").long("attachment").action(ArgAction::Append))
                .arg(Arg::new("smtps").long("smtps").action(ArgAction::SetTrue))
                .arg(Arg::new("key").long("key")),
        )
        .subcommand(
            Command::new("encrypt")
                .about("Encrypt config")
                .arg(Arg::new("file").required(true)),
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt config")
                .arg(Arg::new("file").required(true)),
        )
}

