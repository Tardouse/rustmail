#[macro_use]
extern crate rust_i18n;

use anyhow::{Context, Result};
use clap::{Arg, ArgAction, Command};
use lettre::{
    message::{header::ContentType, Mailbox, Message, MultiPart, SinglePart},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
    SmtpTransport, Transport,
};
use native_tls::TlsConnector;
use serde::Deserialize;
use std::{fs, path::PathBuf};

i18n!("locales", fallback = "en");

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
    insecure: bool,
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

fn main() -> Result<()> {
    let args = parse_and_merge_args()?;

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

    let content = fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file at {:?}", config_path))?;

    let config: ConfigFile = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse config file at {:?}", config_path))?;

    Ok(config)
}

/// Parses CLI arguments, loads config file, and merges them.
fn parse_and_merge_args() -> Result<Args> {
    let cli_matches = build_cli().get_matches();
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
        .map(|vals| vals.map(String::from).collect())
        .or(config.to)
        .unwrap_or_default();

    let cc = cli_matches
        .get_many::<String>("cc")
        .map(|vals| vals.map(String::from).collect())
        .or(config.cc)
        .unwrap_or_default();

    let bcc = cli_matches
        .get_many::<String>("bcc")
        .map(|vals| vals.map(String::from).collect())
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
        subject: cli_matches
            .get_one::<String>("subject")
            .cloned()
            .context("Subject is required")?,
        body: cli_matches
            .get_one::<String>("body")
            .cloned()
            .context("Body is required")?,
        body_html: cli_matches.get_one::<String>("body_html").cloned(),
        attachment: cli_matches
            .get_many::<PathBuf>("attachment")
            .unwrap_or_default()
            .cloned()
            .collect(),
        smtps: cli_matches.get_flag("smtps"),
        insecure: cli_matches.get_flag("insecure"),
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
        )
        .arg(
            Arg::new("insecure")
                .long("insecure")
                .action(ArgAction::SetTrue)
                .help(t!("insecure_help")),
        )
}

/// Configures and builds the SMTP transport (mailer).
fn build_mailer(args: &Args) -> Result<SmtpTransport> {
    let creds = Credentials::new(args.smtp_username.clone(), args.smtp_password.clone());

    let mut relay_builder = if args.smtps {
        SmtpTransport::relay(&args.smtp_server)?
    } else {
        SmtpTransport::starttls_relay(&args.smtp_server)?
    };

    relay_builder = relay_builder.port(args.smtp_port).credentials(creds);

    if args.insecure {
        let tls_connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        let tls_parameters = TlsParameters::builder(args.smtp_server.clone())
            .connector(tls_connector)
            .build()?;

        relay_builder = relay_builder.tls(Tls::Required(tls_parameters));
    }

    Ok(relay_builder.build())
}

/// Constructs the email message from arguments.
fn build_message(args: &Args) -> Result<Message> {
    // --- From ---
    let from_mailbox: Mailbox = if let Some(name) = &args.from_name {
        format!("{name} <{}>", args.smtp_username).parse()?
    } else {
        args.smtp_username.parse()?
    };

    let mut builder = Message::builder().from(from_mailbox);

    // --- To, CC, BCC ---
    for recipient in &args.to {
        builder = builder.to(recipient.parse()?);
    }
    for recipient in &args.cc {
        builder = builder.cc(recipient.parse()?);
    }
    for recipient in &args.bcc {
        builder = builder.bcc(recipient.parse()?);
    }

    // --- Subject ---
    builder = builder.subject(&args.subject);

    // --- Body and Attachments ---
    let body_text = read_content(&args.body).context(t!("fail_read_text"))?;
    let body_html = args
        .body_html
        .as_ref()
        .map(|s| read_content(s)) // Use closure here
        .transpose()
        .context(t!("fail_read_html"))?;

    let multipart = build_multipart(body_text, body_html, &args.attachment)?;

    Ok(builder.multipart(multipart)?)
}

/// Reads content from a string, interpreting a leading '@' as a file path.
fn read_content(content_or_path: &str) -> Result<String> {
    if let Some(path) = content_or_path.strip_prefix('@') {
        fs::read_to_string(path)
            .with_context(|| t!("fail_read_content", path = path))
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
    // Start with the body, creating the initial MultiPart object
    let mut multipart = match html {
        Some(html_content) => {
            let body = MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(text),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html_content),
                );
            // The builder is consumed and returns a MultiPart
            MultiPart::mixed().multipart(body)
        }
        None => {
            let body = SinglePart::builder()
                .header(ContentType::TEXT_PLAIN)
                .body(text);
            // The builder is consumed and returns a MultiPart
            MultiPart::mixed().singlepart(body)
        }
    };

    // Now, iterate through attachments and add them to the MultiPart
    for path in attachments {
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("attachment")
            .to_string();
        let content =
            fs::read(path).with_context(|| t!("fail_read_attachment", path = path.to_string_lossy()))?;
        let content_type = mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string();

        let attachment = lettre::message::Attachment::new(filename)
            .body(content, ContentType::parse(&content_type)?);
        
        // The multipart object is consumed and replaced by a new one with the attachment
        multipart = multipart.singlepart(attachment);
    }

    Ok(multipart)
}