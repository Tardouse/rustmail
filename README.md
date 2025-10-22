# RustMail: A Simple & Powerful CLI Mail Sender

RustMail is a lightweight, versatile, and standalone command-line utility for sending emails via SMTP. It's designed for easy integration into shell scripts, Python scripts, or any environment where you need to send email notifications without relying on system mailers like `sendmail`.

## Features

- **Standalone:** No dependencies on local mail daemons. Works out-of-the-box.
- **Flexible SMTP:** Supports both STARTTLS (port 587) and SMTPS (implicit TLS on port 465).
- **Rich Content:** Send emails with attachments, HTML body, CC, and BCC recipients.
- **Versatile Configuration:** Configure via command-line arguments, environment variables, or a central YAML config file.
- **Internationalization (i18n):** UI messages are available in English and Chinese, automatically selected based on your system's locale.

## Installation
Downloads from Release.

Or

Ensure you have Rust and Cargo installed. You can then build and install RustMail with a single command:

```bash
cargo install --path .
```

This will compile the binary and place it in your Cargo bin path (e.g., `~/.cargo/bin`), making it available system-wide.

## Configuration

For convenience, you can create a configuration file to store your default settings. RustMail looks for a file at `$XDG_CONFIG_HOME/rustmail/mail.yaml`. On Linux and macOS, this is typically `~/.config/rustmail/mail.yaml`.

Create the directory and the file:

```bash
mkdir -p ~/.config/rustmail
touch ~/.config/rustmail/mail.yaml
```

Here is an example `mail.yaml` file. You can specify any or all of these settings.

```yaml
# Your SMTP server details
smtp_server: "smtp.example.com"
smtp_port: 587
smtp_username: "user@example.com"
smtp_password: "your_secret_password" # Use an app-specific password if possible

# Default sender and recipients
from_name: "My Awesome Script"
to:
  - "default-recipient@example.com"
  - "another-recipient@example.com"
cc:
  - "manager@example.com"
```

**Priority Order:** Command-line arguments > Environment variables > Config file.

## Usage

You can see all available options by running `rustmail send --help`.

### Example 1: From a Shell Script

This script runs a backup command and sends a notification email with the log file attached upon completion.

```bash
#!/bin/bash

LOG_FILE="/tmp/backup_$(date +%F).log"
RECIPIENT="admin@example.com"

# Run the backup command and save its output
echo "Starting backup..." > "$LOG_FILE"
tar -czf /var/backups/home.tar.gz /home/user &>> "$LOG_FILE"
BACKUP_STATUS=$?
echo "Backup finished." >> "$LOG_FILE"

# Prepare email content
if [ $BACKUP_STATUS -eq 0 ]; then
  SUBJECT="✅ Backup Successful"
  BODY="The backup completed successfully. See attached log for details."
else
  SUBJECT="❌ Backup FAILED"
  BODY="The backup process failed. Please check the attached log."
fi

# Send the email notification with the log file as an attachment
# Assumes SMTP credentials are in the config file or env vars
rustmail send \
  --to "$RECIPIENT" \
  --subject "$SUBJECT" \
  --body "$BODY" \
  --attachment "$LOG_FILE"

# Clean up the log file
rm "$LOG_FILE"
```

### Example 2: From a Python Script

This Python script demonstrates how to call `rustmail` to send a report after some data processing.

```python
import subprocess
import sys

def run_data_processing():
    """
    A placeholder function for your data processing task.
    Returns a tuple: (success_boolean, report_content_string).
    """
    print("Processing data...")
    # Simulate a task
    try:
        # Your real logic here
        report = "Data processing completed.\nProcessed 1000 records.\nNo errors found."
        return True, report
    except Exception as e:
        report = f"An error occurred during data processing:\n{e}"
        return False, report

def send_notification(success, report_content):
    """
    Calls the rustmail CLI to send a notification email.
    """
    subject = "✅ Data Processing Report" if success else "❌ Data Processing FAILED"
    
    # rustmail will use credentials from its config file or environment variables
    command = [
        "rustmail", "send",
        "--to", "team@example.com",
        "--subject", subject,
        "--body", report_content,
    ]
    
    try:
        print("Sending notification email...")
        # Using text=True and capture_output=True for better error handling
        result = subprocess.run(
            command, 
            check=True, 
            capture_output=True, 
            text=True,
            encoding='utf-8'
        )
        print("Email sent successfully!")
        print(result.stdout)
    except FileNotFoundError:
        print("Error: 'rustmail' command not found.", file=sys.stderr)
        print("Please ensure it is installed and in your system's PATH.", file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print("Error sending email:", file=sys.stderr)
        print(f"Return Code: {e.returncode}", file=sys.stderr)
        print(f"Stdout: {e.stdout}", file=sys.stderr)
        print(f"Stderr: {e.stderr}", file=sys.stderr)

if __name__ == "__main__":
    success, report = run_data_processing()
    send_notification(success, report)

```
