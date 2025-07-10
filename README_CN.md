# RustMail: 一个简单强大的命令行邮件发送器

RustMail 是一个轻量、多功能且独立的命令行工具，用于通过 SMTP 发送邮件。它被设计用于轻松集成到 Shell 脚本、Python 脚本或任何需要发送邮件通知的环境中，而无需依赖像 `sendmail` 这样的系统邮件服务。

## 功能特性

- **独立运行:** 不依赖本地的邮件守护进程，完全开箱即用。
- **灵活的 SMTP:** 同时支持 STARTTLS (端口 587) 和 SMTPS (隐式 TLS，端口 465)。
- **丰富的内容:** 支持发送带附件、HTML 正文、抄送 (CC) 和密送 (BCC) 的邮件。
- **多样的配置方式:** 支持通过命令行参数、环境变量或一个中央 YAML 配置文件进行配置。
- **国际化 (i18n):** UI 消息提供英文和中文两种版本，并会根据您的系统语言环境自动选择。

## 安装

请确保您已安装 Rust 和 Cargo。然后，您可以通过一个命令来构建和安装 RustMail：

```bash
cargo install --path .
```

这个命令会编译程序，并将其二进制文件放置到 Cargo 的 bin 目录中 (例如 `~/.cargo/bin`)，从而使其在您的系统中全局可用。

## 配置

为了方便日常使用，您可以创建一个配置文件来保存您的默认设置。RustMail 会在 `$XDG_CONFIG_HOME/rustmail/mail.yaml` 路径下寻找配置文件。在 Linux 和 macOS 上，这个路径通常是 `~/.config/rustmail/mail.yaml`。

首先创建目录和文件：

```bash
mkdir -p ~/.config/rustmail
touch ~/.config/rustmail/mail.yaml
```

这是一个 `mail.yaml` 配置文件的示例。您可以指定其中的部分或全部设置。

```yaml
# 您的 SMTP 服务器信息
smtp_server: "smtp.example.com"
smtp_port: 587
smtp_username: "user@example.com"
smtp_password: "your_secret_password" # 推荐使用应用专用密码

# 默认的发件人和收件人
from_name: "我的神奇脚本"
to:
  - "default-recipient@example.com"
  - "another-recipient@example.com"
cc:
  - "manager@example.com"
```

**配置优先级顺序:** 命令行参数 > 环境变量 > 配置文件。

## 使用方法

您可以运行 `rustmail --help` 来查看所有可用的选项。

### 示例 1: 在 Shell 脚本中使用

这个脚本会运行一个备份命令，并在任务完成后，将日志文件作为附件发送一封通知邮件。

```bash
#!/bin/bash

LOG_FILE="/tmp/backup_$(date +%F).log"
RECIPIENT="admin@example.com"

# 运行备份命令并保存其输出
echo "开始备份..." > "$LOG_FILE"
tar -czf /var/backups/home.tar.gz /home/user &>> "$LOG_FILE"
BACKUP_STATUS=$?
echo "备份结束。" >> "$LOG_FILE"

# 准备邮件内容
if [ $BACKUP_STATUS -eq 0 ]; then
  SUBJECT="✅ 备份成功"
  BODY="备份任务已成功完成。详情请见附件中的日志。"
else
  SUBJECT="❌ 备份失败"
  BODY="备份过程出现错误。请检查附件中的日志。"
fi

# 发送带日志附件的邮件通知
# 此处假设 SMTP 凭据已在配置文件或环境变量中设置
rustmail \
  --to "$RECIPIENT" \
  --subject "$SUBJECT" \
  --body "$BODY" \
  --attachment "$LOG_FILE"

# 清理日志文件
rm "$LOG_FILE"
```

### 示例 2: 在 Python 脚本中使用

这个 Python 脚本演示了如何在完成一些数据处理后，调用 `rustmail` 来发送一份报告。

```python
import subprocess
import sys

def run_data_processing():
    """
    一个模拟数据处理任务的占位函数。
    返回一个元组: (是否成功, 报告内容的字符串)。
    """
    print("正在处理数据...")
    # 模拟一个任务
    try:
        # 在这里放置您的真实逻辑
        report = "数据处理完成。\n共处理 1000 条记录。\n未发现错误。"
        return True, report
    except Exception as e:
        report = f"数据处理过程中发���错误:\n{e}"
        return False, report

def send_notification(success, report_content):
    """
    调用 rustmail 命令行工具来发送通知邮件。
    """
    subject = "✅ 数据处理报告" if success else "❌ 数据处理失败"
    
    # rustmail 会自动使用其配置文件或环境变量中的凭据
    command = [
        "rustmail",
        "--to", "team@example.com",
        "--subject", subject,
        "--body", report_content,
    ]
    
    try:
        print("正在发送通知邮件...")
        # 使用 text=True 和 capture_output=True 以便更好地处理错误
        result = subprocess.run(
            command, 
            check=True, 
            capture_output=True, 
            text=True,
            encoding='utf-8'
        )
        print("邮件发送成功!")
        print(result.stdout)
    except FileNotFoundError:
        print("错误: 未找到 'rustmail' 命令。", file=sys.stderr)
        print("请确保该程序已安装并在系统的 PATH 路径中。", file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print("发送邮件时出错:", file=sys.stderr)
        print(f"返回码: {e.returncode}", file=sys.stderr)
        print(f"标准输出: {e.stdout}", file=sys.stderr)
        print(f"标准错误: {e.stderr}", file=sys.stderr)

if __name__ == "__main__":
    success, report = run_data_processing()
    send_notification(success, report)

```