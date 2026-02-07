# 📧 myl

myl is a dead simple IMAP CLI client hosted on GitHub at
https://github.com/pschmitt/myl

## 📝 Description

myl is a command-line interface client for IMAP, designed to provide a
straightforward way to interact with IMAP servers.

## ⭐ Features

- Simple command-line interface
- Support for various IMAP operations
- Autodiscovery of the required server and port
- Support for Google IMAP settings
- Fetch a specific number of messages
- Mark messages as seen
- Fetch messages from a specific folder
- Search for specific strings in messages
- Output HTML email
- Output raw email
- Fetch a specific mail by ID
- Fetch a specific attachment

## 🚀 Installation

To install myl, follow these steps:

```shell
pipx install myl
# or:
pip install --user myl
```

on nix you can do this:

```shell
nix run github:pschmitt/myl -- --help
```

## 🛠️ Usage

Here's how you can use myl:

```shell
myl --help
```

This command will display the help information for the `myl` command.

### Configuration File

To avoid repeatedly passing connection arguments, you can create a configuration 
file at `~/.config/myl/config` (or `~/.config/myl.conf`). The configuration file 
uses INI format with a `[myl]` section:

```ini
[myl]
server = imap.example.com
port = 993
username = your.email@example.com
password = your_password
ssl = true
folder = INBOX
count = 20
```

Supported configuration options:
- `server`: IMAP server address
- `port`: IMAP server port (default: 993)
- `username`: IMAP username
- `password`: IMAP password
- `password_file`: Path to a file containing the password
- `ssl`: Use SSL/TLS connection (true/false, default: true)
- `starttls`: Use STARTTLS (true/false, default: false)
- `insecure`: Disable certificate validation (true/false, default: false)
- `google`: Use Google IMAP settings (true/false, default: false)
- `auto`: Enable autodiscovery (true/false, default: false)
- `folder`: Default IMAP folder (default: INBOX)
- `count`: Number of messages to fetch (default: 10)
- `mark_seen`: Mark messages as seen (true/false, default: false)
- `search`: Default search string (default: ALL)
- `unread`: Limit to unread emails (true/false, default: false)
- `date_format`: Date format string (default: %H:%M %d/%m/%Y)

**Note:** Command-line arguments always override configuration file values.

Here are some examples of using flags with the `myl` command:

```shell
# Connect to an IMAP server
myl --server imap.example.com --port 143 --starttls --username "$username" --password "$password"

# Use Google IMAP settings
myl --google --username "$username" --password "$password"

# Autodiscovery of the required server and port
myl --auto --username "$username" --password "$password"

# With a config file, you can simply run:
myl

# Fetch a specific number of messages
myl --count 5

# Mark messages as seen
myl --mark-seen

# Fetch messages from a specific folder
myl --folder "INBOX"

# Search for specific strings in messages
myl --search "important"

# Fetch a specific mail ID
myl "$MAILID"

# Show HTML
myl --html "$MAILID"

# raw email
myl --raw "$MAILID" > email.eml

# Fetch a specific attachment (outputs to stdout)
myl "$MAILID" "$ATT" > att.txt
```

Please replace `imap.example.com`, `$username`, `$password`, `$MAILID`,
and `$ATT` with your actual IMAP server details, username, password,
mail ID, and attachment name.

## 📜 License

This project is licensed under the GPL-3.0 license.
