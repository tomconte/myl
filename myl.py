#!/usr/bin/env python3
# coding: utf-8

from importlib.metadata import version, PackageNotFoundError
import argparse
import base64
import configparser
import logging
import os
from pathlib import Path
import ssl
import sys
from json import dumps as json_dumps

import html2text
from imap_tools import (
    BaseMailBox,
    MailBox,
    MailBoxStartTls,
    MailBoxUnencrypted,
    MailMessageFlags,
)
from imap_tools.query import AND
from myldiscovery import autodiscover
from rich import print, print_json
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

try:
    __version__ = version("myl")
except PackageNotFoundError:
    pass

LOGGER = logging.getLogger(__name__)
IMAP_PORT = 993
GMAIL_IMAP_SERVER = "imap.gmail.com"
GMAIL_IMAP_PORT = IMAP_PORT
GMAIL_SENT_FOLDER = "[Gmail]/Sent Mail"
# GMAIL_ALL_FOLDER = "[Gmail]/All Mail"


class MissingServerException(Exception):
    pass


def get_config_path():
    """Get the path to the configuration file."""
    config_home = os.environ.get("XDG_CONFIG_HOME")
    if not config_home:
        config_home = Path.home() / ".config"
    else:
        config_home = Path(config_home)

    # Try both myl.conf and myl/config
    config_file = config_home / "myl.conf"
    if not config_file.exists():
        config_file = config_home / "myl" / "config"

    return config_file


def load_config():
    """Load configuration from file if it exists."""
    config_file = get_config_path()
    config = configparser.ConfigParser()

    if config_file.exists():
        LOGGER.debug(f"Loading config from {config_file}")
        config.read(config_file)
    else:
        LOGGER.debug(f"No config file found at {config_file}")

    return config


def error_msg(msg):
    print(f"[red]{msg}[/red]", file=sys.stderr)


def mail_to_dict(msg, date_format="%Y-%m-%d %H:%M:%S", include_content=True):
    result = {
        "uid": msg.uid,
        "subject": msg.subject,
        "from": msg.from_,
        "to": msg.to,
        "date": msg.date.strftime(date_format) if msg.date else None,
        "timestamp": str(int(msg.date.timestamp())) if msg.date else None,
        "unread": mail_is_unread(msg),
        "flags": msg.flags,
    }

    if include_content:
        result["content"] = {
            "html": msg.html,
            "text": msg.text,
        }
        result["attachments"] = [
            {
                "filename": x.filename,
                "content_id": x.content_id,
                "content_type": x.content_type,
                "content_disposition": x.content_disposition,
                "payload": base64.b64encode(x.payload).decode("utf-8"),
                "size": x.size,
            }
            for x in msg.attachments
        ]
    else:
        result["has_attachments"] = len(msg.attachments) > 0
        result["attachment_count"] = len(msg.attachments)

    return result


def mail_to_json(msg, date_format="%Y-%m-%d %H:%M:%S"):
    return json_dumps(mail_to_dict(msg, date_format))


def mail_is_unread(msg):
    return MailMessageFlags.SEEN not in msg.flags


def parse_args():
    # Load config file first
    config = load_config()
    config_defaults = {}

    # Extract defaults from [myl] section if it exists
    if config.has_section("myl"):
        for key, value in config.items("myl"):
            # Convert config keys to argument names
            config_defaults[key] = value

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(
        dest="command", help="Available commands"
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    # Support for `myl <MAILID>` syntax (when no subcommand is provided)
    parser.add_argument(
        "MAILID",
        help="Mail ID to fetch (optional, used when no subcommand is specified)",
        type=int,
        nargs="?",
        default=None,
    )

    # Default command: list all emails
    subparsers.add_parser("list", help="List all emails")

    # Get/show email command
    get_parser = subparsers.add_parser(
        "get", help="Retrieve a specific email or attachment"
    )
    get_parser.add_argument("MAILID", help="Mail ID to fetch", type=int)
    get_parser.add_argument(
        "ATTACHMENT",
        help="Name of the attachment to fetch",
        nargs="?",
        default=None,
    )

    # get most recent email
    last_parser = subparsers.add_parser(
        "last", aliases=["-1"], help="Retrieve the most recent email"
    )
    last_parser.add_argument(
        "ATTACHMENT",
        help="Name of the attachment to fetch",
        nargs="?",
        default=None,
    )

    # Delete email command
    delete_parser = subparsers.add_parser("delete", help="Delete an email")
    delete_parser.add_argument(
        "MAILIDS", help="Mail ID(s) to delete", type=int, nargs="+"
    )

    # Mark email as read/unread
    mark_read_parser = subparsers.add_parser(
        "read", help="mark an email as read"
    )
    mark_read_parser.add_argument(
        "MAILIDS", help="Mail ID(s) to mark as read", type=int, nargs="+"
    )
    mark_unread_parser = subparsers.add_parser(
        "unread", help="mark an email as unread"
    )
    mark_unread_parser.add_argument(
        "MAILIDS", help="Mail ID(s) to mark as unread", type=int, nargs="+"
    )

    # Optional arguments
    parser.add_argument(
        "-d", "--debug", help="Enable debug mode", action="store_true"
    )

    # IMAP connection settings
    parser.add_argument(
        "-s",
        "--server",
        help="IMAP server address",
        required=False,
        default=config_defaults.get("server"),
    )
    parser.add_argument(
        "--google",
        "--gmail",
        help="Use Google IMAP settings (overrides --port, --server etc.)",
        action="store_true",
        default=config_defaults.get("google", "").lower()
        in ("true", "yes", "1"),
    )
    parser.add_argument(
        "-a",
        "--auto",
        help="Autodiscovery of the required server and port",
        action="store_true",
        default=config_defaults.get("auto", "").lower()
        in ("true", "yes", "1"),
    )

    # Safely parse port with error handling
    port_str = config_defaults.get("port") or IMAP_PORT
    try:
        port_default = int(port_str)
    except (ValueError, TypeError):
        LOGGER.warning(
            f"Invalid port value in config: {port_str}, using default: {IMAP_PORT}"
        )
        port_default = IMAP_PORT

    parser.add_argument(
        "-P",
        "--port",
        help="IMAP server port",
        default=port_default,
        type=int,
    )

    # SSL/TLS options - mutually exclusive
    ssl_group = parser.add_mutually_exclusive_group()
    ssl_group.add_argument(
        "--ssl",
        help="Use SSL/TLS connection (default)",
        action="store_true",
        dest="ssl",
    )
    ssl_group.add_argument(
        "--no-ssl",
        help="Disable SSL/TLS",
        action="store_false",
        dest="ssl",
    )
    ssl_group.add_argument(
        "--starttls",
        help="Use STARTTLS",
        action="store_true",
    )

    # Set SSL defaults from config
    ssl_default = config_defaults.get("ssl", "true").lower() in (
        "true",
        "yes",
        "1",
    )
    starttls_default = config_defaults.get("starttls", "false").lower() in (
        "true",
        "yes",
        "1",
    )
    parser.set_defaults(ssl=ssl_default, starttls=starttls_default)

    parser.add_argument(
        "--insecure",
        help="Disable cert validation",
        action="store_true",
        default=config_defaults.get("insecure", "").lower()
        in ("true", "yes", "1"),
    )

    # Credentials - make them optional if provided in config
    username_required = "username" not in config_defaults
    password_required = (
        "password" not in config_defaults
        and "password_file" not in config_defaults
    )

    parser.add_argument(
        "-u",
        "--username",
        help="IMAP username",
        required=username_required,
        default=config_defaults.get("username"),
    )
    password_group = parser.add_mutually_exclusive_group(
        required=password_required
    )
    # Handle password_file from config by reading it
    # and treating it as a password value
    password_default = config_defaults.get("password")
    if not password_default and "password_file" in config_defaults:
        try:
            with open(config_defaults["password_file"], "r") as f:
                password_default = f.read().strip()
        except (IOError, OSError) as e:
            LOGGER.warning(f"Could not open password file from config: {e}")

    password_group.add_argument(
        "-p",
        "--password",
        help="IMAP password",
        default=password_default,
    )
    password_group.add_argument(
        "--password-file",
        help="IMAP password (file path)",
        type=argparse.FileType("r"),
    )

    # Display preferences
    # Safely parse count with error handling
    count_str = config_defaults.get("count") or "10"
    try:
        count_default = int(count_str)
    except (ValueError, TypeError):
        LOGGER.warning(
            f"Invalid count value in config: {count_str}, using default: 10"
        )
        count_default = 10

    parser.add_argument(
        "-c",
        "--count",
        help="Number of messages to fetch",
        default=count_default,
        type=int,
    )
    parser.add_argument(
        "-t", "--no-title", help="Do not show title", action="store_true"
    )
    parser.add_argument(
        "--date-format",
        help="Date format",
        default=config_defaults.get("date_format", "%H:%M %d/%m/%Y"),
    )

    # IMAP actions
    parser.add_argument(
        "-m",
        "--mark-seen",
        help="Mark seen",
        action="store_true",
        default=config_defaults.get("mark_seen", "").lower()
        in ("true", "yes", "1"),
    )

    # Email filtering
    parser.add_argument(
        "-f",
        "--folder",
        help="IMAP folder",
        default=config_defaults.get("folder", "INBOX"),
    )
    parser.add_argument(
        "--sent",
        help="Sent email",
        action="store_true",
    )
    parser.add_argument(
        "-S",
        "--search",
        help="Search string",
        default=config_defaults.get("search", "ALL"),
    )
    parser.add_argument(
        "--unread",
        help="Limit to unread emails",
        action="store_true",
        default=config_defaults.get("unread", "").lower()
        in ("true", "yes", "1"),
    )

    # Output preferences
    parser.add_argument(
        "-H",
        "--html",
        help="Show HTML email",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-j",
        "--json",
        help="JSON output",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-r",
        "--raw",
        help="Show the raw email",
        action="store_true",
        default=False,
    )

    return parser.parse_args()


def mb_connect(console, args) -> BaseMailBox:
    imap_password = args.password or (
        args.password_file and args.password_file.read()
    )

    if args.google:
        args.server = GMAIL_IMAP_SERVER
        args.port = GMAIL_IMAP_PORT
        args.starttls = False
        args.ssl = True

        if args.sent or args.folder == "Sent":
            args.folder = GMAIL_SENT_FOLDER
        # elif args.folder == "INBOX":
        #     args.folder = GMAIL_ALL_FOLDER
    else:
        if args.auto:
            try:
                settings = autodiscover(
                    args.username,
                    password=imap_password,
                    insecure=args.insecure,
                ).get("imap", {})
            except Exception as e:
                error_msg("Failed to autodiscover IMAP settings")
                if args.debug:
                    console.print_exception(show_locals=True)
                else:
                    LOGGER.error(str(e))
                    sys.exit(1)

            LOGGER.debug(f"Discovered settings: {settings})")
            args.server = settings.get("server")
            args.port = settings.get("port", IMAP_PORT)
            args.starttls = settings.get("starttls")
            args.ssl = settings.get("ssl")

        if args.sent:
            args.folder = "Sent"

    if not args.server:
        error_msg(
            "No server specified\n"
            "You need to either:\n"
            "- specify a server using --server HOSTNAME\n"
            "- set --google if you are using a Gmail account\n"
            "- use --auto to attempt autodiscovery"
        )
        raise MissingServerException()

    ssl_context = None
    if args.insecure:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    mb_kwargs = {"host": args.server, "port": args.port}

    # Determine which mailbox type to use based on SSL/STARTTLS settings
    if args.starttls:
        mb = MailBoxStartTls
        mb_kwargs["ssl_context"] = ssl_context
    elif args.ssl:
        mb = MailBox
        mb_kwargs["ssl_context"] = ssl_context
    else:
        mb = MailBoxUnencrypted

    mailbox = mb(**mb_kwargs)
    mailbox.login(args.username, imap_password, args.folder)
    return mailbox


def display_single_mail(
    mailbox: BaseMailBox,
    mail_id: int | None = None,
    attachment: str | None = None,
    mark_seen: bool = False,
    raw: bool = False,
    html: bool = False,
    json: bool = False,
):
    if mail_id is None:
        LOGGER.debug("No mail_id provided, fetching the most recent mail")
        msg = next(
            mailbox.fetch(
                "ALL", reverse=True, bulk=True, limit=1, mark_seen=mark_seen
            )
        )
    else:
        LOGGER.debug("Fetch mail %s", mail_id)
        msg = next(mailbox.fetch(f"UID {mail_id}", mark_seen=mark_seen))
    LOGGER.debug("Fetched mail %s", msg)

    if attachment:
        for att in msg.attachments:
            if att.filename == attachment:
                sys.stdout.buffer.write(att.payload)
                return 0
        print(
            f"attachment {attachment} not found",
            file=sys.stderr,
        )
        return 1

    if json:
        print_json(data=mail_to_dict(msg))
        return 0
    elif raw:
        print(msg.obj.as_string())
        return 0
    elif html:
        if msg.html:
            output = html2text.html2text(msg.html)
        else:
            output = msg.text
        print(output)
    else:
        print(msg.text)

    for att in msg.attachments:
        print(f"📎 Attachment: {att.filename}", file=sys.stderr)
    return 0


def display_emails(
    mailbox,
    console,
    no_title=False,
    search="ALL",
    unread_only=False,
    count=10,
    mark_seen=False,
    json=False,
    date_format="%H:%M %d/%m/%Y",
):
    json_data = []
    table = Table(
        show_header=not no_title,
        header_style="bold",
        expand=True,
        show_lines=False,
        show_edge=False,
        pad_edge=False,
        box=None,
        row_styles=["", "dim"],
    )
    table.add_column("ID", style="red", no_wrap=True)
    table.add_column("Subject", style="green", no_wrap=True, ratio=3)
    table.add_column("From", style="blue", no_wrap=True, ratio=2)
    table.add_column("Date", style="cyan", no_wrap=True)

    if unread_only:
        search = AND(seen=False)

    for msg in mailbox.fetch(
        criteria=search,
        reverse=True,
        bulk=True,
        limit=count,
        mark_seen=mark_seen,
        headers_only=False,  # required for attachments
    ):
        subj_prefix = "🆕 " if mail_is_unread(msg) else ""
        subj_prefix += "📎 " if len(msg.attachments) > 0 else ""
        subject = (
            msg.subject.replace("\n", "") if msg.subject else "<no-subject>"
        )
        if json:
            # Exclude full content for list display to reduce memory usage
            json_data.append(
                mail_to_dict(msg, date_format, include_content=False)
            )
        else:
            table.add_row(
                msg.uid if msg.uid else "???",
                f"{subj_prefix}{subject}",
                msg.from_,
                (msg.date.strftime(date_format) if msg.date else "???"),
            )
        if table.row_count >= count:
            break

    if json:
        print_json(data=json_data)
    else:
        console.print(table)
        if table.row_count == 0:
            print(
                "[yellow italic]No messages[/yellow italic]",
                file=sys.stderr,
            )
    return 0


def delete_emails(mailbox: BaseMailBox, mail_ids: list):
    LOGGER.warning("Deleting mails %s", mail_ids)
    mailbox.delete([str(x) for x in mail_ids])
    return 0


def set_seen(mailbox: BaseMailBox, mail_ids: list, value=True):
    LOGGER.info(
        "Marking mails as %s: %s", "read" if value else "unread", mail_ids
    )
    mailbox.flag(
        [str(x) for x in mail_ids],
        flag_set=(MailMessageFlags.SEEN),
        value=value,
    )
    return 0


def mark_read(mailbox: BaseMailBox, mail_ids: list):
    return set_seen(mailbox, mail_ids, value=True)


def mark_unread(mailbox: BaseMailBox, mail_ids: list):
    return set_seen(mailbox, mail_ids, value=False)


def main() -> int:
    console = Console()
    args = parse_args()
    logging.basicConfig(
        format="%(message)s",
        handlers=[RichHandler(console=console)],
        level=logging.DEBUG if args.debug else logging.INFO,
    )
    LOGGER.debug(args)

    try:
        with mb_connect(console, args) as mailbox:
            # Handle `myl <MAILID>` syntax (no subcommand provided)
            if args.command is None and args.MAILID is not None:
                return display_single_mail(
                    mailbox=mailbox,
                    mail_id=args.MAILID,
                    attachment=None,
                    mark_seen=args.mark_seen,
                    raw=args.raw,
                    html=args.html,
                    json=args.json,
                )

            # inbox display
            if args.command in ["list", None]:
                return display_emails(
                    mailbox=mailbox,
                    console=console,
                    no_title=args.no_title,
                    search=args.search,
                    unread_only=args.unread,
                    count=args.count,
                    mark_seen=args.mark_seen,
                    json=args.json,
                    date_format=args.date_format,
                )

            # single email
            elif args.command in ["get", "show", "display"]:
                return display_single_mail(
                    mailbox=mailbox,
                    mail_id=args.MAILID,
                    attachment=args.ATTACHMENT,
                    mark_seen=args.mark_seen,
                    raw=args.raw,
                    html=args.html,
                    json=args.json,
                )

            elif args.command in ["-1", "last"]:
                return display_single_mail(
                    mailbox=mailbox,
                    mail_id=None,
                    attachment=args.ATTACHMENT,
                    mark_seen=args.mark_seen,
                    raw=args.raw,
                    html=args.html,
                    json=args.json,
                )

            # mark emails as read
            elif args.command in ["read"]:
                return mark_read(
                    mailbox=mailbox,
                    mail_ids=args.MAILIDS,
                )

            elif args.command in ["unread"]:
                return mark_unread(
                    mailbox=mailbox,
                    mail_ids=args.MAILIDS,
                )

            # delete email
            elif args.command in ["delete", "remove"]:
                return delete_emails(
                    mailbox=mailbox,
                    mail_ids=args.MAILIDS,
                )
            else:
                error_msg(f"Unknown command: {args.command}")
                return 1

    except Exception:
        console.print_exception(show_locals=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
