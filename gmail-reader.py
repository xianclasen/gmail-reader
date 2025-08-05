import os
import base64
from dotenv import load_dotenv
import hashlib
import logging
import subprocess
from typing import Optional
from pydantic import BaseModel
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

load_dotenv()

# SCOPES: read-only Gmail access
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


class AttachmentConfig(BaseModel):
    user_id: str = os.getenv("user")
    query: str = os.getenv("filter")
    download_folder: str = os.getenv("attachments_folder")


def file_hash(filepath: str) -> str:
    """Calculate MD5 hash of a file"""
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
    return md5.hexdigest()


def data_hash(data: bytes) -> str:
    """Calculate MD5 hash of bytes data."""
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest()


def authenticate_gmail():
    creds = None
    if os.path.exists("token.json"):
        logger.debug("Loading credentials from token.json")
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    if not creds or not creds.valid:
        logger.debug("Valid credentials not found. Initiating OAuth flow.")
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def convert_heic_to_jpg(folder: str):
    """
    Converts all HEIC files in the given folder to JPG using 'heif-convert' or 'magick' (ImageMagick).
    """
    for filename in os.listdir(folder):
        if filename.lower().endswith(".heic"):
            logger.debug(f"Found HEIC file: {filename}")
            heic_path = os.path.join(folder, filename)
            jpg_path = os.path.splitext(heic_path)[0] + ".jpg"
            try:
                # Try using heif-convert if available
                subprocess.run(
                    ["heif-convert", heic_path, jpg_path],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                logger.info(f"Converted {heic_path} to {jpg_path} using heif-convert.")
            except FileNotFoundError:
                # Fallback to ImageMagick if heif-convert is not available
                logger.debug("heif-convert not found, trying ImageMagick.")
                try:
                    subprocess.run(
                        ["magick", "convert", heic_path, jpg_path],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    logger.info(
                        f"Converted {heic_path} to {jpg_path} using ImageMagick."
                    )
                except Exception as e:
                    logger.error(f"Failed to convert {heic_path}: {e}")
            except Exception as e:
                logger.error(f"Failed to convert {heic_path}: {e}")


def download_attachments(service, config: Optional[AttachmentConfig] = None):
    config = config or AttachmentConfig()
    os.makedirs(config.download_folder, exist_ok=True)

    next_page_token = None
    total_downloaded = 0

    while True:
        results = (
            service.users()
            .messages()
            .list(userId=config.user_id, q=config.query, pageToken=next_page_token)
            .execute()
        )
        messages = results.get("messages", [])
        if not messages:
            logger.debug("No messages found matching the query.")
            break

        # Only calculate hashes if there are messages to process
        existing_hashes = {}
        for fname in os.listdir(config.download_folder):
            fpath = os.path.join(config.download_folder, fname)
            if os.path.isfile(fpath):
                try:
                    existing_hashes[file_hash(fpath)] = fname
                except Exception as e:
                    logger.warning(f"Could not hash file {fpath}: {e}")

        for msg in messages:
            msg_data = (
                service.users()
                .messages()
                .get(userId=config.user_id, id=msg["id"])
                .execute()
            )
            logger.debug(f"Processing message ID: {msg['id']}")
            parts = msg_data["payload"].get("parts", [])
            for part in parts:
                filename = part.get("filename")
                if not filename:
                    logger.debug("No filename found in part, skipping.")
                    continue
                data = None
                if "data" in part["body"]:
                    data = part["body"]["data"]
                elif "attachmentId" in part["body"]:
                    att_id = part["body"]["attachmentId"]
                    att = (
                        service.users()
                        .messages()
                        .attachments()
                        .get(userId=config.user_id, messageId=msg["id"], id=att_id)
                        .execute()
                    )
                    data = att.get("data")
                if not data:
                    continue

                file_data = base64.urlsafe_b64decode(data.encode("UTF-8"))
                file_data_hash = data_hash(file_data)

                if file_data_hash in existing_hashes:
                    logger.info(
                        f"Attachment already exists as {existing_hashes[file_data_hash]}, skipping download."
                    )
                    continue

                # Avoid overwriting: if filename exists, append hash prefix
                file_path = os.path.join(config.download_folder, filename)
                if os.path.exists(file_path):
                    name, ext = os.path.splitext(filename)
                    file_path = os.path.join(
                        config.download_folder, f"{file_data_hash[:8]}_{name}{ext}"
                    )
                    logger.info(f"Filename exists, saving as {file_path}")

                with open(file_path, "wb") as f:
                    f.write(file_data)
                logger.info(f"Downloaded: {file_path}")
                existing_hashes[file_data_hash] = os.path.basename(file_path)
                total_downloaded += 1

        next_page_token = results.get("nextPageToken")
        if not next_page_token:
            break

    logger.info(f"Total attachments downloaded: {total_downloaded}")


if __name__ == "__main__":
    service = authenticate_gmail()
    config = AttachmentConfig()
    download_attachments(service, config)
    convert_heic_to_jpg(config.download_folder)
    logger.info("All attachments processed.")
