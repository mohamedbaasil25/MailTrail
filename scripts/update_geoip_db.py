#!/usr/bin/env python3
"""
scripts/update_geoip_db.py

Downloads (or refreshes) the MaxMind GeoLite2-City database that
services/geoip_service.py looks for. Without this file present,
Geo Intelligence runs entirely on the clearly-labeled simulated fallback
built into geoip_service.py - functional for demos, but not real
attribution. This script is what turns that on for real, and is meant to
be run periodically (MaxMind publishes GeoLite2 updates roughly weekly) -
e.g. as a cron job, a scheduled CI workflow, or a container init step.

Requires a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
Then set these environment variables (see .env.example):
    MAXMIND_ACCOUNT_ID    - your numeric account ID
    MAXMIND_LICENSE_KEY   - a license key generated in your account
    MAXMIND_EDITION_ID    - defaults to GeoLite2-City

Usage:
    python scripts/update_geoip_db.py
    python scripts/update_geoip_db.py --output /custom/path/GeoLite2-City.mmdb
    python scripts/update_geoip_db.py --check    # exit 0 if a DB already exists, else 1 - no download

This reuses services/http_client.py's retry/backoff logic rather than a
bare requests.get() - the same transient-failure handling already proven
out for the threat-intel integration, applied to a download that (per
MaxMind's own docs) is periodically flaky under load.
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.http_client import fetch_bytes, APIClientError, APIRequestError  # noqa: E402

DOWNLOAD_URL_TEMPLATE = "https://download.maxmind.com/geoip/databases/{edition_id}/download?suffix=tar.gz"


def download_database(account_id: str, license_key: str, edition_id: str) -> bytes:
    """Downloads the GeoLite2 tarball, retrying transient failures."""
    url = DOWNLOAD_URL_TEMPLATE.format(edition_id=edition_id)
    print(f"Downloading {edition_id} from MaxMind...")
    return fetch_bytes(url, auth=(account_id, license_key), timeout=60.0, max_retries=4, max_delay=20.0)


def extract_mmdb(tarball_bytes: bytes, edition_id: str) -> bytes:
    """
    MaxMind ships the .mmdb inside a dated folder within the tarball, e.g.
    GeoLite2-City_20260115/GeoLite2-City.mmdb. Find it by suffix rather than
    assuming an exact path, since that date-stamped folder name changes
    with every release.
    """
    with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
        member = next((m for m in tar.getmembers() if m.name.endswith(f"{edition_id}.mmdb")), None)
        if member is None:
            raise RuntimeError(f"No {edition_id}.mmdb file found inside the downloaded archive")
        extracted = tar.extractfile(member)
        if extracted is None:
            raise RuntimeError(f"Could not read {member.name} from the archive")
        return extracted.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", default="GeoLite2-City.mmdb", help="Where to write the .mmdb file (default: ./GeoLite2-City.mmdb, matching geoip_service.py's default lookup path)")
    parser.add_argument("--check", action="store_true", help="Exit 0 if the output file already exists, 1 otherwise. Does not download.")
    args = parser.parse_args()

    output_path = Path(args.output)

    if args.check:
        sys.exit(0 if output_path.exists() else 1)

    account_id = os.getenv("MAXMIND_ACCOUNT_ID", "")
    license_key = os.getenv("MAXMIND_LICENSE_KEY", "")
    edition_id = os.getenv("MAXMIND_EDITION_ID", "GeoLite2-City")

    if not account_id or not license_key:
        print(
            "MAXMIND_ACCOUNT_ID and/or MAXMIND_LICENSE_KEY are not set.\n"
            "Geo Intelligence will keep using the simulated fallback until "
            "these are configured. Get a free account at "
            "https://www.maxmind.com/en/geolite2/signup"
        )
        sys.exit(1)

    try:
        tarball = download_database(account_id, license_key, edition_id)
        mmdb_bytes = extract_mmdb(tarball, edition_id)
    except APIClientError as exc:
        # Almost always a bad/expired account ID or license key (401/403).
        print(f"MaxMind rejected the request - check your credentials: {exc}")
        sys.exit(1)
    except APIRequestError as exc:
        print(f"Could not reach MaxMind after retries: {exc}")
        sys.exit(1)
    except (tarfile.TarError, RuntimeError) as exc:
        print(f"Downloaded archive was malformed: {exc}")
        sys.exit(1)

    tmp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    tmp_path.write_bytes(mmdb_bytes)
    tmp_path.replace(output_path)  # atomic on POSIX - readers never see a half-written file

    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"Wrote {output_path} ({size_mb:.1f} MB). Restart the app (or wait for the next lookup) to start using real GeoIP data.")


if __name__ == "__main__":
    main()
