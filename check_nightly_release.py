"""Compare generated XML with the XML asset published under a release tag.

Usage:
    uv run python check_nightly_release.py --repository HLND2T/kphtools \\
        --xml kphdyn.xml --tag nightly

GITHUB_TOKEN authenticates GitHub API requests when set. The decision is printed
as changed=true/false and appended to GITHUB_OUTPUT when running in Actions.
Both decisions return zero; errors return one without emitting a decision.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from urllib.parse import quote
import xml.etree.ElementTree as ET

import requests


GITHUB_API_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
XML_ASSET_NAME = "kphdyn.xml"
REQUEST_TIMEOUT_SECONDS = 60


def canonicalize_xml(content: bytes) -> str:
    return ET.canonicalize(content, strip_text=True, with_comments=False)


def release_xml_changed(
    repository: str,
    xml_path: Path,
    tag: str = "nightly",
    token: str | None = None,
) -> bool:
    candidate = canonicalize_xml(xml_path.read_bytes())
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    release_url = f"{GITHUB_API_URL}/repos/{repository}/releases/tags/{quote(tag, safe='')}"
    release_response = requests.get(
        release_url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS
    )
    if release_response.status_code == 404:
        print(f"Release {tag} does not exist; publish the initial XML.")
        return True
    release_response.raise_for_status()
    asset = next(
        (
            asset
            for asset in release_response.json()["assets"]
            if asset["name"] == XML_ASSET_NAME
        ),
        None,
    )
    if asset is None:
        print(f"Release {tag} has no {XML_ASSET_NAME}; publish the XML.")
        return True

    asset_response = requests.get(
        asset["url"],
        headers={**headers, "Accept": "application/octet-stream"},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    asset_response.raise_for_status()
    published = canonicalize_xml(asset_response.content)
    changed = candidate != published
    print(
        "XML data changed; publish the XML."
        if changed else "XML data is unchanged; skip publication."
    )
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository", required=True, help="GitHub repository in owner/repo form"
    )
    parser.add_argument("--xml", type=Path, default=Path(XML_ASSET_NAME))
    parser.add_argument("--tag", default="nightly")
    args = parser.parse_args(argv)

    try:
        changed = release_xml_changed(
            args.repository, args.xml, tag=args.tag, token=os.getenv("GITHUB_TOKEN")
        )
        decision = f"changed={'true' if changed else 'false'}"
        output_path = os.getenv("GITHUB_OUTPUT")
        if output_path:
            with Path(output_path).open("a", encoding="utf-8", newline="\n") as output:
                output.write(f"{decision}\n")
    except (
        OSError, requests.RequestException, ET.ParseError, ValueError, KeyError, TypeError
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(decision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
