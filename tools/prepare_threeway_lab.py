"""Prepare isolated lab secrets and a loopback-only variant of the official Wazuh compose.

Does not install Docker, modify WSL/sysctl, or start containers.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "benchmarks" / "three_way" / "lab"
WAZUH_TAG = "v4.14.10"


def init_secrets(folder=LAB):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / ".env"
    if target.exists():
        return False
    names = ("ELASTIC_PASSWORD", "KIBANA_SYSTEM_PASSWORD", "KIBANA_ENCRYPTION_KEY",
             "KIBANA_SECURITY_KEY", "KIBANA_REPORTING_KEY")
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        for name in names:
            stream.write(name + "=" + secrets.token_hex(24) + "\n")
    return True


def prepare_wazuh(repo):
    import yaml  # Only needed when preparing the optional Wazuh Docker checkout.
    single = Path(repo) / "single-node"
    source = single / "docker-compose.yml"
    content = yaml.safe_load(source.read_text(encoding="utf-8"))
    content["name"] = "socbench-wazuh"
    ports = {"wazuh.manager": ["127.0.0.1:55000:55000"],
             "wazuh.indexer": ["127.0.0.1:19200:9200"],
             "wazuh.dashboard": ["127.0.0.1:9443:5601"]}
    for name, values in ports.items():
        content["services"][name]["ports"] = values
        if not content["services"][name]["image"].endswith(":" + WAZUH_TAG[1:]):
            raise ValueError("Checkout Wazuh không khớp phiên bản đã chốt")
    content["services"]["wazuh.manager"]["volumes"].append(
        "./config/socbench-rules.xml:/var/ossec/etc/rules/socbench-rules.xml:ro")
    # Modify the dedicated checkout's mounted config, never an existing live manager.
    config = single / "config" / "wazuh_cluster" / "wazuh_manager.conf"
    text = config.read_text(encoding="utf-8")
    block = "\n".join((LAB / "wazuh-localfile.xml").read_text(encoding="utf-8").splitlines()[1:])
    if "/var/ossec/logs/socbench-input.jsonl" not in text:
        if "</ossec_config>" not in text:
            raise ValueError("Không tìm thấy ossec_config trong checkout")
        text = text.replace("</ossec_config>", block + "\n</ossec_config>", 1)
        ET.fromstring("<configs>" + text + "</configs>")
        backup = config.with_suffix(config.suffix + ".before-socbench")
        if not backup.exists():
            backup.write_text(config.read_text(encoding="utf-8"), encoding="utf-8")
        config.write_text(text, encoding="utf-8")
    sys.path.insert(0, str(ROOT))
    from benchmarks.three_way.core import wazuh_rules_xml
    (single / "config" / "socbench-rules.xml").write_text(wazuh_rules_xml(), encoding="utf-8")
    target = single / "compose.socbench.json"
    target.write_text(json.dumps(content, indent=2), encoding="utf-8")
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch-wazuh", action="store_true", help="Download the official pinned Wazuh Docker checkout")
    args = parser.parse_args()
    created = init_secrets()
    print("Created ignored lab/.env" if created else "Kept existing lab/.env")
    if args.fetch_wazuh:
        vendor = LAB / "vendor" / "wazuh-docker"
        vendor.parent.mkdir(parents=True, exist_ok=True)
        if not vendor.exists():
            subprocess.run(["git", "clone", "--depth", "1", "--branch", WAZUH_TAG,
                            "https://github.com/wazuh/wazuh-docker.git", str(vendor)], check=True)
        tag = subprocess.run(["git", "-C", str(vendor), "describe", "--tags", "--exact-match"],
                             check=True, capture_output=True, text=True).stdout.strip()
        if tag != WAZUH_TAG:
            raise ValueError("Vendor checkout không ở đúng tag")
        print("Prepared:", prepare_wazuh(vendor))
    print("No containers started. No operating-system settings changed.")


if __name__ == "__main__":
    main()
