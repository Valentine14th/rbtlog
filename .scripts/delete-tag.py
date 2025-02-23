#!/usr/bin/env python3
import argparse
import json
import os
import sys
import glob

def process_file(filename, removal_tags, removed_shas):
    """
    Process a single JSON file (located in the logs/ directory).
    removal_tags: list of tags to remove; if empty, remove all tags.
    removed_shas: a set to which all removed SHA keys are added.
    """
    try:
        with open(filename, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return

    if not isinstance(data, dict) or "tags" not in data:
        print(f"File {filename} does not contain a valid top-level JSON object with 'tags'. Skipping.")
        return

    # If removal_tags is empty, remove all tags in the file.
    if not removal_tags:
        current_tags = list(data["tags"].keys())
    else:
        current_tags = removal_tags

    # Process each tag.
    for tag in current_tags:
        if tag in data["tags"]:
            for apk in data["tags"][tag]:
                sha = apk.get("upstream_signed_apk_sha256")
                version_code = str(apk.get("version_code"))
                if sha and sha in data.get("sha256", {}):
                    del data["sha256"][sha]
                    removed_shas.add(sha)
                    print(f"Removed sha '{sha}' from {filename}")
                if version_code and version_code in data.get("version_codes", {}):
                    del data["version_codes"][version_code]
                    print(f"Removed version_code '{version_code}' from {filename}")
            del data["tags"][tag]
            print(f"Removed tag '{tag}' from {filename}")
        else:
            print(f"Tag '{tag}' not found in {filename}")

    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Updated {filename} successfully.")
    except Exception as e:
        print(f"Error writing to {filename}: {e}")

def update_index(removed_shas, index_file="index.json"):
    """
    Open index.json and remove any top-level keys that match the SHAs in removed_shas.
    """
    if not os.path.exists(index_file):
        print(f"Index file '{index_file}' not found.")
        return

    try:
        with open(index_file, "r") as f:
            index_data = json.load(f)
    except Exception as e:
        print(f"Error reading {index_file}: {e}")
        return

    if not isinstance(index_data, dict):
        print(f"Index file '{index_file}' does not contain a top-level JSON object. Skipping.")
        return

    removed = False
    for sha in list(removed_shas):
        if sha in index_data:
            del index_data[sha]
            print(f"Removed SHA '{sha}' from {index_file}")
            removed = True

    if removed:
        try:
            with open(index_file, "w") as f:
                json.dump(index_data, f, indent=2)
            print(f"Updated {index_file} successfully.")
        except Exception as e:
            print(f"Error writing to {index_file}: {e}")
    else:
        print("No matching SHA entries found in index.json to remove.")

def main():
    parser = argparse.ArgumentParser(
        description="Remove specified keys from JSON files in the logs/ directory. "
                    "The JSON filename is inferred as 'logs/<id>.json'.\n"
                    "Usage examples:\n"
                    "  --remove ch.threema.libre 5.8.0 5.7.0\n"
                    "  --remove ch.threema.onprem"
    )
    # Each --remove argument takes one or more space-separated tokens.
    parser.add_argument(
        "--remove",
        action="append",
        nargs="+",
        required=True,
        help="Removal spec: <id> [tag1 tag2 ...]. If no tags are provided, all tags will be removed."
    )
    args = parser.parse_args()

    removed_shas = set()
    removal_operations = {}  # mapping: filename -> list of tags (empty list means remove all)

    # Build removal operations based on the provided --remove groups.
    for group in args.remove:
        file_id = group[0].strip()
        tags = [tag.strip() for tag in group[1:]]
        filename = f"logs/{file_id}.json"
        removal_operations[filename] = tags

    # Process each specified file.
    for filename, tags in removal_operations.items():
        if not os.path.exists(filename):
            print(f"File not found: {filename}")
            continue
        print(f"Processing {filename} with tags {tags if tags else 'ALL'}...")
        process_file(filename, removal_tags=tags, removed_shas=removed_shas)

    # Update index.json to remove entries for all removed SHAs.
    update_index(removed_shas)

if __name__ == "__main__":
    main()
