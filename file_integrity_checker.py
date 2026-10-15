import os
import hashlib
import json

def calculate_hash(filepath):
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def scan_folder(folder_path):
    file_hashes = {}

    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            filepath = os.path.join(root, filename)

            try:
                file_hashes[filepath] = calculate_hash(filepath)
            except (PermissionError, OSError):
                print("Could not read:", filepath)

    return file_hashes


def save_baseline(folder_path, baseline_file):
    hashes = scan_folder(folder_path)

    with open(baseline_file, "w") as file:
        json.dump(hashes, file, indent=4)

    print("Baseline created successfully!")
    print("Files recorded:", len(hashes))


def check_integrity(folder_path, baseline_file):
    if not os.path.exists(baseline_file):
        print("Baseline not found. Create a baseline first.")
        return

    with open(baseline_file, "r") as file:
        old_hashes = json.load(file)

    new_hashes = scan_folder(folder_path)

    old_files = set(old_hashes.keys())
    new_files = set(new_hashes.keys())

    added_files = new_files - old_files
    deleted_files = old_files - new_files
    common_files = old_files & new_files

    modified_files = []

    for filepath in common_files:
        if old_hashes[filepath] != new_hashes[filepath]:
            modified_files.append(filepath)

    print("\n--- File Integrity Report ---")

    if added_files:
        for filepath in sorted(added_files):
            print("Added:", filepath)

    if deleted_files:
        for filepath in sorted(deleted_files):
            print("Deleted:", filepath)

    if modified_files:
        for filepath in sorted(modified_files):
            print("Modified:", filepath)

    if not added_files and not deleted_files and not modified_files:
        print("No changes detected. All files are unchanged.")


print("FILE INTEGRITY CHECKER")
print("1. Create baseline")
print("2. Check file integrity")

choice = input("Enter your choice (1 or 2): ")

folder_path = input("Enter the folder path to scan: ").strip().strip('"')
baseline_file = "file_integrity_baseline.json"

if choice == "1":
    save_baseline(folder_path, baseline_file)
elif choice == "2":
    check_integrity(folder_path, baseline_file)
else:
    print("Invalid choice.")
