
from pathlib import Path
from datetime import datetime
import hashlib
import csv


def load_reference(filename):
    known_hashes = {}

    with open(filename, "r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames or not {"sha256", "label"}.issubset(reader.fieldnames):
            raise ValueError("Missing columns in the reference CSV.")

        for row in reader:
            file_hash = (row["sha256"] or "").strip().lower()
            label = (row["label"] or "").strip()

            if len(file_hash) != 64 or any(c not in "0123456789abcdef" for c in file_hash):
                raise ValueError("Invalid SHA-256 hash in the reference CSV.")

            known_hashes[file_hash] = label

    return known_hashes


def scan_files(folder, known_hashes):
    results = []

    for file in sorted(folder.iterdir()):
        if (file.is_file()
        and file.suffix.lower() in (".txt", ".bin")
        and file.name.lower() not in ("readme.txt", "triage_report.txt")):

            try:
                info = file.stat()
                file_hash = hashlib.sha256(file.read_bytes()).hexdigest()

                if file_hash in known_hashes:
                    status = "KNOWN"
                    label = known_hashes[file_hash]
                else:
                    status = "UNKNOWN"
                    label = "No reference match"

                results.append({
                    "name": file.name,
                    "extension": file.suffix,
                    "size": info.st_size,
                    "modified": str(datetime.fromtimestamp(info.st_mtime)),
                    "hash": file_hash,
                    "status": status,
                    "label": label
                })

            except OSError as error:
                print("Error reading", file.name, ":", error)

    return results


def find_duplicates(results):
    hash_groups = {}

    for file in results:
        file_hash = file["hash"]

        if file_hash not in hash_groups:
            hash_groups[file_hash] = []

        hash_groups[file_hash].append(file["name"])

    duplicates = []

    for file_hash, filenames in hash_groups.items():
        if len(filenames) > 1:
            duplicates.append((file_hash, filenames))

    return duplicates


def generate_report(results, duplicates):
    lines = []

    lines.append("FILE TRIAGE & HASH ANALYSIS REPORT")
    lines.append("===================================")

    known_count = 0
    unknown_count = 0

    for file in results:
        lines.append("")
        lines.append("File name: " + file["name"])
        lines.append("Extension: " + file["extension"])
        lines.append("Size: " + str(file["size"]) + " bytes")
        lines.append("Last modified: " + file["modified"])
        lines.append("SHA-256: " + file["hash"])
        lines.append("Status: " + file["status"])
        lines.append("Reference: " + file["label"])
        lines.append("------------------------")

        if file["status"] == "KNOWN":
            known_count += 1
        else:
            unknown_count += 1

    lines.append("")
    lines.append("FILE SUMMARY")
    lines.append("------------------------")
    lines.append("Total files: " + str(len(results)))
    lines.append("Known files: " + str(known_count))
    lines.append("Unknown files: " + str(unknown_count))

    lines.append("")
    lines.append("DUPLICATE FILE REPORT")
    lines.append("------------------------")

    for file_hash, filenames in duplicates:
        lines.append("Duplicate files: " + ", ".join(filenames))
        lines.append("Matching SHA-256: " + file_hash)

    if not duplicates:
        lines.append("No duplicate files found.")

    lines.append("Duplicate groups found: " + str(len(duplicates)))

    lines.append("")
    lines.append("SECURITY NOTES")
    lines.append("------------------------")
    lines.append("KNOWN means the hash matches the reference list.")
    lines.append("UNKNOWN means no reference match was found.")
    lines.append("An unknown file is not automatically malicious.")
    lines.append("Matching hashes indicate identical file contents.")

    return "\n".join(lines)


def main():
    import sys

    project_folder = Path(__file__).resolve().parent

    if len(sys.argv) > 1:
        folder = Path(sys.argv[1]).expanduser()
    else:
        folder = project_folder

    try:
        known_hashes = load_reference(project_folder / "hashes_reference.csv")

        results = scan_files(folder, known_hashes)
        duplicates = find_duplicates(results)

        report = generate_report(results, duplicates)

        print(report)

        report_path = folder / "triage_report.txt"
        report_path.write_text(report, encoding="utf-8")

        print("\nReport saved to:", report_path)

    except (OSError, ValueError, csv.Error) as error:
        print("Error:", error)


if __name__ == "__main__":
    main()
