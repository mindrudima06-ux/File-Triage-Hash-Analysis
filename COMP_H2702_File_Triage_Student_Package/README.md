# File Triage & Hash Analysis

## Project Description

This is my individual Python project for COMP H2702 Scripting for Cybersecurity.

The program scans files in a folder and calculates their SHA-256 hashes. It compares these hashes with a reference CSV file to identify known and unknown files.

The program also detects duplicate files and saves the results in a text report.

## Requirements

- Python 3
- No additional Python packages required

## How to Run

Open the project folder in VS Code and run:

`python file_triage.py`

To scan another folder, run:

`python file_triage.py test_files`

The reference CSV must remain in the same folder as the Python script.

## Main Features

- Scans TXT and BIN files
- Displays file names, sizes, extensions and modified dates
- Calculates SHA-256 hashes
- Classifies files as KNOWN or UNKNOWN
- Detects duplicate files
- Saves results to `triage_report.txt`
- Handles missing files and invalid CSV data

## Cybersecurity Purpose

The program helps security analysts identify files that match known reference hashes and files that may need further investigation.

An UNKNOWN file is not automatically malicious. Matching SHA-256 hashes indicate identical file contents, but they do not prove that the files are safe.

## Testing

I tested the program using the five supplied files, a separate test folder, an empty folder and invalid reference data.

