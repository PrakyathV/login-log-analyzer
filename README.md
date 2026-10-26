# Failed Login Log Analyzer

A Python-based cybersecurity project that analyzes authentication logs,
tracks failed logins by IP address and username, and flags suspicious
login activity using a configurable threshold.

## Features
- Parse synthetic authentication logs.
- Analyze OpenSSH failed and successful login events.
- Track failed attempts by IP address and username.
- Detect invalid-user events.
- Expand repeated OpenSSH log messages.
- Generate threshold-based alerts.
- Process large logs line by line.
- Include automated unit tests.

## Requirements
- Python 3.10+
- No third-party Python packages required.

## Usage

Analyze the sample log:

    python main.py

Analyze an OpenSSH log:

    python main.py data/raw/SSH.log --threshold 20

Run tests:

    python -m unittest discover -s tests -v

## Project Structure

    main.py
    README.md
    .gitignore
    tests/
        test_main.py
    data/
        raw/  (local datasets excluded from Git)

## Security Notes
Use authorized log sources. Historical IP addresses are not proof of
current malicious activity. Raw datasets should not be committed without
reviewing their contents and distribution permissions.

## Future Improvements
- Export reports to CSV or JSON.
- Add date and time-window filtering.
- Visualize authentication trends.
- Integrate with a SIEM workflow.
