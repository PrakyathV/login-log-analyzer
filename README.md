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

Clone the repository:

    git clone https://github.com/PrakyathV/login-log-analyzer.git
    cd login-log-analyzer

Analyze the included sample log:

    python main.py --log sample_logs/auth.log --threshold 4

Analyze your own OpenSSH log:

    python main.py --log /path/to/auth.log --threshold 20

Run the automated tests:

    python -m unittest discover -s tests -v

View available command-line options:

    python main.py --help

## Example Results

Using the included sample log with a threshold of 4:

- Failed login attempts: 7
- Successful logins: 2
- Alert: 192.0.2.10 had 5 failed login attempts

These results come from synthetic sample data.

## Project Structure

    main.py
    README.md
    .gitignore
    sample_logs/
        auth.log
    tests/
        test_main.py
    reports/  (generated reports)
    data/
        raw/  (local datasets excluded from Git)

## Security Notes

Use only authorized log sources. Historical IP addresses are not proof
of current malicious activity. Review datasets before distributing them.

## Future Improvements

- Export reports to CSV or JSON.
- Add date and time-window filtering.
- Visualize authentication trends.
- Integrate with a SIEM workflow.
