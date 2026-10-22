# Python SOC Log Analyzer 

I chose to work with SSH authentication logs because repeated failed login attempts are a pattern a security analyst might investigate when looking for possible brute-force activity.

The goal was to create a small tool that reads log entries, identifies repeated failed logins, and generates a JSON report with the results.

## What it does

- Reads OpenSSH authentication logs.
- Extracts information such as timestamps, usernames, IP addresses, and event types.
- Identifies repeated failed login attempts from the same IP address.
- Flags an IP when it reaches five failed attempts within a five-minute window.
- Generates a JSON report summarizing the analysis and detected alerts.
- Uses automated tests to check whether the parsing, detection, and reporting functions work as expected.

## What I used

- **Python** — for parsing logs and implementing the detection rule.
- **Regular expressions** — to recognize patterns in log messages.
- **JSON** — to save the results in a structured format.
- **Git and GitHub** — to track changes and publish the project.
- **unittest** — to test the code.

The project currently uses Python's built-in libraries, so no third-party packages are required.


## Running the project

You need Python installed and an OpenSSH log file to analyze.

1. Place your log file in the `data/` folder.
2. Make sure the filename matches the path configured in `src/main.py`. The current filename is `OpenSSH_2k.log`.
3. From the project folder, run:

```bash
python src/main.py
```

The analysis summary will appear in the terminal, and the JSON report will be saved to `reports/analysis_report.json`.

To run the tests:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

## Results so far

In one run, the analyzer processed 2,000 log entries, rejected zero lines, and generated nine alerts for repeated failed SSH logins.

The detection rule uses a threshold of five failed attempts within five minutes. It reports the highest number of failures observed within that window for each flagged IP.

These alerts indicate patterns worth investigating; they do not prove that an attack succeeded.

## What I'm learning

Building this project has helped me practise working with log data, using regular expressions, organizing Python code into separate modules, writing tests, and using Git to manage a project.

There is still room to improve it. Some of the next things I want to explore are:

- Making the detection threshold configurable.
- Handling more OpenSSH log formats and timestamp variations.
- Detecting cases where repeated failures are followed by a successful login.
- Improving the report to make the results easier to investigate.

This is a learning project, and I plan to keep improving it as I develop my Python and cybersecurity skills.

## Ethical use

This tool is intended for learning and defensive security analysis. Only analyze logs you are authorized to access, and check dataset licensing before redistributing raw log files.
