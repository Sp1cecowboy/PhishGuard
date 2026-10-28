# PhishGuard 🛡️

**PhishGuard is a lightweight URL risk analyzer built with Python and FastAPI.**

It evaluates suspicious URL patterns using heuristic rules, calculates a risk score, and explains which characteristics influenced the result.

> **Status:** MVP / educational cybersecurity project.

## Features

- URL risk scoring with heuristic rules.
- Detection of potentially suspicious URL characteristics.
- Checks for HTTP usage, IP-based hosts, suspicious keywords, and other URL patterns.
- Explanations of findings to make results easier to understand.
- Web interface for submitting URLs.
- REST API built with FastAPI.
- Automated tests with pytest.

Detection capabilities depend on the rules implemented in the current version.

## Tech Stack

- Python
- FastAPI
- Uvicorn
- pytest

## Project Structure

```text
phishguard/
├── app/
│   └── main.py
├── tests/
│   └── test_analyzer.py
├── requirements.txt
├── README.md
├── .gitignore
└── screenshots/
    └── preview.png
```

The `screenshots/preview.png` file is an example path for a screenshot you can add.

## Getting Started

### Requirements

- Python 3.11 or newer
- pip
- Git (optional, for cloning the repository)

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
```

Replace `YOUR_USERNAME` with your GitHub username.

Alternatively, download the repository as a ZIP and extract it.

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the application

```bash
python app/main.py
```

If the application does not open a browser automatically, navigate to:

http://127.0.0.1:8000

Keep the terminal open while using the application.

## API Documentation

FastAPI provides interactive API documentation at:

http://127.0.0.1:8000/docs

The main analysis endpoint is:

`POST /api/analyze`

Example request:

```json
{
  "url": "https://example.com"
}
```

The API returns the analysis result in JSON format. The exact response fields depend on the implementation.

## Running Tests

Activate the virtual environment and run:

```bash
python -m pytest -v
```

The current baseline test suite contains six tests covering basic domain handling, HTTP detection, IP-based hosts, suspicious keywords, unsupported URL schemes, and score bounds.

## Screenshots

Screenshots of the web interface and analysis results will be added here.

Suggested screenshots:

- Main interface.
- Analysis of a normal HTTPS URL.
- Analysis of a suspicious URL, showing the risk score and findings.

## Limitations

PhishGuard is a heuristic analyzer, not a definitive phishing detection service.

- A suspicious URL may be legitimate.
- A phishing URL may evade heuristic checks.
- HTTPS does not guarantee that a website is trustworthy.
- The heuristic score is not a calibrated probability of maliciousness.
- The current MVP should not be treated as a replacement for professional threat intelligence or security software.

Only submit URLs for analysis; do not visit suspicious links just to test them.

## Roadmap

- Expand automated test coverage.
- Improve lookalike-domain and typosquatting detection.
- Evaluate false-positive and false-negative rates.
- Explore integration with reputable threat intelligence sources.
- Improve the interface and reporting of analysis results.

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes.

## License

No license has been selected yet. Add a license before allowing others to reuse or redistribute the project.