# API BOLA Vulnerability Fuzzer

A simple Python tool for testing API endpoints for BOLA (Broken Object Level Authorization) vulnerabilities using OWASP ZAP.

## What is BOLA?

BOLA is when an API doesn't check if you should have access to specific data. For example, if changing `/users/123` to `/users/456` lets you see someone else's data, that's a BOLA vulnerability.

## Requirements

- Python 3.6+
- OWASP ZAP running on port 8080
- **Important**: ZAP must have an authenticated session configured before running the fuzzer
- Python package: `requests`

## Installation

1. Clone the repository
2. Install dependencies:
```bash
   pip install requests
```
3. Copy the example config:
```bash
   cp config.example.json config.json
```
4. Edit `config.json` with your API details

## Usage

### Using config file:
```bash
python fuzzer.py
```

### Using command-line arguments:
```bash
python fuzzer.py --url https://api.example.com --file openapi.json
```

### Options:
- `--url` - Target API base URL
- `--file` - Path to OpenAPI/Swagger file
- `--config` - Path to config file (default: config.json)

## How it works

1. Reads your OpenAPI specification
2. Finds endpoints with path parameters (like `/users/{id}`)
3. Replaces parameters with test payloads (1, 0, -5, text, etc.)
4. Sends requests through ZAP proxy
5. Checks if endpoints return 200 OK with invalid/fuzzed IDs
6. Saves suspicious endpoints to a results file

## Setting up ZAP

1. Start OWASP ZAP
2. Configure authentication for your target API
3. Create an authenticated session
4. Make sure ZAP is running on `localhost:8080`

The fuzzer will use ZAP's session for authentication in all requests.

## Output

Results are saved to `results_[timestamp].txt` with all endpoints that returned 200 OK during fuzzing.
