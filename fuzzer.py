import requests
import json
from urllib.parse import urljoin
import warnings
import datetime
import argparse
import os
import asyncio
import httpx
import time

# Suppress SSL warnings when using OWASP ZAP as MITM proxy
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Default configuration
DEFAULT_CONFIG = {
    'base_url': 'https://api.example.com',
    'openapi_file': 'openapi.json',
    'zap_proxy': 'http://127.0.0.1:8080'
}

# Fuzzing payloads to test for BOLA vulnerabilities
FUZZ_PAYLOADS = [
    '1',
    '0',
    '6,5',
    '24',
    '-5',
    '*&^$',
    'text'
]

# Containers for result data
positive_responses = set()
canceled_requests = set()

requests_count = 0


# Load configuration from file
def load_config(config_file='config.json'):
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f'Warning: Invalid JSON in {config_file}, using defaults')
    return DEFAULT_CONFIG.copy()


# Parse command line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(
        description='API BOLA Vulnerability Fuzzer - Tests API endpoints for Broken Object Level Authorization'
    )
    parser.add_argument(
        '--url',
        help='Base URL of the target API (overrides config file)'
    )
    parser.add_argument(
        '--file',
        help='Path to OpenAPI specification file (overrides config file)'
    )
    parser.add_argument(
        '--config',
        default='config.json',
        help='Path to configuration file (default: config.json)'
    )
    return parser.parse_args()


# Load OpenAPI specification from JSON file
def load_openapi_spec(file_path):
    print(f"Loading OpenAPI spec from: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f'Error: File {file_path} not found')
        return None
    except json.JSONDecodeError:
        print(f'Error: Invalid JSON format in {file_path}')
        return None


# Async requests preparation
async def send_req(client, full_url, method, path, semaphore):
    global requests_count, positive_responses, canceled_requests
    async with semaphore:
        try:
            requests_count += 1
            if requests_count % 10 == 0:
                print(f'Processed {requests_count} requests...', end='\r' )
            res = await client.request(
                                    method,
                                    full_url,
                                    data="{}",
                                    timeout=25,
                                )

            # Debag loggs
            # print(f'Request #{requests_count}: {method.upper()} {full_url}')
            # print(f'STATUS: {res.status_code}\n')
        
        # Status 200 on fuzzed input indicates potential BOLA vulnerability
            if res.status_code == 200:
                positive_responses.add(path)
                print(f"WARNING: Potential vulnerability found in: {path}\n")       
        except Exception as e:
            print(f'Request: {method.upper()} {full_url}')
            print(f"ERROR: {repr(e)}\n")
            canceled_requests.add(path)
        

# Fuzz all path parameters in the API specification
async def fuzz_path_parameters(spec, base_url, pr):
    
    print('Starting fuzzing process...\n')

    tasks = []

    semaphore = asyncio.Semaphore(24)

    fixed_url = base_url.rstrip('/') + '/'

    async with httpx.AsyncClient(proxy=pr, verify=False) as client:
        for path, path_data in spec.get('paths', {}).items():
            for method, operation in path_data.items():
                # Extract path parameters from the endpoint
                path_params = [
                    p for p in operation.get('parameters', []) 
                    if p.get('in') == 'path'
                ]
                if not path_params:
                    continue

                # Test each payload against the endpoint
                for payload in FUZZ_PAYLOADS:
                    fuzzed_path = path

                    # Replace all path parameters with the current payload
                    for param in path_params:
                        placeholder = f'{{{param["name"]}}}'
                        fuzzed_path = fuzzed_path.replace(placeholder, payload)
        
                    full_url = urljoin(fixed_url, fuzzed_path.lstrip('/'))
                    tasks.append(send_req(client, full_url, method, path, semaphore))
        await asyncio.gather(*tasks)
    print(f'Fuzzing completed. Total requests: {requests_count}')


# Save results to file
def save_to_file(pos_resp, can_req):
    if not pos_resp and not can_req:
        print("\nNo vulnerable endpoints found")
        return
    timestamp = datetime.datetime.now().strftime("%H-%M-%S_%d-%m-%y")
    filename = os.path.join('results', f"results_{timestamp}.txt") 
    with open(filename, "w") as f:
        if pos_resp:
            f.write("Endpoints that returned 200 OK with fuzzed payloads:\n")
            f.write("=" * 50 + "\n\n")
            f.write("\n".join(sorted(pos_resp)))
            f.write('\n\n')

        if can_req:
            f.write("Requests were canceled on endpoints:\n")
            f.write('\n'.join(sorted(can_req)))
    print(f"\nResults saved to: {filename}")
      


# Main execution
if __name__ == '__main__':
    
    if not os.path.exists('results'):
        os.makedirs('results')

    # Parse command line arguments
    args = parse_arguments()
    
    # Load configuration
    config = load_config(args.config)
    
    # Command line arguments override config file
    BASE_URL = args.url if args.url else config['base_url']
    OPENAPI_FILE = args.file if args.file else config['openapi_file']
    ZAP_PROXY_HOST = config['zap_proxy']
    
    print("=" * 60)
    print("API BOLA Vulnerability Fuzzer")
    print("=" * 60)
    print(f"Target URL: {BASE_URL}")
    print(f"OpenAPI File: {OPENAPI_FILE}")
    print(f"ZAP Proxy: {ZAP_PROXY_HOST}")
    print("=" * 60 + "\n")

    # Start time point for duration measurement
    start_time = time.perf_counter()

    try:
        spec = load_openapi_spec(OPENAPI_FILE)
        if spec:
            asyncio.run(fuzz_path_parameters(spec, BASE_URL, ZAP_PROXY_HOST))
    except KeyboardInterrupt:
        print('\n\nFuzzing interrupted by user')
    finally:
        end_time = time.perf_counter()
        duration = end_time - start_time
        print(f"Duration: {duration:.2f}")
        save_to_file(positive_responses, canceled_requests)