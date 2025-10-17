# Tatou API Fuzzing Test Plan

This document describes the comprehensive fuzzing test plan created for the Tatou platform.

## Overview

This fuzzing test plan uses the schemathesis tool to perform comprehensive security testing on all Tatou API endpoints, including:

- **Automated API Testing**: Automatically generate test cases based on OpenAPI specifications
- **Boundary Condition Testing**: Test various boundary values and exceptional inputs
- **Security Vulnerability Detection**: Detect common security vulnerabilities such as SQL injection, XSS, path traversal
- **Performance Testing**: Test API performance under high load

## File Structure

```
tatou/
├── openapi.yaml              # OpenAPI specification file
├── fuzzing_config.yaml       # Fuzzing configuration file
├── fuzzing_test.py           # Main test script
├── requirements-fuzzing.txt  # Python dependencies
├── run_fuzzing.sh           # Run script
└── FUZZING_README.md        # This document
```

## Quick Start

### 1. Start Tatou Server

Ensure the Tatou server is running:

```bash
cd server
python3 src/server.py
```

The server should be running on `http://localhost:5000`.

### 2. Run Fuzzing Tests

There are two ways to run the tests:

#### Method 1: Using Script (Recommended)

```bash
./run_fuzzing.sh
```

#### Method 2: Manual Run

```bash
# Install dependencies
pip3 install -r requirements-fuzzing.txt

# Run tests
python3 fuzzing_test.py
```

## API Endpoints Covered by Testing

### Authentication Related
- `POST /api/create-user` - User registration
- `POST /api/login` - User login

### Document Management
- `POST /api/upload-document` - Upload document
- `GET /api/list-documents` - List documents
- `GET /api/get-document` - Get document
- `GET /api/get-document/{document_id}` - Get document by ID
- `DELETE /api/delete-document` - Delete document
- `DELETE /api/delete-document/{document_id}` - Delete document by ID

### Version Management
- `GET /api/list-versions` - List versions
- `GET /api/list-versions/{document_id}` - List versions for specific document
- `GET /api/list-all-versions` - List all versions
- `GET /api/get-version/{link}` - Get version by link

### Watermarking Features
- `GET /api/get-watermarking-methods` - Get watermarking methods
- `POST /api/read-watermark-by-link/{link}` - Read watermark
- `POST /api/create-watermark` - Create watermark
- `POST /api/create-watermark/{document_id}` - Create watermark for specific document

### RMAP Protocol
- `POST /api/rmap-initiate` - RMAP initialization
- `POST /api/rmap-get-link` - RMAP get link
- `POST /api/rmap-identify-leak` - RMAP identify leak (admin function)

### System Functions
- `GET /healthz` - Health check

## Testing Strategy

### 1. Normal Input Testing
- Test APIs with valid parameters and request bodies
- Verify correct response format and status codes

### 2. Boundary Condition Testing
- Test maximum/minimum values
- Test empty and null values
- Test overly long strings

### 3. Malicious Input Testing
- SQL injection attacks
- XSS attacks
- Path traversal attacks
- Malformed JSON
- Invalid file types

### 4. Authentication and Authorization Testing
- Unauthenticated requests
- Invalid tokens
- Privilege escalation attempts

## Configuration Options

In `fuzzing_config.yaml` you can configure:

- **Test Parameters**: Concurrency, timeout, maximum requests
- **Authentication Settings**: Bearer token, Admin key
- **Endpoint Configuration**: Number of test cases per endpoint
- **Fuzzing Data**: Custom test data

## Reports and Logs

After test completion, the following files will be generated:

- `fuzzing_report.html` - Detailed report in HTML format
- `fuzzing_report.json` - Structured report in JSON format
- `fuzzing_summary.json` - Test summary
- `fuzzing.log` - Detailed execution log

## Custom Testing

You can add custom test cases in the `run_custom_fuzzing_tests()` method in `fuzzing_test.py`:

```python
test_cases = [
    {
        "name": "Custom Test Name",
        "endpoint": "/api/endpoint",
        "method": "POST",
        "data": {"key": "value"}
    }
]
```

## Troubleshooting

### Common Issues

1. **Server Connection Failed**
   - Ensure Tatou server is running
   - Check if the port is correct (default 5000)

2. **Authentication Failed**
   - Check if server correctly handles user registration and login
   - View authentication error messages in logs

3. **Test Timeout**
   - Increase `max_response_time` configuration
   - Reduce concurrency `workers`

4. **Out of Memory**
   - Reduce `max_requests_per_test`
   - Reduce `workers` count

### Debug Mode

Set environment variables to enable detailed logging:

```bash
export PYTHONPATH=.
export LOG_LEVEL=DEBUG
python3 fuzzing_test.py
```

## Security Recommendations

Based on fuzzing test results, it is recommended to:

1. **Input Validation**: Strictly validate all user inputs
2. **Authentication Enhancement**: Implement stronger authentication mechanisms
3. **Error Handling**: Avoid leaking sensitive information in error responses
4. **Rate Limiting**: Implement API rate limiting to prevent abuse
5. **Log Monitoring**: Monitor abnormal requests and potential attacks

## Continuous Integration

Fuzzing tests can be integrated into CI/CD workflows:

```yaml
# .github/workflows/fuzzing.yml
name: API Fuzzing
on: [push, pull_request]
jobs:
  fuzzing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.8
      - name: Install dependencies
        run: pip install -r requirements-fuzzing.txt
      - name: Run fuzzing tests
        run: python3 fuzzing_test.py
```

## Contact and Support

For questions or suggestions, please refer to the project documentation or contact the development team.