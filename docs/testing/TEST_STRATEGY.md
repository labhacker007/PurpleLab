# Joti Sim — Test Strategy

## Testing Philosophy

Joti Sim is a cybersecurity simulation platform that generates vendor-format alert payloads. Our testing strategy prioritizes:

1. **Payload fidelity** — Every generator must produce payloads that match the real vendor's documented format. A malformed payload means the simulator is useless for testing downstream SOC tooling.
2. **Engine reliability** — Sessions must start, run, and stop cleanly without leaking resources (schedulers, HTTP clients, memory).
3. **Safety** — All IOC data (IPs, domains, URLs) must use reserved/example ranges to prevent accidental interaction with real threat infrastructure.
4. **API correctness** — All endpoints must return proper status codes, handle edge cases, and reject malformed input.

## Test Categories

### Unit Tests (`tests/unit/`)

**Generator tests** (`tests/unit/test_generators/`):
- One test file per generator (12 total)
- Verify every required field is present in the output dict
- Validate field value ranges (severity scores, confidence levels, etc.)
- Confirm MITRE ATT&CK technique IDs match `T####(.###)?` format
- Check UUIDs, timestamps, and SHA256 hashes are well-formed
- Ensure all IOCs come from safe example pools (no real infrastructure)

**Engine tests** (`tests/unit/test_engine.py`):
- Session CRUD: create, read, update, delete
- Start/stop: scheduler creation, generator instantiation, cleanup
- Event log: buffer limits, session filtering, limit parameter
- Generator registry: all 12 products registered and instantiable
- Concurrent sessions: independent state, no cross-contamination

**Scenario tests** (`tests/unit/test_scenarios.py`):
- All scenarios reference valid product types
- Severity weights sum to 1.0
- Events per minute within bounds

### Integration Tests (`tests/integration/`)

- **API legacy tests**: Full endpoint coverage for `/api/*` routes
- **Session lifecycle**: End-to-end create -> start -> events -> stop -> delete
- **v2 API stubs**: Specification tests for the upcoming v2 API (xfail until implemented)

### Security Tests (`tests/security/`)

- **Input validation**: SQL injection, XSS payloads, path traversal, oversized payloads
- **CORS**: Verify CORS configuration matches security requirements
- **Authentication**: Document current (open) state and specify future auth requirements

## Coverage Goals

| Category | Target | Current |
|----------|--------|---------|
| Generator payload fields | 100% of required fields per vendor | Tracked per generator |
| Engine session lifecycle | All state transitions | Covered |
| API endpoints | Every route, success + error | 12/12 routes |
| Security | OWASP Top 10 relevant items | Injection, XSS, CORS |
| Overall line coverage | > 85% | TBD (run `pytest --cov`) |

## Running Tests

```bash
# All tests
pytest

# Unit tests only
pytest tests/unit/

# Single generator
pytest tests/unit/test_generators/test_splunk_generator.py -v

# Integration tests
pytest tests/integration/

# Security tests
pytest tests/security/

# With coverage
pytest --cov=backend --cov-report=html
```

## CI/CD Integration Plan

### Phase 1 — Local Development (Current)
- Developers run `pytest` before committing
- Pre-commit hook runs unit tests

### Phase 2 — GitHub Actions
```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt && pip install pytest pytest-asyncio pytest-cov httpx
      - run: pytest --cov=backend --cov-report=xml
      - uses: codecov/codecov-action@v4
```

### Phase 3 — Quality Gates
- PR checks: all tests must pass before merge
- Coverage: PRs must not decrease coverage below 85%
- Security tests: must pass on every commit

## How Test Results Feed Back to Development

1. **Failing generator tests** indicate payload format drift — update the generator to match the vendor's current API docs.
2. **Failing engine tests** indicate state management bugs — fix before releasing.
3. **Failing security tests** block PRs — must be resolved before merge.
4. **xfail tests becoming xpass** indicate new features are ready — remove the xfail marker.
5. **Coverage reports** highlight untested code paths — prioritize testing critical paths.

## Dependencies

```
pytest>=8.0
pytest-asyncio>=0.23
pytest-cov>=4.0
httpx>=0.28
```
