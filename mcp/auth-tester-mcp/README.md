# Auth Tester MCP Server

Authentication testing MCP server. Exposes tools for JWT, OAuth, MFA, CSRF, and session testing.

## Tools (5)

| Tool | Description |
|------|-------------|
| `auth_test_jwt` | Test JWT: alg:none, weak secrets, RS256->HS256, kid injection |
| `auth_test_oauth` | Test OAuth: redirect_uri manipulation, state bypass |
| `auth_test_mfa` | Test MFA/2FA bypass, brute force, session fixation |
| `auth_test_csrf` | Test CSRF protection on sensitive actions |
| `auth_test_session` | Test session handling |

## Setup

```json
{
  "mcpServers": {
    "auth-tester": {
      "command": "python3",
      "args": ["mcp/auth-tester-mcp/server.py"]
    }
  }
}
```

## Requirements

- Python 3.8+
- `requests`
- Project tools: `tools/python/auth_tester.py`
