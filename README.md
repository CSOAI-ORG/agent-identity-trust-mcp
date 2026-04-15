# Agent Identity Trust

> By [MEOK AI Labs](https://meok.ai) — MEOK AI Labs — Agent Identity. DIDs, verifiable credentials, reputation scoring. Agent passports for the MCP ecosystem.

Agent Identity & Trust MCP — MEOK AI Labs. DIDs, verifiable credentials, trust chains for AI agents.

## Installation

```bash
pip install agent-identity-trust-mcp
```

## Usage

```bash
# Run standalone
python server.py

# Or via MCP
mcp install agent-identity-trust-mcp
```

## Tools

### `register_agent_identity`
Register an agent with a decentralized identifier (DID) and capability attestation.

**Parameters:**
- `agent_name` (str)
- `capabilities` (str)
- `organization` (str)

### `issue_credential`
Issue a verifiable credential to an agent (compliance cert, capability proof, etc.).

**Parameters:**
- `agent_did` (str)
- `credential_type` (str)
- `claims` (str)

### `verify_credential`
Verify a credential is valid and not expired.

**Parameters:**
- `credential_id` (str)

### `get_agent_reputation`
Get an agent's reputation score and history.

**Parameters:**
- `agent_did` (str)

### `list_registered_agents`
List all registered agents, optionally filtered by organization.

**Parameters:**
- `organization` (str)


## Authentication

Free tier: 15 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## Links

- **Website**: [meok.ai](https://meok.ai)
- **GitHub**: [CSOAI-ORG/agent-identity-trust-mcp](https://github.com/CSOAI-ORG/agent-identity-trust-mcp)
- **PyPI**: [pypi.org/project/agent-identity-trust-mcp](https://pypi.org/project/agent-identity-trust-mcp/)

## License

MIT — MEOK AI Labs
