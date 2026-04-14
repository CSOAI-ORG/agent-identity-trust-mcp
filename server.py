#!/usr/bin/env python3
"""Agent Identity & Trust MCP — MEOK AI Labs. DIDs, verifiable credentials, trust chains for AI agents."""
import json, os, hashlib, secrets
from datetime import datetime, timezone, timedelta
from typing import Optional
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

FREE_DAILY_LIMIT = 15
_usage = defaultdict(list)
def _rl(c="anon"):
    now = datetime.now(timezone.utc)
    _usage[c] = [t for t in _usage[c] if (now-t).total_seconds() < 86400]
    if len(_usage[c]) >= FREE_DAILY_LIMIT: return json.dumps({"error": f"Limit {FREE_DAILY_LIMIT}/day"})
    _usage[c].append(now); return None

mcp = FastMCP("agent-identity-trust", instructions="MEOK AI Labs — Agent Identity. DIDs, verifiable credentials, reputation scoring. Agent passports for the MCP ecosystem.")

_identities = {}
_credentials = {}

@mcp.tool()
def register_agent_identity(agent_name: str, capabilities: str, organization: str = "") -> str:
    """Register an agent with a decentralized identifier (DID) and capability attestation."""
    if err := _rl(): return err
    did = f"did:meok:{hashlib.sha256(f'{agent_name}{secrets.token_hex(8)}'.encode()).hexdigest()[:24]}"
    identity = {"did": did, "name": agent_name, "organization": organization,
                "capabilities": [c.strip() for c in capabilities.split(",")],
                "registered": datetime.now(timezone.utc).isoformat(),
                "trust_level": 0.5, "interactions": 0, "status": "active"}
    _identities[did] = identity
    return json.dumps(identity, indent=2)

@mcp.tool()
def issue_credential(agent_did: str, credential_type: str, claims: str) -> str:
    """Issue a verifiable credential to an agent (compliance cert, capability proof, etc.)."""
    if err := _rl(): return err
    if agent_did not in _identities:
        return json.dumps({"error": "Agent DID not found. Register first."})
    cred_id = f"vc:{hashlib.sha256(f'{agent_did}{credential_type}{datetime.now(timezone.utc).isoformat()}'.encode()).hexdigest()[:16]}"
    ts = datetime.now(timezone.utc)
    credential = {"id": cred_id, "type": credential_type, "subject": agent_did,
                  "issuer": "did:meok:governance-authority", "issued": ts.isoformat(),
                  "expires": (ts + timedelta(days=365)).isoformat(),
                  "claims": {c.split(":")[0].strip(): c.split(":")[-1].strip() for c in claims.split(",") if ":" in c},
                  "proof": {"type": "MEOK-SHA256", "hash": hashlib.sha256(f"{cred_id}{agent_did}".encode()).hexdigest()}}
    _credentials[cred_id] = credential
    return json.dumps(credential, indent=2)

@mcp.tool()
def verify_credential(credential_id: str) -> str:
    """Verify a credential is valid and not expired."""
    if err := _rl(): return err
    cred = _credentials.get(credential_id)
    if not cred: return json.dumps({"valid": False, "error": "Credential not found"})
    expired = datetime.fromisoformat(cred["expires"]) < datetime.now(timezone.utc)
    return json.dumps({"valid": not expired, "credential": cred, "expired": expired}, indent=2)

@mcp.tool()
def get_agent_reputation(agent_did: str) -> str:
    """Get an agent's reputation score and history."""
    if err := _rl(): return err
    identity = _identities.get(agent_did)
    if not identity: return json.dumps({"error": "Agent not found"})
    creds = [c for c in _credentials.values() if c["subject"] == agent_did]
    return json.dumps({"agent": identity, "credentials": len(creds), "trust_level": identity["trust_level"],
        "credential_types": list(set(c["type"] for c in creds))}, indent=2)

@mcp.tool()
def list_registered_agents(organization: str = "") -> str:
    """List all registered agents, optionally filtered by organization."""
    agents = list(_identities.values())
    if organization: agents = [a for a in agents if organization.lower() in a.get("organization", "").lower()]
    return json.dumps({"agents": agents, "total": len(agents)}, indent=2)

if __name__ == "__main__":
    mcp.run()
