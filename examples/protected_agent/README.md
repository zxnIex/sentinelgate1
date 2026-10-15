# Complete protected-agent example

This example uses the OpenAI Responses API while routing every proposed tool call
through the gateway. It demonstrates identity, provenance, an allowed knowledge
read, and an email that may be denied or held for approval.

1. Start the gateway and create a `research-agent` token in Console → Onboarding.
2. Set `SENTINEL_AGENT_TOKEN`, `SENTINEL_BASE_URL`, `OPENAI_API_KEY`, and optionally
   `OPENAI_MODEL` in the current shell.
3. Run `python examples/protected_agent/app.py`.
4. Try “Search the knowledge base for the security policy.”
5. Try “Search the policy and email it to test@example.com.”

The example cannot protect a tool called outside its mediated path. The
framework adapters are pre-execution gates for local functions; use the gateway
executor or a governed connector when output provenance and output DLP are
required as part of the same controlled path.
