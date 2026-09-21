"""Public product page and dependency-free operator console shells."""

import json

LANDING_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="SentinelGate is an inline runtime security gateway for autonomous AI-agent tool calls.">
<title>SentinelGate — The security boundary for AI agents</title>
<link rel="stylesheet" href="/assets/landing.css"><script src="/assets/landing.js" defer></script></head>
<body><header class="site-nav"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true"></span><span>SentinelGate</span></a>
<nav aria-label="Main navigation"><a href="#platform">Platform</a><a href="#proof">Evidence</a><a href="/docs">API</a><a class="button ghost" href="/console/login">Sign in</a><a class="button primary" href="/console/onboarding">Start evaluation</a></nav></header>
<main><section class="hero"><div class="hero-copy"><div class="eyebrow"><span class="pulse"></span> Runtime security for autonomous agents</div>
<h1>Every agent action.<br><em>Through the gate.</em></h1>
<p>Put identity, least privilege, field-level data lineage, approvals and containment directly on the path between an AI agent and the tools it can reach.</p>
<div class="hero-actions"><a class="button primary" href="/console/onboarding">Protect a first agent</a><a class="button ghost" href="/docs">Explore the API</a></div>
<p class="honesty">Self-hosted developer preview · Project-authored evidence · No certification claim</p></div>
<div class="gate-demo" aria-label="Animated agent security gate"><div class="demo-top"><span>LIVE ENFORCEMENT PATH</span><span class="mode">ENFORCE</span></div>
<div class="track"><div class="agent-node"><span></span><small>AGENT</small></div><div class="packet"><i></i><span>tool.call</span></div>
<div class="gate"><b></b><b></b><div class="scanner"></div><span>SG</span></div><div class="destination"><span></span><small>TOOLS</small></div></div>
<div class="verdict-card"><div><small>DECISION</small><strong id="demo-verdict">Inspecting</strong></div><div><small>CONTROL</small><strong id="demo-control">Identity</strong></div><div class="signal" id="demo-signal"></div></div>
<div class="demo-log" aria-live="polite"><span id="demo-log">Verifying signed agent identity…</span></div></div></section>
<section class="proof-strip"><div><b>Field-aware</b><span>JSON-pointer lineage</span></div><div><b>Fail-closed</b><span>Unknown paths stop</span></div><div><b>Human-bound</b><span>One-time approvals</span></div><div><b>Measurable</b><span>Reproducible evidence</span></div></section>
<section id="platform" class="section"><div class="section-lead"><div class="eyebrow">THE ENFORCEMENT PLANE</div><h2>Security follows the action,<br>not just the prompt.</h2><p>Prompt filters see text. SentinelGate evaluates the identity, data history, destination, requested permission and live tool definition before code runs.</p></div>
<div class="feature-grid"><article><span>01</span><h3>Agent identity</h3><p>Scoped, expiring workload tokens with inventory, revocation and tenant binding.</p></article><article><span>02</span><h3>Data-flow control</h3><p>Signed field provenance follows structured values across deterministic and LLM transformations.</p></article><article><span>03</span><h3>MCP firewall</h3><p>Baseline tool definitions and block description poisoning or definition drift inline.</p></article><article><span>04</span><h3>Human approval</h3><p>Freeze the exact request, notify a reviewer and permit one execution only.</p></article><article><span>05</span><h3>Bounded response</h3><p>Monitor, restrict, quarantine or revoke a compromised agent without arbitrary remediation.</p></article><article><span>06</span><h3>Operational evidence</h3><p>Tamper-evident decisions, replayable policy changes and honest benchmark boundaries.</p></article></div></section>
<section id="proof" class="boundary"><div><div class="eyebrow">PROOF OVER PROMISES</div><h2>Built to be tested.</h2><p>Every published number carries its command, environment, policy digest and limitations. Missed attacks remain visible instead of being edited out.</p><a class="text-link" href="/console/benchmarks">Inspect benchmark evidence →</a></div>
<div class="boundary-list"><article><i class="ok"></i><div><b>Protects mediated calls</b><p>Identity, policy, taint, approvals, MCP definitions and bounded connectors.</p></div></article><article><i class="warn"></i><div><b>Does not protect bypasses</b><p>Tools called outside SentinelGate remain outside its security boundary.</p></div></article><article><i class="warn"></i><div><b>No borrowed credibility</b><p>Project-authored corpora are regression evidence, not independent validation.</p></div></article></div></section>
<section class="final-cta"><div><span class="eyebrow">DESIGN-PARTNER RELEASE v0.10</span><h2>Put one real agent through the gate.</h2><p>Start locally, replay representative traffic, then move to PostgreSQL and federated identity.</p></div><a class="button primary" href="/console/onboarding">Launch guided setup</a></section></main>
<footer><a class="brand" href="/"><span class="brand-mark"></span>SentinelGate</a><span>Runtime controls for autonomous agents</span><span>v0.10</span></footer></body></html>"""


_CONSOLE_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelGate Control Plane</title><link rel="stylesheet" href="/assets/console.css"><link rel="stylesheet" href="/assets/auth.css">
<script src="/assets/console.js" defer></script></head>
<body data-section="__SECTION__"><div class="app-shell"><aside class="sidebar"><a class="brand" href="/"><span class="brand-mark"></span><span>SentinelGate</span></a>
<nav><div class="nav-label">GET STARTED</div><a data-page="onboarding" href="/console/onboarding"><i>01</i>Onboarding</a>
<div class="nav-label">OPERATE</div><a data-page="overview" href="/console"><i>02</i>Overview</a><a data-page="traces" href="/console/traces"><i>03</i>Data flows</a><a data-page="approvals" href="/console/approvals"><i>04</i>Approvals</a><a data-page="agents" href="/console/agents"><i>05</i>Agents</a><a data-page="incidents" href="/console/incidents"><i>06</i>Incidents</a>
<div class="nav-label">CONFIGURE</div><a data-page="connectors" href="/console/connectors"><i>07</i>Connectors</a><a data-page="mcp-security" href="/console/mcp-security"><i>08</i>MCP security</a><a data-page="policy" href="/console/policy"><i>09</i>Policy lab</a>
<div class="nav-label">VERIFY</div><a data-page="benchmarks" href="/console/benchmarks"><i>10</i>Benchmarks</a><a data-page="system" href="/console/system"><i>11</i>System health</a><a data-page="audit" href="/console/audit"><i>12</i>Audit log</a><a data-page="reports" href="/console/reports"><i>13</i>Reports</a></nav>
<div class="sidebar-foot"><span class="status-dot"></span><span>v0.10 developer preview</span></div></aside>
<main><header class="topbar"><button id="menu-toggle" class="icon-button" aria-label="Toggle navigation">☰</button><div><p class="breadcrumb">CONTROL PLANE / <span id="crumb"></span></p><h1 id="title"></h1></div>
<div class="session"><div class="runtime-state"><span id="mode-dot"></span><div><b id="mode">Disconnected</b><small id="session-name">No active session</small></div></div><button class="button secondary" data-action="open-login">Sign in</button><button class="icon-button" data-action="logout" aria-label="Sign out">↗</button></div></header>
<div class="page"><div id="error" class="alert error" role="alert"></div><div id="view"></div></div></main></div>
<dialog id="login-dialog"><form method="dialog" class="dialog-card"><button class="dialog-close" value="cancel" aria-label="Close">×</button><div class="eyebrow">OPERATOR ACCESS</div><h2>Sign in to the control plane</h2><p>Company deployments use their existing identity provider. Local evaluation can use the development admin token.</p><div id="sso-action"></div><label>Administrator access token<input id="token" type="password" autocomplete="off" placeholder="Raw token — do not add Bearer"></label><div class="dialog-actions"><button value="cancel" class="button secondary">Cancel</button><button id="connect-button" value="default" class="button primary">Connect securely</button></div><p class="micro">Stored in this tab's session storage only. SentinelGate does not create local enterprise user accounts.</p></form></dialog>
<dialog id="detail-dialog"><div class="dialog-card detail-card"><button class="dialog-close" data-action="close-detail">×</button><div class="eyebrow" id="detail-eyebrow">DETAIL</div><h2 id="detail-title">Record</h2><pre id="detail-body"></pre></div></dialog>
<div id="toast" class="toast" role="status"></div></body></html>"""


def console_page(section: str) -> str:
    return _CONSOLE_TEMPLATE.replace("__SECTION__", json.dumps(section)[1:-1])
