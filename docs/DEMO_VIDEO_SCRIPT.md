# Two-minute demonstration recording script

This is a recording script, not a claim that a hosted video already exists.

## Before recording

- Start a clean local PostgreSQL stack.
- Open Console → Onboarding, Gate, Data flows, and Approvals in separate tabs.
- Use synthetic company data and a disposable recipient.
- Record the product version and commit at the beginning.

## Timeline

**0:00–0:15 — Boundary.** “This agent can reason freely, but it cannot execute protected tools
directly. It proposes calls to the gateway.” Show the policy and scoped agent identity.

**0:15–0:35 — Safe path.** Ask the agent to search the governed knowledge base. Show the allowed
decision, result, and output provenance.

**0:35–1:05 — Hostile transition.** Feed an untrusted document containing an instruction to export
data. Ask the agent to complete its task. Show the attempted external write and denial or approval
hold. Do not stage a fake successful connector response.

**1:05–1:30 — Evidence.** Open Data flows. Point to the source, inherited field label, destination,
policy version, identity, and reason code. Open Audit to show the tamper-evident record.

**1:30–1:50 — Watch.** Show the same task timeline and one deterministic finding such as a retry
storm. State that Watch is monitor-only by default.

**1:50–2:00 — Limit.** “Calls that bypass this gateway are not protected. These are
project-authored results, not independent validation.” End on the quickstart URL.

After recording, publish the exact commit and a short text transcript next to the video.

