# Independent adoption test

Run this with at least three developers who did not build the product. Do not guide them after the
clock starts; observe silently and record only with consent.

## Task

“Protect one tool in this sample agent. Demonstrate an allowed call, a denied call, and show the
reason in the control plane.”

## Measures

| Measure | Target for the design-partner release |
| --- | --- |
| Installation completion | 3/3 developers |
| Median time to first protected call | 15 minutes or less |
| Secret accidentally committed | 0 |
| Direct fallback left active | 0 |
| Assistance required | Record every intervention; target 0 |
| `doctor` failure understood without help | 90% or better |

Track the phase where an evaluator stops: download, Python, installation, configuration,
authentication, agent token, policy, adapter, first call, or evidence inspection. The optional CLI
telemetry records only these product events when the evaluator explicitly passes `--telemetry`;
otherwise collect the timings manually.

Do not send prompts, tool arguments, tokens, file paths, email addresses, repository names, or
other customer content to onboarding analytics.

