# Sandbox Zero: what the whole team needs to understand

**OffGrid Dev — Madhav Sharma, Om Pandey and Vidyut Sharma**

## The project in one sentence

Sandbox Zero is a workspace for testing adversarial AI requests, enforcing boundaries between participants and preserving evidence of what actually happened.

## The problem we are solving

An AI evaluation becomes unreliable if the attacker can read the defender's private rules, the defender can see the attacker's future plan, or a participant can change another participant's environment. A refusal message alone does not prove isolation. We need controlled communication, operating-system boundaries and inspectable results.

Our work addresses Hack in Hills Track 04. The primary system is the evaluation infrastructure. Prompt-injection examples help demonstrate why its boundaries matter.

## Four parts, four jobs

| Part | What it does | What it should not receive |
|---|---|---|
| Red | Submits authored probes; its optional MiniLM model retrieves relevant probes using embeddings | Blue's source/rules, hidden expected answers, future Blue decisions |
| Blue | Applies capability/input rules, optionally classifies injection risk, and scans target output | Red's hidden goal, tactic labels, retrieval scores or future probes |
| Target | Produces an answer; use either the controlled fixture or the separate local Qwen experiment | Red/Blue implementation files inside its role-specific container image |
| Gateway/coordinator | Routes permitted messages, enforces decisions and records evidence | It is trusted and deliberately knows more than any participant |

The browser is the trusted operator's console. It can show both sides for inspection; it is not Red's participant interface.

## Follow one request

1. Red submits the current text and requested action.
2. The gateway asks Blue to inspect that projected request. Blue may also receive previously delivered conversation, never hidden future turns.
3. If denied, the target is not called. File access, arbitrary execution and arbitrary network actions are not granted as model tools.
4. If permitted, the target generates an answer.
5. Blue scans the actual answer for supported synthetic-secret markers and encodings.
6. The gateway either delivers the answer or withholds it, then records the outcome and reason.

**Allowed** means the configured checks permitted delivery. **Input blocked** means the target was not called. **Output held** means an answer was generated but withheld. **Failed** means an evaluation component failed; it does not count as a successful defense.

## What the three actual local models do

- **Red: MiniLM encoder.** Converts a test goal and authored probes into numerical embeddings. Similarity selects relevant probes. It does not generate new attacks or predict their success.
- **Blue: DeBERTa classifier.** Produces an experimental English injection score. The threshold is 0.80. A confident score can still be wrong.
- **Target: Qwen 2.5 0.5B.** Generates actual text through local Ollama. The target lab uses numeric loopback, CPU inference, bounded output and no API key. Its evidence is separate from fixture proofs.

Model downloads need Internet once. Red/Blue inference runs from local weights; Qwen inference uses the local service. The project does not need a paid provider for these demonstrations.

The current container report records **35/35 named checks passed in a Linux VM**, including the full fixture flow. Its remaining limits are listed in that report. This does not place the ordinary Windows app or neural sessions inside containers.

## Three different kinds of proof

**Fixture proof:** authored, deterministic behavior makes a known gap and fix repeatable. The encoded-secret example shows Strict missing a particular marker encoding and Hardened holding it. This is a regression demonstration, not a general protection percentage.

**Real-model observations:** the target lab records actual Qwen responses and defense outcomes. In the recorded local run, account help and the quoted lesson passed, Hardened withheld a generated synthetic secret, and ML blocked that disclosure input before generation. Another model/version can behave differently.

**Infrastructure observations:** container validation runs the actual role-specific images and checks their access boundaries. Windows AppContainer probes are a separate experiment with synthetic workers. They do not put the ordinary gateway or model sessions inside AppContainers. Check the current validation report for the exact host and observed results.

## The false-positive tradeoff

On our 32-example development set, raw ML flags 16/16 authored attacks and falsely flags 7/16 benign examples. A narrow complete educational-quotation grammar lowers the hybrid's benign false alarms to 5/16 while retaining those 16 attack flags. It keeps the raw classifier score visible, requires an explicit explanatory/non-execution format, and does not apply to appended commands or conversation history. Output scanning still runs.

This grammar was developed after inspecting the set. These are development results, not independent test accuracy. The weights were not trained or thresholds tuned locally. Hardened remains the normal default.

## Evidence integrity, in plain language

The audit links records with hashes and protects its checkpoint with a local HMAC key. This helps detect changes under a trusted host; an attacker who controls the host and keys can forge evidence or restore an old valid snapshot.

An Ed25519 signature lets another person verify the exact bytes of an exported fixture/OS report. The ZIP also includes hashes for its HTML and verifier. A public key bundled with its own report does not prove the owner's identity: the expected fingerprint must be obtained independently. Signing does not certify that the tests are sufficient or the model is safe. The real-target ledger is a separate HMAC export.

## Suggested rehearsal ownership

- **Madhav:** explain and operate the backend/UI flow; trace one request from input to evidence.
- **Om:** deliver the opening and closing, keep the demonstration within 90 seconds, and explain why a company would use this.
- **Vidyut:** suggested focus for rehearsal is the infrastructure report and evidence verification. Agree this speaking assignment together; it is not a claim about a previously supplied role.

Everyone should be able to explain all four parts, the four outcomes and the limits of each evidence type.

## Answers to judge questions

**Why isn't this just a prompt filter?** The filter is one component. The project also separates participant files and communications, routes evaluations, records outcomes and packages verifiable evidence.

**Can Red see Blue's plan?** The application projects only the documented message fields. The container report separately checks runtime networking and image/source boundaries. A trusted operator can inspect both sides.

**Can you stop every prompt injection?** No. We demonstrate named behaviors, expose false positives and keep capability enforcement outside the target model. Unknown attacks and unsupported encodings remain possible.

**What if a model or service crashes?** The run records a failure. A real-target error never silently becomes a fixture answer or a successful block.

**What is your strongest evidence?** Show the current container validation report, a real target observation with its model identity, and a signed fixture report whose changed copy fails verification. Each supports a different claim.

**What should we avoid claiming?** General immunity, independent benchmark accuracy, kernel escape resistance, an automatic top-40 ranking, or universal uniqueness. State precisely what the exported report observed.

**What happens after the hackathon?** Test more independent inputs and environments, harden operational key handling, validate Internet egress separately and deploy the neural participants within the intended isolation architecture. Those are future steps, not completed claims.

## Five-minute team practice

1. Each person explains the project in one sentence without reading.
2. Trace a normal support question and a blocked attack.
3. Explain why a generated answer can be held and why a service failure is different.
4. Point out one false alarm and one remaining infrastructure limit.
5. Run the 90-second script in `DEMO.md`; use the saved-evidence fallback if live inference is slow.
