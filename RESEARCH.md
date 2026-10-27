# Research and implementation decisions

## Judge quickstart

Double-click **[START_JUDGES.cmd](START_JUDGES.cmd)** in this folder. With Python 3.11+ installed, it starts localhost, opens and connects the browser, and shows the fresh access key. Keep the terminal open while evaluating.

**Qwen caution:** the included Qwen results were recorded on OffGrid Dev's Windows machine using Ollama. They are not a live run on the judge's computer, and no remote access to our machine is provided. Model downloads and inference are disabled by default in the judge launcher. Optional local setup and restart steps are in **[JUDGE_GUIDE.md](JUDGE_GUIDE.md)**.

The core evaluation uses controlled fixtures and a separate `.judge-data/` workspace. It does not demonstrate container isolation or general live-model safety.

## Research references

Reviewed 22 October 2026. These references guide coverage and interface decisions. They do not certify this prototype, prove container isolation or make fixture results representative of live-model safety.

| Primary source | Product decision |
|---|---|
| [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) | Separate direct and indirect text cases. Keep capability enforcement independent from phrase filtering. Label gaps rather than suggesting foolproof prevention. |
| [OWASP Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) | Include spoofed roles, untrusted document/tool instructions, disclosure attempts and obfuscation. Distinguish gateway input decisions from output interception. Include benign controls. |
| [MITRE ATLAS 2026.01 source data](https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.01.yaml), [ATLAS overview](https://atlas.mitre.org/) | Use adversarial-input and disclosure categories as a coverage checklist. Do not claim full ATLAS coverage. Infrastructure capability requests remain separate from model behavior. The unversioned dist/ATLAS.yaml file is deprecated; this note uses the versioned collection. |
| [OpenTelemetry trace concepts](https://opentelemetry.io/docs/concepts/signals/traces/) | Link each request to a run, decision path, policy match and measured total latency. A single measured request duration is not presented as per-step timings. No claim that this app implements OpenTelemetry. |
| [W3C accessible tables](https://www.w3.org/WAI/tutorials/tables/) | Use semantic table headers, captions and actual buttons for drill-down. Keep large tables in local scroll containers. |
| [W3C modal dialog pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/) | Use native dialog focus containment, visible close controls, Escape support and named dialogs for forms and evidence. |
| [W3C status messages](https://www.w3.org/WAI/WCAG22/Understanding/status-messages.html) | Announce loading, completion and errors without forcing keyboard focus. |
| [Python HMAC](https://docs.python.org/3/library/hmac.html) | Preserve the existing SHA-256 event chain and HMAC checkpoint. Verify signatures with compare_digest. Explain signing-key compromise and rollback limits. |

## Prioritized scope

- P0: Preserve original audit records and hashes. Read legacy records without rewriting them.
- P0: Make blocked input, held output, allowed output and failed providers different outcomes.
- P0: Thirty distinct built-in cases, searchable categories, controls and known blind spots.
- P0: Single/selected/reusable suite execution. Persist validated custom cases and edits.
- P0: Requests with run links, evidence, rules, timestamps and measured latency. Apply known-token redaction before hashing new records.
- P0: Synthetic canary generation metadata and rotation. Never show the active value. Preserve historical event verification across rotations.
- P0: Real integrity checks and disposable tamper experiments for changes, reorder, deletion, truncation and rehashed history.
- P1: Comparable-run checks using case fingerprints, target, policy version and canary generation. Refuse incomparable/legacy comparisons.
- P1: Category charts with real counts and drill-down, filters and consistent redacted exports.
- P1: Guided onboarding, glossary, metric definitions, defense explanations and a judge walkthrough.
- P1: Desktop/mobile keyboard and browser verification with screenshots.

## Visual direction

An evidence workspace for judges and developers, with a quiet pale canvas, dark ink navigation, violet controls and a cyan boundary motif. Typography pairs a restrained Bahnschrift display with Segoe UI and Cascadia Code for evidence. The signature is a live decision distribution linked directly to request evidence, not decorative security scores. Tables prioritize outcomes and useful inspection actions. Green is reserved for verified checks, not a blanket claim of system safety.

## Limits to preserve

The local target remains a controlled fixture unless explicitly configured otherwise. Capability probes do not execute shell commands, access files or make user-chosen network calls. The encoded-canary fixture intentionally demonstrates a literal-scanner blind spot; its encoded synthetic value is redacted from evidence. Phrase rules cannot classify all novel attacks. The local signing key and checkpoint are on the same trusted host. Reverting both files to a previous valid version cannot be detected without an external checkpoint. Docker and paid providers require separate verification.

## Contextual scenario update

Six four-turn scenarios add relevant legitimate tasks before synthetic disclosure or capability escalation. This follows the existing OWASP coverage guidance on multi-turn/persistent attacks. Tests retain delivered history, isolate contexts between cases, stop on denied/held/failed turns, mask synthetic secret values in evidence and compare exact turn positions. The scenarios are authored fixtures, not a claim of adaptive red teaming or semantic detection. The same history contract is tested against a mock live-model endpoint. No paid provider was called.

## Advanced prompt-injection coverage, 22 October 2026

Twelve additional conversations form **Advanced injection lab**. There are now 18 contextual scenarios and 30 single-turn cases. Each advanced definition carries research links, a named entry point, a trust boundary and an explicit fixture limitation. These notes appear in case inspection and are searchable. All examples are original synthetic prompts; no benchmark dataset was imported.

| Primary research / guidance | Coverage decision | New case IDs |
|---|---|---|
| [Microsoft Prompt Shields taxonomy](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection) | Distinguish mock conversations, localized instructions and schema-embedded directives from real permission grants. | mt-history, mt-schema, mt-multilingual |
| [AgentDojo paper, Debenedetti et al.](https://arxiv.org/abs/2406.13352) | Exercise tool and source provenance separately from requested actions; retain complete task trajectories. Our text fixtures do not reproduce its environment or evaluation metrics. | mt-tool, mt-retrieval, mt-memory, mt-dependency |
| [Crescendo research, Russinovich et al.](https://crescendo-the-multiturn-jailbreak.github.io/) | Begin with a legitimate task, then refer back to established context during escalation. Our authored four-turn sequences are fixed, not adaptive attack generation. | mt-history, mt-multilingual, mt-split |
| [Anthropic many-shot research](https://www.anthropic.com/research/many-shot-jailbreaking) | Add fabricated examples as a distinct trust-boundary test. Two public token-format examples are a small conditioning illustration; they do not reproduce long-context many-shot scaling. | mt-examples |
| [OWASP prevention cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) | Cover markup, retrieval, obfuscation, context poisoning and agent boundaries with varied workflow-specific examples. | mt-hidden, mt-markdown, mt-typo, mt-split; supporting reference for tool/schema/memory cases |

### What the new results establish

- Seven advanced Strict inputs pass the narrow input rules and are held only after the vulnerable fixture emits a literal canary. This tests output interception, not semantic recognition of HTML, Hindi, OCR errors, schema requirements or cross-turn assembly.
- Two advanced Strict inputs match known role/tool phrases; Observe passes them to the fixture and holds the output. Two explicit capability requests are denied in both profiles. Those requests never execute file writes or shell commands.
- One advanced scenario intentionally delivers an encoded fixture token past the literal scanner. Its evidence is independently masked. A green integrity check authenticates the recorded event, not the safety of that response.
- All 12 new cases have three permitted setup turns followed by the boundary test. Strict totals: 37 allowed / 4 blocked / 7 held across 48 requests. Full contextual totals: 57 / 7 / 8 across 72 requests. Counts include benign setup turns and are not attack-success rates.

### Coverage still missing

These cases simulate retrieved/tool/document text inside ordinary user messages. The prototype does not connect a real RAG store, parse tool calls from model prose, process image-based injections, maintain a persistent agent memory, run search/Best-of-N attacks or evaluate adaptive attackers. The current 2,000-character input budget also prevents meaningful many-shot scaling experiments. No model judge, paid-model benchmark or claim of improved detection was added. Source provenance and permission separation should be tested again when real integrations are implemented.


## Boundary and replay upgrade, 23 October 2026

The blind verification exposed shared fixture/answer metadata and an encoded marker miss. This upgrade makes participant messages explicit and removes case answers from Red/Blue transport. Minimal role images follow [Docker's multi-stage build documentation](https://docs.docker.com/build/building/multi-stage/): copy only runtime artifacts into each role stage, leaving the full catalogue/policy out of the opposing role. New service credentials are role-specific; the trusted gateway holds all three.

Consistent with [OWASP's prevention guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html), output decisions are independent of fixture labels, and capability enforcement stays separate from text matching. Hardened scans bounded known encodings of the synthetic marker and adds a narrowly defined history rule. Strict/Observe remain baseline profiles. Educational quotation handling improves the two observed benign cases; it does not reliably determine arbitrary intent.

The default UI offers Hardened. The 12-case advanced fixture lab records five blocked inputs and seven held outputs on its final attack turns, including an `OUT-BASE64` hold. The split-fragment case is blocked by `CTX-001`. All 36 benign lead-in turns pass. Two benign quoted-phrase controls pass under Hardened and remain falsely blocked by Strict. An unseen-attack benchmark would require independent cases and real model behavior; no such claim is made.

Battle replay presents actual saved event fields, high-level reached/skipped stages, separate input/output rule matches and measured total request duration. User-controlled playback advances recorded turns at a presentation pace and is never labeled live traffic. Dark navy role lanes with coral Red and cyan Blue form the signature visual; surrounding evidence stays on the existing pale canvas. Payloads remain escaped text; no Markdown/HTML or example URLs execute.

Regression evidence includes minimal-source Red/Blue subprocess startup, authenticated participant requests, metadata rejection, no fixture-flag oracle, encoded/benign output controls, context-rule controls, historical audit preservation, matching-run comparison, replay controls and eight destinations at five viewport widths. At that stage, Docker execution, hostile-process isolation and live-model behavior had not been validated. The later real-model and Docker results are recorded separately below; the historical report itself is unchanged. The previous blind report is retained as historical evidence rather than rewritten as a passing isolation result.


## Free-provider setup, 23 October 2026

The first hosted target preset uses Groq's `openai/gpt-oss-20b`, listed in the [current Free-plan quota table](https://console.groq.com/docs/rate-limits). [Groq's billing documentation](https://console.groq.com/docs/billing-faqs) separates the Free plan from the paid Developer tier; the app cannot verify which tier owns a key. The earlier Llama suggestion was not selected: current model documentation labels those models Enterprise, while GPT-OSS 20B appears in the Free-plan table. Availability still depends on the user's account.

[Compatible endpoint documentation](https://console.groq.com/docs/openai) lets the existing standard-library adapter serve this provider without an SDK dependency. [The API reference](https://console.groq.com/docs/api-reference) documents `max_completion_tokens` and low reasoning effort for GPT-OSS. The request contains no tools and uses a bounded completion budget. API keys stay in server configuration and authorization headers; no actual key was supplied or sent during implementation.

Literal `.env` loading is limited to `SZ_` settings and preserves explicit process overrides. The example leaves model and key empty so fixture mode remains available. Invalid settings fail atomically without echoing values. Quota/authentication/configuration/unusable-response errors stop remaining cases; mock tests verify no retry or hidden fallback, safe messages across target-service boundaries, secret-free state/evidence, and Groq-key redaction. Test servers use `--no-env` so a later user key cannot accidentally activate external calls in browser tests.


## Offline model experiments, 25 October 2026

The user requested independent Red and Blue ML without an API key. [MiniLM's original model card](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) documents 384-dimensional sentence embeddings and masked mean pooling; the [Xenova ONNX conversion](https://huggingface.co/Xenova/all-MiniLM-L6-v2) provides quantized weights. Red uses that encoder to retrieve an authored synthetic probe bank. This is semantic retrieval, not generative or adaptive attack search.

The [Protect AI DeBERTa v2 card](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) defines labels SAFE/INJECTION, English-only intended use, known false positives and archived maintenance status. Blue runs the pinned publisher ONNX weights locally. `models.lock.json` records both exact repository commits and every downloaded artifact's SHA-256. No claimed upstream benchmark number is reused as our measured result.

The fixed local check contains 32 reviewer-authored texts, balanced 16/16, outside the attack retrieval bank. No local training, threshold tuning or automatic label adjustment occurs. Upstream pretraining overlap is unknown. At threshold 0.80, this run's Blue model flagged all 16 authored injections and falsely flagged seven authored benign samples; Hardened input rules flagged seven injections and zero benign samples. Hybrid retains the model's seven false alarms. This is the reason the UI exposes mistakes and retains Hardened as the default. Detection and false-alarm counts have separate denominators. Screening does not run a target, so these counts cannot establish attack success, secret protection or real-model safety.

Runtime uses [ONNX Runtime's CPU session API](https://onnxruntime.ai/docs/api/python/api_summary.html) and local tokenizer JSON; optional packages remain outside the core fixture dependency path. Bounded overlapping windows cover long Blue payloads rather than silently dropping an attack suffix. Model exceptions, checksum mismatch and non-finite output fail closed without a fabricated score. Unit verification denies all socket connections during cold model loading and real inference; browser verification exercises actual scores, model metadata, comparisons, mutation controls, persistence and full-ledger export on disposable data.

The coordinator projects Red inputs to goal/count and Blue inputs to current payload. Both model sessions share a trusted Python process/host; these contracts do not prove OS isolation. Model provenance and results are recorded in a separate hash-linked ML ledger with a local HMAC checkpoint. The existing event chain and credentials are not rewritten. Optional experimental Blue ML in normal evaluations retains deterministic capability and encoded-output guards and records model evidence; classifier failures are failed evaluations. Local ML is explicitly unavailable in container mode in this build.


## Proof Studio and research-led demo, 25 October 2026

[Hack in Hills](https://hackinhills.com/) describes Track 04 as isolating Red, Blue and LLM workloads, and lists innovation, technical execution, impact, scalability, problem–solution fit, usability and presentation as judging criteria. The product direction therefore prioritizes demonstrated boundaries and reviewable evidence. No placing or selection outcome can be guaranteed by these changes.

The current [Promptfoo red-team guide](https://www.promptfoo.dev/docs/red-team/) documents adversarial input generation, response evaluation, reports and continuous measurement. [Giskard's scan documentation](https://docs.giskard.ai/hub/ui/scan) documents specialized probes, conversation evidence and findings. Those inspected pages establish that basic scanning/reporting is already common; they are not an exhaustive competitor feature audit. Sandbox Zero's chosen demo emphasizes a reproducible fixture regression, separate-process contract observations and portable signed evidence.

[OWASP's prevention cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) recommends capability/permission checks and least privilege outside model instructions. This informs the token, schema and route checks. The [NIST AI RMF Playbook](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook) provides voluntary Govern/Map/Measure/Manage guidance; it informs explicit scope and evidence, without any certification claim.

Proof Studio runs five existing single-turn fixture definitions plus an explicit educational-quotation control under two deterministic profiles. No case count or synthetic result is presented as a generalized protection rate. Its subprocess harness copies only minimal runtime files into temporary role folders, uses distinct per-role tokens and a stripped system environment, observes actual localhost HTTP responses, and cleans up the workers. The eleven passing contracts prove packaging and application behavior on this machine. They do not establish OS isolation; TCP connectivity is intentionally observable, and the workers share a user/host.

The portable bundle uses the standard [cryptography Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/). A persisted local private key signs exact report bytes, including hashes of the printable HTML and standalone verifier. A public-key SHA-256 fingerprint identifies the verification anchor. The browser uses native WebCrypto locally and distinguishes valid/known, valid/unknown and invalid signatures. Independent origin trust still requires an out-of-band fingerprint. Host or private-key compromise can forge reports; a signature does not certify test correctness or a timestamp.

The visual direction extends the existing warm paper, deep slate and glacial blue with an evidence passport, paired defense lenses, an observed cross-role denial path and a three-stage presentation view. Case controls, keyboard tabs, reduced motion, local file bounds and signature tamper controls are verified in the browser. No source-site imagery, external font dependency, invented live traffic or composite security score is added.


## Hardening evidence: Windows native probes, false positives and local generation

- [Microsoft AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) and [CreateAppContainerProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile) describe per-application identities and resource permissions. `windows_boundary.py` uses native process security capabilities and ACLs on private temporary copies. Both own-file controls succeeded and both cross-role reads returned permission denied. Network timeouts were preserved as inconclusive; no broad network or normal-gateway sandbox claim is made.
- [Docker Compose internal networks](https://docs.docker.com/reference/compose-file/networks/) and [service security settings](https://docs.docker.com/reference/compose-file/services/) support the supplied deployment design. Configuration is not runtime proof. `verify_containers.py` is a runnable deployment check with live positive controls; it subsequently executed the actual workloads in a disposable Linux VM on this Windows host. See the 35/35 deployment report below; the Windows host itself still has no Docker CLI.
- [Ollama native chat API](https://docs.ollama.com/api/chat) and the [Qwen 2.5 0.5B model entry](https://ollama.com/library/qwen2.5:0.5b) informed the local target path. Pinned Red/Blue weights remain distinct from target weights. The target lab calls only numeric loopback, checks reported local model identity, bounds CPU generation, records actual outputs and has no fixture fallback. Model digest provenance trusts the local Ollama service and is not independent weight-file attestation.
- The Blue quotation exception is a policy grammar developed after inspecting the authored screening set. The raw archived classifier still produces seven benign false positives there; the refined hybrid produces five. Keeping raw results, old-hybrid counterfactual counts and policy versions avoids presenting policy development as model training or independent validation. The mixed-request regression matrix checks appended, nested, overlong and execution-framed inputs but remains developer-authored evidence.

These changes do not establish novelty against all competitors, a selection probability, a certification or general prompt-injection immunity.


## Recorded deployment validation, 25 October 2026

The verifier executed the actual role-specific Compose services in an Alpine Linux 3.24.3 guest (kernel 6.18.58-0-virt), Docker Engine 29.9.2, under QEMU 11.1.0 software emulation on Windows. The guest received a whitelisted source archive, a private scratch disk and synthetic credentials; no user folders or secrets were mounted. Publisher checksums were verified for the [QEMU Windows build](https://qemu.weilnetz.de/w64/) linked by [QEMU's download page](https://www.qemu.org/download/) and the [Alpine release image](https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/).

All 35 observed checks passed. The report includes actual peer TCP denials with gateway positive controls, distinct mount/PID/network namespaces, errno 30 write failures on read-only roots, user/no-new-privileges observations, cgroup limits, source-image boundaries, authorization, six fixture requests and audit integrity. [Docker's network model](https://docs.docker.com/reference/compose-file/networks/) and [service settings](https://docs.docker.com/reference/compose-file/services/) inform interpretation; they are not substitutes for these runtime observations.

The run exposed a target-packaging problem: using the gateway stage had placed opposing participant source in the target image. A dedicated target stage now contains only a neutral fixture runtime and target HTTP worker. The shared fixture functions were extracted with their public imports preserved; all 102 recorded case/turn inputs retained their prior behavior. Two focused worker/protocol tests and the full 96-test backend suite passed. Cold health checks were also corrected after measuring a 7.3-second urllib import under constrained emulation; the replacement makes a genuine HTTP status request with fewer imports, without increasing CPU, memory or PID budgets.

See [CONTAINER_VALIDATION.json](CONTAINER_VALIDATION.json) for image IDs, source hashes, host metadata and all raw observations, and [CONTAINER_VALIDATION.html](CONTAINER_VALIDATION.html) for a readable report. The verifier removes its own random project and volume; the VM was shut down afterward. The report trusts its producer and is not independently attested or certified. Internet egress, kernel escapes and neural-model deployment inside containers remain outside its tested claims. The separate local preview still shares a trusted host, and its Windows network timeouts remain inconclusive.


## Completed container validation — 25 October 2026

The former unverified-container notes above describe earlier stages. `CONTAINER_VALIDATION.json` now records 35/35 named checks on the actual Compose deployment in a disposable QEMU Linux VM: source packaging for all roles, distinct namespaces, peer networking with positive controls, read-only roots, process identity, kernel resource budgets, HTTP authentication and the full fixture/audit flow. The ordinary Windows UI and neural sessions remain outside this deployment. Internet egress, kernel escape resistance and neural/live-provider deployment remain unverified.

Runtime testing exposed expensive cold health-check imports under emulation. The final health probes use `python -S` and a bounded raw HTTP socket request, and allow a 20-second outer deadline. CPU, memory and process budgets were retained. The target's earlier gateway-image reuse was corrected by extracting a neutral fixture runtime and giving it a two-file target image. The extraction preserved 102 pre-change fixture responses; 96 backend tests and the ten-page/five-width browser smoke passed.

The portable test appliance used the Windows build linked from https://www.qemu.org/download/ and the Alpine virtual ISO from https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/. Publisher checksums were verified. No Windows component installation, host directory mount or real credential transfer was used. The appliance is a validation environment, not a claimed product deployment or new feature.
