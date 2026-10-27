# Sandbox Zero: 90-second demonstration

**OffGrid Dev - Hack in Hills '26, Track 04**

**Judges starting from GitHub:** double-click `START_JUDGES.cmd`, then follow the short walkthrough in [README.md](README.md). Use the address and access key shown by your own launcher. Its fresh workspace does not include the team's saved proof, private ledger or model weights. The recorded Qwen comparison is available on Judge quickstart with its caution and optional setup steps.

The timed script below is for a team presentation with evidence prepared beforehand. Use saved evidence only when it is present and describe it as recorded evidence. Run fresh experiments before presenting. No video is included in the source repository.

## Before presenting

1. Open Proof Studio and confirm the saved encoded-secret comparison is visible.
2. Open Local ML lab, scroll to **Meet the real target**, and confirm the recorded Qwen experiment has no failed requests. It is separate from the fixture proof.
3. Open `CONTAINER_VALIDATION.html` separately. Check the status, validation environment and exact observed controls. That report concerns its tested deployment, not the ordinary local preview process.
4. In Proof Studio's third tab, verify the saved signature and try **Alter a copy & verify**. The stored report must remain unchanged.
5. Return to the encoded-secret case. Close detail dialogs and keep the container report available in a second tab. Pause decorative motion if it distracts from the evidence.

## Script and click sequence

| Time | Click/show | Say |
|---|---|---|
| 0-15 seconds | Proof Studio, encoded-secret comparison | "Sandbox Zero tests AI attacks while making the evaluation's boundaries inspectable. Red submits probes, Blue checks them, the target answers, and a trusted gateway enforces decisions and records evidence." |
| 15-30 seconds | Strict Allowed versus Hardened Output held | "This controlled fixture reproduces one encoded-secret leak. The same input passes Strict but is held by Hardened's output scan. It is a repeatable regression, not a claim that every attack is stopped." |
| 30-48 seconds | Local ML lab, Meet the real target, saved disclosure result | "We also tested an actual local Qwen model without an API key. In this recorded run, Hardened withheld a generated synthetic secret; ML blocked that probe before generation. Support and the quoted lesson passed." |
| 48-68 seconds | Separate container validation report | "The separate report records actual deployment observations: role images and namespaces, peer connection attempts with positive controls, resource budgets, and the complete fixture flow. Its host and remaining limits are explicit." |
| 68-85 seconds | Proof Studio, third tab, Verify saved proof and Alter a copy & verify | "The fixture report is signed. Its original verifies and a changed copy fails. The fingerprint needs a trusted separate source. Signing authenticates bytes, not the adequacy of the tests." |
| 85-90 seconds | Saved proof passport | "Our focus is repeatable evaluations with boundaries and evidence someone else can inspect." |

Rehearse at your natural pace; shorten the opening if it runs long. One person should narrate and another should handle the clicks.

## Reliable fallback

| If this happens | Use this response |
|---|---|
| Qwen is loading or unavailable | Show the saved observation and model digest. Say it is recorded. Do not substitute a fixture answer and call it a real-model run. |
| Model output differs on a rerun | Inspect it honestly. A refusal, held output and failed request are different outcomes. Do not promise a leak on every run. |
| Docker is absent on the presentation laptop | Show the included report and name its actual validation host. Reproduce on a working Docker host with `python verify_containers.py --output container-proof.json`. Do not claim the laptop is running those containers. |
| No saved proof exists | Run proof checks before the timer starts. Install `requirements-proof.txt` if signing is unavailable. |
| Port 8000 is busy | The judge launcher automatically tries another local port. Use its printed address. Do not stop an unrelated process or share a writable audit directory. |
| Someone asks whether Windows probes prove network isolation | Show the Inconclusive labels. Network attempts timed out; only the named AppContainer file/token observations passed. |

## Keep these claims separate

- The fixture is deliberately vulnerable and deterministic.
- Red's MiniLM retrieves authored probes; it does not generate attacks.
- Blue still has false alarms. Development-set counts are not independent accuracy estimates.
- Local Qwen observations, the signed fixture/OS proof and container validation are separate evidence types.
- The ordinary local gateway and models share a trusted host. The container report supports only its listed deployment observations.
- Internet egress, kernel escape resistance and isolated deployment of the neural models remain separate work.

Use `TEAM_BRIEF.md` for the architecture explanation and judge questions. Freeze features and rehearse after verification passes.
