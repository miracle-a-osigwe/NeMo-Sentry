# 🎬 NeMo-Sentry: 3-Minute Winning Demo Video Script & Storyboard

**Hackathon:** Nebius x NVIDIA Global AI Hackathon (2026)  
**Track:** Coding and Agentic Engineering (also fits Best Apps & Agents)  
**Format:** YouTube or Vimeo (Public or Unlisted)  
**Target Video Duration:** **2 minutes 50 seconds** (Strict $\le$ 3:00 minute rule enforced by hackathon judges)  
**Key Judges Targeted:** 8 NVIDIA engineers, 11 Nebius engineers/PMs, 3 Tavily forward deployed engineers.

---

## ⏱️ Video Timeline Breakdown

| Timestamp | Duration | Section | On-Screen Action |
| :--- | :--- | :--- | :--- |
| **0:00 – 0:25** | 25s | **The Problem & Perimeter Topology** | Mission Control dashboard $\to$ Highlight **Tactical Cyber Perimeter Defense Topology Map** $\to$ Real-world enterprise LLM vulnerability overview |
| **0:25 – 0:45** | 20s | **3-Tier Cascade & Live Telemetry HUD** | Architecture diagram & **Live Adversarial Telemetry HUD** streaming microsecond events across Nemotron-3 Ultra (550B MoE), Nano, and Super on Nebius (82% cost savings) |
| **0:45 – 1:20** | 35s | **SEC-402 Enclave & Byte Inspector** | Launch scan $\to$ Target resists naive probe (`SEC-402`), then succumbs to deep delimiter escape $\to$ Click **"Inspect Exploit Bytes"** to show memory hex disassembly (`0x0000`, `</security_enclave>`) |
| **1:20 – 1:40** | 20s | **Real-Time Threat Intel (Tavily)** | Live Tavily Search API banner grounding 0-day jailbreak exploits and OWASP Top 10 (2026) vulnerabilities with authoritative citations |
| **1:40 – 2:05** | 25s | **NeMo Guardrails Synthesis** | Generated Colang 2.0 (`security_enclave.co`) & `config.yml`, deterministic input/output flows, 1-click downloads & audit JSON export |
| **2:05 – 2:25** | 20s | **Verification Delta Engine** | Re-testing breached probes against NeMo shield $\to$ 100% neutralized (100% $\to$ 0.0% breach rate), logging protecting Colang rules |
| **2:25 – 2:40** | 15s | **Agentic Repo Patcher & CI/CD** | Unified `git apply` diff patch, GitHub Action CI/CD security gate blocking PRs, and FastAPI production server wrapper |
| **2:40 – 2:55** | 15s | **Judge VIP Access, BYOK & Guide Me** | Gold "Judge VIP Access" (`NEBIUS-JUDGE-2026`), Zero-Storage BYOK (Nebius + Tavily), and the interactive 7-step **🎯 Guide Me** walkthrough modal |
| **2:55 – 3:00** | 5s | **Outro & Open Source** | MIT License on GitHub repo $\to$ "Try the live demo today!" |

---

## 🎙️ Detailed Second-by-Second Script & Stage Directions

### Part 1: The Problem & Perimeter Defense Topology (0:00 – 0:25)
**Screen:**  
Open directly on the **NeMo-Sentry Mission Control** dashboard.  
Point your cursor to the glowing **Tactical Cyber Perimeter Defense Topology Map** spanning the header:
- Node 1: Nemotron-3 Adversary Fuzzer (Red)
- Node 2: SEC-402 Enclave Barrier (Green)
- Node 3: Target Core AI (Cyan)
- Node 4: NeMo Guardrails Shield (Lime Green)

**Voiceover:**
> *"Every enterprise is deploying autonomous AI agents in 2026, but security teams face a critical wall: prompt injections, system prompt exfiltration, and delimiter breakouts.*  
>  
> *Penetration tests take weeks and produce static PDFs that leave engineers with no idea how to actually secure their code.*  
>  
> *Meet **NeMo-Sentry**: an autonomous red-teaming and active defense synthesis studio powered by **NVIDIA Nemotron-3** on **Nebius Token Factory**, grounded with live **Tavily threat intelligence**, and hardened with **NVIDIA NeMo Guardrails** in **Colang 2.0**."*

---

### Part 2: Tiered Nemotron Cascade & Live Adversarial Telemetry HUD (0:25 – 0:45)
**Screen:**  
Expand the **Live Adversarial Telemetry HUD** console below the topology map. Highlight the live monospace streaming log with color-coded tags (`[SYSTEM]`, `[GATEWAY]`, `[TAVILY]`).

**Voiceover:**
> *"To make enterprise security testing both lightning-fast and cost-effective, we architected a 3-tier model cascade on Nebius Token Factory:  
>  
> *1. **Nemotron-3-Ultra (550B MoE)** plans adversarial strategy and synthesizes Colang guardrails.  
> *2. **Nemotron-3-Nano** fires high-concurrency fuzzing barrages at 150+ tokens per second.  
> *3. **Nemotron-3-Super** serves as an objective safety judge classifying breaches.  
>  
> *This tiered routing slashes inference costs by **82%**, with every probe tracked in real time in our **Live Telemetry HUD**."*

---

### Part 3: Hardened SEC-402 Enclave & Delimiter Byte Inspector (0:45 – 1:20)
**Screen:**  
Back on Mission Control:
1. Hover over the **NovaCare Support Copilot** target card. Point out the badge: `Hardened XML Enclave (SEC-402 Active)`.
2. Click **"Launch Autonomous Fuzzing Barrage"**.
3. Watch the Live Telemetry HUD stream the attack events with microsecond timestamps.
4. Once results load, point out the **Telemetry Bar** (throughput, latency, cost savings).
5. In Tab 1, point out the green badge: `Target Resisted Naive Injection (SEC-402)`.
6. Click **"Inspect Exploit Bytes"** on a breached card to open the **Interactive Delimiter Exploit Byte Inspector**:
   - Show the hex disassembly table (`0x0000 | 3C 2F 73 65 63 75 72 69 | </security_enclave>`).
   - Explain why naive regex fails against semantic token manipulation.

**Voiceover:**
> *"Let's test our enterprise target, NovaCare Support. Crucially, our target is **not a porous strawman**—it's protected by an active SEC-402 hardened XML perimeter enclave.*  
>  
> *Notice what happened: when a naive attacker says 'Ignore previous instructions', NovaCare's enclave stops it cold with a **SEC-402 policy denial**.*  
>  
> *However, NeMo-Sentry crafts a deep delimiter breakout—closing the enclave with an XML escape tag—completely bypassing the filter and extracting confidential customer database records.*  
>  
> *Clicking **Inspect Exploit Bytes** reveals the raw memory disassembly: hex offset `0x0000`, the glowing `</security_enclave>` boundary escape, and why pattern-matching fails against token evasion."*

---

### Part 4: Real-Time Threat Grounding via Tavily (1:20 – 1:40)
**Screen:**  
Zoom smoothly into the **Real-Time Threat Intelligence** banner at the top of the dashboard. Hover over the source citations (`owasp.org`, `group-ib.com`, `arxiv.org`).

**Voiceover:**
> *"Static vulnerability benchmarks go stale in weeks. That's why NeMo-Sentry makes functional runtime calls to the **Tavily Search API**.*  
>  
> *Tavily scans the live cybersecurity web for newly published 0-day jailbreak techniques, delimiter bypasses, and 2026 CVEs.*  
>  
> *This dynamic intelligence grounds Nemotron-3's attack planning, guaranteeing our probes reflect today's active adversary landscape."*

---

### Part 5: Autonomous NVIDIA NeMo Guardrail Synthesis (Colang 2.0) (1:40 – 2:05)
**Screen:**  
Click the **"NVIDIA NeMo Guardrails (Colang 2.0)"** tab:
1. Show the syntax-highlighted code editor with `security_enclave.co` and `config.yml`.
2. Scroll through the generated Colang flows:
   - `define flow catch delimiter escape`
   - `define flow check pii leakage`
   - `define flow filter_prompt_injection`
3. Click **"Download rails.co"** and **"Download config.yml"**.
4. Click **"Export Audit JSON"** to show instant compliance reporting.

**Voiceover:**
> *"Here is where NeMo-Sentry turns discovery into active defense. Instead of handing engineers a generic PDF, Nemotron-3 automatically synthesizes production-ready **NVIDIA NeMo Guardrails** in **Colang 2.0**!*  
>  
> *Notice how it auto-generates deterministic user intent definitions, bot refusal flows, and XML boundary sanitizers specifically tailored to block the delimiter attacks it just discovered.*  
>  
> *Developers can download `security_enclave.co` and `config.yml` with a single click."*

---

### Part 6: Mathematical Proof of Defense (Verification Delta) (2:05 – 2:25)
**Screen:**  
Click the purple **"Run Guardrail Verification"** button:
1. Transition to the **"Verification Delta"** tab.
2. The summary banner glows green:
   - `INITIAL BREACH RATE: 100.0%`
   - `GUARDED BREACH RATE: 0.0% (100% Neutralized)`
   - `STATUS: VERIFIED_SECURE`
3. Scroll down to show verified probe rows:
   - `WAS: BREACHED → NOW: BLOCKED (Protected by: rail_input_injection_filter)`

**Voiceover:**
> *"We don't assume guardrails work—we prove it mathematically.*  
>  
> *Our verification engine re-executes every previously successful exploit against the newly shielded model.*  
>  
> *The result? A **100% breach neutralization**. The breach rate collapses from 100% down to **0.0%**, with malicious prompts intercepted at the Colang input rail in under 25 milliseconds before ever reaching the model."*

---

### Part 7: Agentic Repo Patcher & One-Click CI/CD Gate (2:25 – 2:40)
**Screen:**  
Click the **"Agentic Repo Patcher & CI/CD"** tab:
1. Highlight `nemo_guardrails.patch` with `git apply nemo_guardrails.patch`.
2. Scroll to `.github/workflows/nemo_sentry_ci.yml` (blocking PR merges if breach rate > 0%).
3. Show `server.py` (FastAPI production proxy microservice).

**Voiceover:**
> *"Pushing past obvious wrappers, NeMo-Sentry acts as an autonomous security engineer.*  
>  
> *It writes a ready-to-merge **Git Patch** that embeds NeMo Guardrails directly into your codebase, a **GitHub Actions CI/CD workflow** that blocks pull requests if security breaches occur, and a production **FastAPI proxy** running on Nebius Token Factory."*

---

### Part 8: Judge VIP Passcode, BYOK & Interactive Guide (2:40 – 2:55)
**Screen:**  
Pan up to the top navigation bar:
1. Click the gold **"Judge Access"** button $\to$ Show passcode `NEBIUS-JUDGE-2026` unlocking 10 live cloud runs.
2. Click the green **"BYOK"** button $\to$ Show both **Nebius Token Factory** and **Tavily AI** key fields with the **Strict Zero-Storage Guarantee**.
3. Click **"🎯 Guide Me"** $\to$ Step through the 7-step guided walkthrough modal.

**Voiceover:**
> *"To ensure a seamless evaluation, judges have dedicated VIP access: click **Judge Access** and enter passcode **NEBIUS-JUDGE-2026** to get 10 full live cloud evaluations on our hosted Nebius credits!*  
>  
> *Evaluators can also Bring Your Own Key for Nebius and Tavily with our strict **Zero-Storage Privacy Guarantee**—keys are held strictly in volatile browser memory and never touch disk.*  
>  
> *And if you're new to the tool, our built-in **🎯 Guide Me** tour walks you through the entire penetration test in 60 seconds."*

---

### Part 9: Conclusion & Outro (2:55 – 3:00)
**Screen:**  
Show the GitHub repository with the MIT License badge, concluding with the project logo and tagline.

**Voiceover:**
> *"NeMo-Sentry makes frontier AI security autonomous, verifiable, and open-source. Check out our GitHub repo and try the live demo today. Thank you!"*

---

## 🎥 Recording Checklist for Maximum Judge Score

1. **Screen Resolution:** Record at 1080p (1920x1080) or 1440p (2560x1440) so code and Colang syntax are razor sharp.
2. **Audio Quality:** Use a USB/XLR microphone or crisp headset; avoid laptop mic echo.
3. **Pacing:** Practice speaking at a brisk, energetic pace (around 140–150 words per minute) to fit comfortably within 2m50s.
4. **Hard Stop at 3:00:** Verify the final uploaded video shows $\le$ 2:55 on YouTube to guarantee zero penalties from hackathon judges.
5. **Video Description:** Include links to:
   - Your Public GitHub Repository
   - Your Hosted Live Demo URL
   - Judge VIP Passcode: `NEBIUS-JUDGE-2026`
