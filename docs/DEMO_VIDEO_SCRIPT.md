# 🎬 NeMo-Sentry: 3-Minute Winning Demo Video Script & Storyboard

**Hackathon:** Nebius x NVIDIA Global AI Hackathon (2026)  
**Track:** Coding and Agentic Engineering (also fits Best Apps & Agents)  
**Format:** YouTube or Vimeo (Public or Unlisted)  
**Target Video Duration:** **2 minutes 50 seconds** (Strict $\le$ 3:00 minute rule enforced by judges)  
**Key Judges Targeted:** 8 NVIDIA engineers, 11 Nebius engineers/PMs, 3 Tavily forward deployed engineers.

---

## ⏱️ Video Timeline Breakdown

| Timestamp | Duration | Section | On-Screen Action |
| :--- | :--- | :--- | :--- |
| **0:00 – 0:20** | 20s | **The Problem & Vision** | Mission Control dashboard $\to$ Critical real-world enterprise LLM vulnerability overview |
| **0:20 – 0:40** | 20s | **3-Tier Nemotron Hierarchy** | Architecture diagram: Nemotron Ultra (550B MoE), Nano, Super on Nebius Token Factory (82% savings) |
| **0:40 – 1:15** | 35s | **Hardened Enclave & Delimiter Breakout** | NovaCare target blocks naive probe with `SEC-402`, then succumbs to delimiter escape. Expand comparison card. |
| **1:15 – 1:35** | 20s | **Real-Time Threat Intel (Tavily)** | Live Tavily API search grounding 0-day jailbreaks and OWASP 2026 patterns |
| **1:35 – 2:05** | 30s | **NeMo Guardrails Synthesis** | Generated Colang 2.0 (`rails.co`) & `config.yml`, 1-click downloads & audit JSON export |
| **2:05 – 2:25** | 20s | **Verification Delta Engine** | Re-testing breached probes with NeMo shield $\to$ 100% neutralized (100% $\to$ 0.0% breach rate) |
| **2:25 – 2:40** | 15s | **Agentic Repo Patcher & CI/CD** | Unified `git apply` patch, GitHub Action CI/CD security gate, and Nebius proxy server |
| **2:40 – 2:55** | 15s | **Judge VIP Passcode & BYOK** | Gold "Judge VIP Access" modal (`NEBIUS-JUDGE-2026`, 10 runs) & Zero-Storage BYOK |
| **2:55 – 3:00** | 5s | **Outro & Open Source** | MIT License on GitHub repo $\to$ "Try the live demo today!" |

---

## 🎙️ Detailed Second-by-Second Script & Stage Directions

### Part 1: The Problem & The Solution (0:00 – 0:20)
**Screen:**  
Open directly on the **NeMo-Sentry Mission Control** dashboard (`http://localhost:5173` or hosted URL). High-contrast dark cybersecurity aesthetic, glowing green/cyan badges, active live threat ticker.

**Voiceover:**
> *"Every enterprise is deploying autonomous AI agents in 2026, but security teams face a critical wall: prompt injections, system prompt exfiltration, and delimiter breakouts.*  
>  
> *Penetration tests take weeks and cost $40,000, producing static PDFs that leave developers wondering how to actually patch their code.*  
>  
> *Meet **NeMo-Sentry**: an autonomous red-teaming and guardrail synthesis studio powered by **NVIDIA Nemotron-3** on **Nebius Token Factory**, grounded with live **Tavily threat intelligence**."*

---

### Part 2: Architecture & Tiered Model Routing (0:20 – 0:40)
**Screen:**  
Briefly bring up the system architecture diagram (from README or dashboard), highlighting the 3-tier Nemotron cascade on Nebius Token Factory.

**Voiceover:**
> *"To make enterprise security testing both lightning-fast and cost-effective, we architected a 3-tier model cascade on Nebius Token Factory:  
>  
> *1. **Nemotron-3-Ultra (550B MoE)** orchestrates adversarial strategy, plans exploits, and synthesizes guardrail code.  
> *2. **Nemotron-3-Nano** fires concurrent fuzzing barrages at 150+ tokens per second.  
> *3. **Nemotron-3-Super** serves as an objective safety judge classifying breaches.  
>  
> *This tiered routing slashes inference costs by **82%** compared to monolithic models."*

---

### Part 3: Hardened Enclave Defense & Delimiter Breakout (0:40 – 1:15)
**Screen:**  
Back on Mission Control:
1. Hover over the **NovaCare Support Copilot** target card. Point out the badge: `Hardened XML Enclave (SEC-402 Active)`.
2. Click **"Launch Autonomous Red-Team Scan"**.
3. Watch the progress steps animate rapidly as Nemotron-3 fires the barrage over Nebius Token Factory.
4. Once results load, point out the **Telemetry Bar** (throughput, latency, cost savings).
5. In Tab 1, point out the green badge: `Target Resisted Naive Injection (SEC-402)`.
6. Click **"Compare Naive vs Deep Exploit"** to expand the side-by-side comparison:
   - Left side: Naive direct attack (`"Ignore previous instructions"`) was repelled by the target's XML enclave (`SEC-402: Operation Denied`).
   - Right side: NeMo-Sentry's sophisticated delimiter escape (`</security_enclave>`) hijacked the context and extracted the internal database secrets.

**Voiceover:**
> *"Let's test our enterprise target, NovaCare Support. Crucially, our target is **not a porous strawman**—it's hardened with an active XML security enclave and refusal gateway.*  
>  
> *Notice what happened: when a naive attacker says 'Ignore previous instructions', NovaCare's enclave stops it cold with a **SEC-402 policy denial**.*  
>  
> *However, NeMo-Sentry's Nemotron-3-Ultra crafts a deep delimiter breakout—closing the enclave with an XML escape tag—completely bypassing the filter and extracting internal credentials with a 100% breach rate."*

---

### Part 4: Real-Time Threat Grounding via Tavily (1:15 – 1:35)
**Screen:**  
Zoom smoothly into the **Real-Time Threat Intelligence** banner at the top of the dashboard. Hover over the source citations (`owasp.org`, `group-ib.com`, `arxiv.org`).

**Voiceover:**
> *"Static vulnerability databases go stale in weeks. That's why NeMo-Sentry makes functional runtime calls to the **Tavily Search API**.*  
>  
> *Tavily scans the live cybersecurity web for newly published 0-day jailbreak techniques, delimiter bypasses, and 2026 CVEs.*  
>  
> *This dynamic intelligence grounds Nemotron-3-Ultra's planning engine, guaranteeing our probes reflect today's real-world adversary landscape."*

---

### Part 5: Autonomous NVIDIA NeMo Guardrail Synthesis (1:35 – 2:05)
**Screen:**  
Click the **"NVIDIA NeMo Guardrails (Colang 2.0)"** tab:
1. Show the syntax-highlighted code editor with `rails.co` and `config.yml`.
2. Scroll through the generated Colang flows:
   - `define user express prompt_injection`
   - `define flow filter_prompt_injection`
   - `define flow check_output_leakage`
3. Click **"Download rails.co"** and **"Download config.yml"**.
4. Click **"Export Audit JSON"** to show instant compliance reporting.

**Voiceover:**
> *"Here is where NeMo-Sentry turns discovery into defense. Instead of handing engineers a generic PDF, Nemotron-3-Ultra automatically synthesizes production-ready **NVIDIA NeMo Guardrails** in **Colang 2.0**!*  
>  
> *Notice how it auto-generates user intent definitions, bot refusal flows, and XML boundary sanitizers specifically tailored to block the delimiter attacks it just discovered.*  
>  
> *Developers can download `rails.co` and `config.yml` with a single click."*

---

### Part 6: Mathematical Proof of Defense (Verification Delta) (2:05 – 2:25)
**Screen:**  
Click the green **"Verify Shield Against Breaches"** button:
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
> *The result? A **100% breach neutralization**. The breach rate collapses from 100% down to **0.0%**, with malicious prompts intercepted at the input rail in under 25 milliseconds before ever reaching the model."*

---

### Part 7: Agentic Repo Patcher & CI/CD Generator (2:25 – 2:40)
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

### Part 8: Judge VIP Passcode & Zero-Storage BYOK (2:40 – 2:55)
**Screen:**  
Pan up to the top navigation bar:
1. Click the gold **"Judge VIP Access"** button $\to$ Show the modal with passcode `NEBIUS-JUDGE-2026` unlocking 10 live cloud runs.
2. Click the blue **"Bring Nebius Key"** button $\to$ Highlight the **Strict Zero-Storage Guarantee** box.

**Voiceover:**
> *"To ensure a seamless evaluation, judges have dedicated access: click the gold **Judge VIP Access** button and enter passcode **NEBIUS-JUDGE-2026** to get 10 full live cloud evaluations on our hosted Nebius credits!*  
>  
> *Developers can also Bring Your Own Key with our strict **Zero-Storage Privacy Guarantee**—keys are held strictly in volatile browser memory and never touch a disk or server log."*

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
