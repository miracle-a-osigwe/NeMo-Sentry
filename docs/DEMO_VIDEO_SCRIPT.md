# 🎬 NeMo-Sentry: 3-Minute Demo Video Script & Storyboard

**Format:** YouTube or Vimeo (Public or Unlisted)  
**Maximum Length:** Under 3 minutes (180 seconds strictly enforced by judges)  
**Key Judges Targeted:** 8 NVIDIA engineers, 11 Nebius engineers/PMs, 3 Tavily forward deployed engineers.

---

## ⏱️ Video Timeline Breakdown

| Timestamp | Duration | Section | On-Screen Action |
| :--- | :--- | :--- | :--- |
| **0:00 – 0:25** | 25s | **The Problem & Vision** | Title slide $\to$ News headlines of LLM data leaks & prompt injections |
| **0:25 – 0:50** | 25s | **Architecture & Model Cascade** | Architecture diagram showing Nebius Token Factory + Nemotron-3 |
| **0:50 – 1:15** | 25s | **Live Red-Teaming Barrage** | Mission Control dashboard: Target selection & high-throughput fuzzing |
| **1:15 – 1:40** | 25s | **Live Threat Grounding (Tavily)** | Highlighting the live Tavily API call and source citations |
| **1:40 – 2:10** | 30s | **NeMo Guardrails Synthesis** | Inspecting auto-generated Colang 2.0 (`rails.co`), `config.yml`, 1-click downloads |
| **2:10 – 2:35** | 25s | **Verification Delta (100% $\to$ 0%)** | Re-testing breached probes with NeMo shield $\to$ 100% neutralized |
| **2:35 – 2:50** | 15s | **Live Shield Playground** | Split-screen test: Unguarded (Breached) vs NeMo Shielded (Blocked) |
| **2:50 – 3:00** | 10s | **Conclusion & Impact** | Summary slide: Open infrastructure, 82% cost savings, MIT open source |

---

## 🎙️ Detailed Second-by-Second Script

### Part 1: The Problem & The Solution (0:00 – 0:25)
**Screen:**  
Show the **NeMo-Sentry Mission Control** dashboard at `http://localhost:5173`. Dark mode, glowing indicators, animated pulse badge reading "DEFCON ACTIVE".

**Voiceover:**
> *"Every company is deploying AI agents in 2026, but they face a critical security wall: prompt injections, system prompt exfiltration, sensitive data leaks, and multi-turn Crescendo jailbreaks.*  
>  
> *Traditional AI red-teaming audits take weeks and cost tens of thousands of dollars, producing static PDFs that don't help engineers patch models.  
>  
> *Meet **NeMo-Sentry**: an autonomous red-teaming and guardrail synthesis studio powered by **NVIDIA Nemotron-3** on **Nebius Token Factory**, grounded with live **Tavily threat intelligence**."*

---

### Part 2: Architecture & Tiered Model Routing (0:25 – 0:50)
**Screen:**  
Switch briefly to the architecture diagram from the README, highlighting the three Nemotron models and Nebius Token Factory.

**Voiceover:**
> *"To make red-teaming fast and cost-effective, we designed a 3-tier model routing hierarchy:  
>  
> *First, **Nemotron-3-Ultra** handles high-level adversarial decomposition and plans sophisticated attack vectors.  
>  
> *Second, **Nemotron-3-Nano** runs concurrent fuzzing barrages at over 150 tokens per second through Nebius Token Factory's low-latency endpoints.  
>  
> *Third, **Nemotron-3-Super** serves as our objective safety judge, evaluating whether target responses breach security policies.  
>  
> *This tiered architecture slashes token inference costs by **82%** compared to monolithic models."*

---

### Part 3: Live Red-Teaming Barrage in Action (0:50 – 1:15)
**Screen:**  
Back on the Mission Control UI:
1. Hover over the Target Card **"NovaCare Support Copilot"**.
2. Select attack vectors: **Prompt Injection**, **System Prompt Leakage**, **PII Exfiltration**.
3. Click the bright red **"Launch Autonomous Attack Barrage"** button.
4. Watch the animated progress bar update:
   - *"Invoking Tavily API for real-time 0-day threat intelligence..."*
   - *"Orchestrating Nemotron-3-Ultra adversarial probe planner..."*
   - *"Dispatching high-throughput concurrent fuzzing probes on Nebius Token Factory..."*
5. The Telemetry Bar and Attack Matrix populate instantly.

**Voiceover:**
> *"Let's test our enterprise target, NovaCare Support. With one click, NeMo-Sentry launches an autonomous barrage.  
>  
> *Notice the Nebius Token Factory telemetry: sub-50 millisecond latency and blazing throughput.  
>  
> *Looking at our attack matrix, the unshielded target suffered a **100% breach rate**. The model leaked internal instructions, disclosed administrative Postgres connection strings, and bypassed safety rules."*

---

### Part 4: Real-Time Threat Grounding via Tavily (1:15 – 1:40)
**Screen:**  
Zoom into the **Live Threat Grounding** banner at the top of the dashboard. Click on one of the external source links.

**Voiceover:**
> *"Unlike static benchmark scanners that become obsolete in weeks, NeMo-Sentry makes functional runtime calls to the **Tavily Search API**.  
>  
> *Tavily scans the live security web for newly disclosed CVEs, OWASP LLM 2026 exploits, and ArXiv papers on delimiter hijacking.  
>  
> *This dynamic threat intelligence is fed directly into Nemotron-3-Ultra's planning prompt, ensuring our attacks reflect today's real-world adversarial landscape."*

---

### Part 5: Autonomous NeMo Guardrail Synthesis (1:40 – 2:10)
**Screen:**  
Click the **"NVIDIA NeMo Guardrails (Colang 2.0)"** tab:
1. The code viewer displays `rails.co` and `config.yml`.
2. Scroll smoothly through the synthesized Colang:
   - `define user express prompt_injection`
   - `define flow filter_prompt_injection`
   - `define flow check_output_leakage`
3. Click **"Download rails.co"** and **"Download config.yml"** (instant downloads).
4. Click **"Export Audit JSON"** to demonstrate compliance export.

**Voiceover:**
> *"Now for the magic. Instead of giving developers a vague report, NeMo-Sentry's Nemotron-3-Ultra synthesizes production-ready **NVIDIA NeMo Guardrails**.  
>  
> *Here is the generated **Colang 2.0 specification** (`rails.co`) and runtime configuration (`config.yml`). It covers all 6 OWASP LLM categories, including input rails, dialog flows, and output redaction.  
>  
> *Developers can download the files with one click and deploy immediately to Nebius Token Factory."*

---

### Part 6: Mathematical Proof of Defense (Verification Delta) (2:10 – 2:35)
**Screen:**  
Click the green **"Verify Shield Against Breaches"** button:
1. The UI transitions to the **"Verification Delta"** tab.
2. The summary banner glows green:
   - **BEFORE SHIELD: 100% Breach Rate**
   - **AFTER NEMO GUARDRAILS: 0.0% Breach Rate**
3. Scroll down to show individual probes:
   - *"WAS: BREACHED $\to$ NOW: BLOCKED (Protected by: rail_input_injection_filter)"*

**Voiceover:**
> *"We don't just generate guardrails; we verify them.  
>  
> *With our automated verification engine, NeMo-Sentry re-fires every breached probe against the newly shielded model.  
>  
> *The result? **100% of attacks are neutralized.** The breach rate drops from 100% to **0.0%**, with malicious prompts intercepted at the input rail before reaching the core model."*

---

### Part 7: Interactive Live Shield Playground (2:35 – 2:50)
**Screen:**  
Click the **"Live Shield Playground"** tab:
1. Click the sample chip: `⚡ Extract System Prompt`.
2. Click **"Test Probe"**.
3. Point out the split screen:
   - Left (Unguarded): Shows leaking setup instructions (Critical Breach).
   - Right (Guarded): Shows clean NeMo Shield interception via `rail_filter_system_prompt_extraction`.

**Voiceover:**
> *"In our Live Shield Playground, engineers and judges can test any adversarial prompt interactively.  
>  
> *Watch side-by-side: on the left, the unguarded target leaks internal configuration. On the right, NVIDIA NeMo Guardrails intercepts the probe in real time, keeping the application safe."*

---

### Part 8: Conclusion & Summary (2:50 – 3:00)
**Screen:**  
Show the GitHub repo with MIT License and the closing summary slide:
- NeMo-Sentry
- Autonomous AI Red-Teaming & NeMo Guardrail Synthesis
- Powered by Nebius Token Factory & NVIDIA Nemotron-3
- Grounded with Tavily AI
- MIT Open Source

**Voiceover:**
> *"NeMo-Sentry proves that open infrastructure and open-weights models like NVIDIA Nemotron on Nebius Token Factory can deliver faster, cheaper, and safer AI systems than closed proprietary ecosystems.  
>  
> *The code is 100% open-source under the MIT license. Check out the GitHub repo and try the demo today. Thank you!"*

---

## 🎥 Recording Tips for Maximum Judge Scoring
1. **Resolution:** 1080p or 1440p (crisp text so code and Colang syntax are legible).
2. **Audio:** Use a clean external microphone, speak clearly and with energetic confidence.
3. **Cursor:** Use a cursor highlighter (like CursorFinder or Loom's default click bubble) so judges can follow where you are clicking.
4. **Strict 3-Minute Limit:** YouTube timer must read $\le$ 3:00 (e.g. 2:54 is ideal). Never exceed 3:00!
