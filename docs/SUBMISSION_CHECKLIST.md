# 🚀 Pre-Submission Checklist: Nebius x NVIDIA Hackathon

**Hackathon:** Nebius x NVIDIA Global AI Hackathon (2026)  
**Project:** NeMo-Sentry — Autonomous Red-Team & NeMo Guardrail Synthesizer  
**Deadline:** October 30, 2026 @ 6:00pm GMT+1  
**Prize Targets:** Grand Prize ($20,000), Track Winner (NVIDIA Jetson Orin Nano), Best Use of Tavily ($3,000)

---

## 🛠️ Phase 1: Code Repository & Licensing (Automated & Ready)
- [x] **Git Repository Initialized:** Local repository with clean, descriptive commit history.
- [x] **Open Source License:** [LICENSE](file:///c:/Users/mirac/Documents/company%20docs/devpost%20hackathon/nvidia/LICENSE) file containing standard MIT License present at repo root.
- [x] **Comprehensive README:** [README.md](file:///c:/Users/mirac/Documents/company%20docs/devpost%20hackathon/nvidia/README.md) with architecture diagram, tiered model cascade, benchmarks, and quickstart commands.
- [x] **Zero Credentials Leak Check:** `.env` is properly ignored in `.gitignore` and has NEVER been staged or committed.
- [ ] **Push to Remote Git Host:** Push repo to GitHub / GitLab:
  ```bash
  git remote add origin https://github.com/your-username/nemo-sentry.git
  git branch -M main
  git push -u origin main
  ```
- [ ] **Verify Repository Visibility:** Open repository URL in an incognito window to verify it is **PUBLIC** with MIT license visible at the top.

---

## 🌐 Phase 2: Live Deployment & Smoke Test
- [ ] **Backend Hosting:** Deploy `backend` to a cloud host (Render, Railway, Fly.io, or Nebius Serverless Endpoints).
  - Environment Variables (Cloud Host Settings):
    - `NEBIUS_API_KEY`: Your hosted Nebius key for the public tier (1 run) and judge VIP quota (10 runs).
    - `TAVILY_API_KEY`: Your Tavily search key.
- [ ] **Frontend Hosting:** Deploy `frontend` to Vercel, Netlify, or Cloudflare Pages.
  - Set `VITE_API_BASE_URL` to point to your live backend URL (e.g. `https://nemo-sentry-api.onrender.com`).
- [ ] **Incognito Smoke Test:**
  1. Open the hosted URL in an incognito window.
  2. Verify the Quota status displays `Public Evaluation Quota: 1/1 Run Remaining`.
  3. Click **"Launch Autonomous Red-Team Scan"** on *NovaCare Support Copilot*.
  4. Verify the XML Enclave defense repels naive attacks (`SEC-402`) while delimiter breakouts succeed.
  5. Click **"Verify Shield Against Breaches"** and confirm 100% $\to$ 0.0% breach rate.
  6. Attempt a 2nd run: verify the **Device Evaluation Limit Modal** appears to prevent credit drain.
  7. Click **"Enter Hackathon Judge Passcode"**, submit `NEBIUS-JUDGE-2026`, and verify that the 10-run VIP quota unlocks.
  8. Click **"Bring Nebius Key"** and confirm the Zero-Storage dialog appears.

---

## 🎥 Phase 3: Demo Video Recording
- [ ] **Review Script:** Read the updated [DEMO_VIDEO_SCRIPT.md](file:///c:/Users/mirac/Documents/company%20docs/devpost%20hackathon/nvidia/docs/DEMO_VIDEO_SCRIPT.md) (strictly timed for 2 minutes 50 seconds).
- [ ] **Record Screen & Voice:** Record high-resolution 1080p/1440p video using OBS Studio, Loom, or ScreenStudio.
- [ ] **Key Highlights to Show:**
  1. 3-Tier model cascade on Nebius Token Factory (Ultra MoE, Nano, Super) = 82% cost savings.
  2. Hardened target sandbox repelling naive attacks with `SEC-402` refusal gateway.
  3. Deep delimiter breakout (`</security_enclave>`) side-by-side comparison.
  4. Live Tavily threat grounding banner.
  5. Synthesized Colang 2.0 guardrail code (`rails.co` & `config.yml`).
  6. Mathematical verification delta (100% $\to$ 0.0% breach rate).
  7. Agentic repo patcher (`.patch` & `.github/workflows/nemo_sentry_ci.yml`).
  8. Judge VIP button (`NEBIUS-JUDGE-2026`) and Zero-Storage BYOK guarantee.
- [ ] **Duration Check:** Confirm final video duration is **$\le$ 3 minutes** (e.g. 2:50).
- [ ] **Upload to YouTube or Vimeo:**
  - Set visibility to **Public** or **Unlisted** (NEVER Private).
  - Add title: `NeMo-Sentry: Autonomous Red-Teaming & NeMo Guardrail Synthesizer (Nebius x NVIDIA Hackathon)`.
  - In video description, link to the public GitHub repo and note the Judge Passcode `NEBIUS-JUDGE-2026`.

---

## 📝 Phase 4: Devpost Form Completion
- [ ] **Open Devpost Submission Link:** Navigate to your Devpost submission draft.
- [ ] **Copy-Paste Fields from:** [DEVPOST_SUBMISSION.md](file:///c:/Users/mirac/Documents/company%20docs/devpost%20hackathon/nvidia/docs/DEVPOST_SUBMISSION.md)
  - Project Name: `NeMo-Sentry: Autonomous Red-Team & NeMo Guardrail Synthesizer`
  - Elevator Pitch (196 characters)
  - About the Project (Markdown story with inspiration, architecture, challenges, accomplishments)
  - Built With Tags
  - Try It Out Links (GitHub + Hosted Demo + Judge Passcode `NEBIUS-JUDGE-2026`)
  - Video URL
  - Track: `Coding and agentic engineering`
  - Model Questions (Nemotron-3-Ultra, Nano, Super)
  - Nebius Platform Feedback (All 5 mandatory questions answered thoroughly)
  - Tavily Question: **YES** (with runtime call explanation)
- [ ] **Upload Screenshots:** Take 3–5 clean screenshots from the dashboard:
  1. Header with Quota Pill & Live Tavily Banner
  2. Attack Matrix & Naive vs Deep Delimiter Exploit Proof
  3. Synthesized Colang 2.0 Code Viewer
  4. Verification Delta (100% $\to$ 0.0% breach rate)
  5. Agentic Repo Patcher & CI/CD tab
- [ ] **Final Click:** Click **"Submit Project"** before the deadline!
