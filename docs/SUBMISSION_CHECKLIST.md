# 🚀 Pre-Submission Checklist: Nebius x NVIDIA Hackathon

**Deadline:** October 30, 2026 @ 6:00pm GMT+1  
**Project:** NeMo-Sentry  
**Prize Targets:** Grand Prize ($20,000), Track Winner (NVIDIA Jetson Orin Nano), Best Use of Tavily ($3,000)

---

## 🛠️ Phase 1: Code Repository & Licensing (Mandatory)
- [x] **Git Repository Initialized:** Local repository with clean commit history.
- [x] **Open Source License:** [LICENSE](file:///c:/Users/mirac/Documents/company%20docs/devpost%20hackathon/nvidia/LICENSE) file containing standard MIT License present at repo root.
- [x] **Comprehensive README:** [README.md](file:///c:/Users/mirac/Documents/company%20docs/devpost%20hackathon/nvidia/README.md) with architecture diagram, model breakdown, Nebius Token Factory benchmarks, and quickstart commands.
- [ ] **Push to Remote Git Host:** Push repo to GitHub / GitLab / Bitbucket:
  ```bash
  git remote add origin https://github.com/your-username/nemo-sentry.git
  git branch -M main
  git push -u origin main
  ```
- [ ] **Verify Repository Visibility:** Check in an incognito browser window that the repository is **PUBLIC** and anyone can view it without logging in.

---

## 🌐 Phase 2: Live Deployment (Demo URL)
- [ ] **Backend Hosting:** Deploy `backend` to a cloud host (Render, Railway, Fly.io, or Nebius Serverless Endpoints).
  - Set Environment Variables:
    - `NEBIUS_API_KEY`: Your Nebius Token Factory key (optional for mock, required for live).
    - `TAVILY_API_KEY`: Your Tavily key (optional for curated fallback, required for live).
- [ ] **Frontend Hosting:** Deploy `frontend` to Vercel, Netlify, or Cloudflare Pages.
  - Set `VITE_API_URL` to point to the live backend URL.
- [ ] **Smoke Test Demo:** Open the hosted URL in incognito, launch an attack barrage, and verify the Colang guardrails and 100% verification delta generate without errors.

---

## 🎥 Phase 3: Demo Video Recording
- [ ] **Review Script:** Read [DEMO_VIDEO_SCRIPT.md](file:///c:/Users/mirac/Documents/company%20docs/devpost%20hackathon/nvidia/docs/DEMO_VIDEO_SCRIPT.md).
- [ ] **Record Screen & Voice:** Record high-resolution 1080p/1440p video using OBS Studio, Loom, or ScreenStudio.
- [ ] **Strict Duration Check:** Ensure length is strictly **under 3 minutes** (e.g. 2 minutes 50 seconds).
- [ ] **Upload to YouTube or Vimeo:**
  - Set visibility to **Public** or **Unlisted** (NEVER Private or password-protected).
  - Add title: `NeMo-Sentry: Autonomous Red-Teaming & NeMo Guardrail Synthesizer (Nebius x NVIDIA Hackathon)`.
  - Add link to GitHub repo in the YouTube video description.

---

## 📝 Phase 4: Devpost Form Completion
- [ ] **Open Devpost Submission Link:** Navigate to your Devpost draft.
- [ ] **Copy-Paste Fields from:** [DEVPOST_SUBMISSION.md](file:///c:/Users/mirac/Documents/company%20docs/devpost%20hackathon/nvidia/docs/DEVPOST_SUBMISSION.md)
  - Project Name
  - Elevator Pitch
  - About the Project (Markdown story)
  - Built With Tags
  - Try It Out Links (GitHub + Hosted Demo)
  - Video URL
  - Track: `Coding and agentic engineering`
  - Model Questions (Nemotron-3-Ultra, Nano, Super)
  - Nebius Platform Feedback (Token Factory ratings)
  - Tavily Question: **YES** (with runtime call explanation)
- [ ] **Upload Screenshots:** Take 3–5 clean screenshots of the dashboard:
  1. Mission Control Header & Live Tavily Banner
  2. Attack Matrix showing detected breaches
  3. Synthesized Colang 2.0 Code Viewer
  4. Verification Delta (100% $\to$ 0.0% breach rate)
- [ ] **Final Click:** Click **"Submit Project"**!
