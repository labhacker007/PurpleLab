# Patent Filing Strategy & Timeline
## PurpleLab Platform — PL-P1, PL-P2, PL-P3

**Date:** 2026-06-09 (updated from 2026-06-08 after deep prior art research)  
**Status:** Ready to file provisionals — all disclosures complete, prior art research complete  
**Urgency:** ⚠️ CRITICAL — CTI-REALM (Microsoft Security AI) published March 2026 covers stages 1, 4, 5 of PL-P2. Each passing month increases the risk that another paper or product announcement constitutes prior art. File provisional NOW.

---

## Recommended Action Sequence

### Immediate (within 60 days)

**File one provisional patent application covering PL-P1 + PL-P2 + PL-P3.**

A single provisional filing establishes the same priority date for all three claims at lower cost than three separate applications. The provisional does not need complete claims — a detailed technical disclosure (already prepared as the three PL-P* documents in this directory) satisfies the enablement requirement.

**Why NOT wait — threat timeline (most urgent first):**

| Event | Date | What It Means |
|-------|------|---------------|
| **CTI-REALM published** (Microsoft Security AI, arXiv:2603.13517) | March 2026 | Covers stages 1, 4, 5 of PL-P2 — the closest academic prior art. Published 3 months ago. Any further similar publication risks narrowing PL-P2 claims further. |
| **Picus + Recorded Future announcement** (intelligence-led BAS) | January 2026 | Covers TI-prioritized simulation. No patent filed. Could file any day. |
| **Picus AI-powered BAS** (multi-agent TI-to-simulation) | October 2025 | 8 months in market without a patent. |
| **CardinalOps "Agentic Detection Engineering"** rebranding | 2026 | No patents found but active in detection gap automation. Could file defensively at any time. |
| **AttackIQ Watchtower** (AI-driven ATT&CK coverage) | August 2025 | No patent filed on coverage mapping automation. Active in the same space. |

Under 35 U.S.C. § 102 (America Invents Act, first-to-file), any application published after your priority date cannot be prior art against your claims. **Filing the provisional now locks the priority date for all three inventions simultaneously.** Every day of delay is a day any of the above parties could file first.

**What a provisional filing provides:**
- Established priority date (critical)
- 12 months to file full utility application(s)
- No formal claim requirements — the technical disclosures in this directory are sufficient
- Approximate attorney cost: $1,500–3,000 for a provisional based on the technical disclosures already prepared

---

### Within 6 months (by December 2026)

**Defensive technical publication for DES/IHDS formulas.**

Publish a technical disclosure on arXiv or as a company technical blog post describing the exact DES and IHDS scoring formulas, their derivation, and the underlying scoring rationale. This creates prior art that blocks competitors from patenting a similar formula.

A defensive publication:
- Is free (just publish it)
- Immediately becomes prior art that anyone searching USPTO must acknowledge
- Does not require attorney fees
- Does not prevent you from continuing to use the formula

---

### Within 12 months (by June 2027)

**File full utility patent applications.** Convert the provisionals into one or two full utility patent applications with complete claim sets.

**Option A — Single utility application covering all three inventions:**  
- One filing, lower cost (~$15,000–25,000 attorney fees for prosecution)
- Single claim set covering the closed-loop gap dispatch (PL-P1), intel-to-detection pipeline (PL-P2), and LLM composition (PL-P3)
- Risk: if one claim area is rejected, it may affect the whole application

**Option B — Two utility applications (recommended):**  
- Application 1: PL-P1 + PL-P2 (both relate to the coverage store and automated simulation dispatch — natural fit)
- Application 2: PL-P3 (LLM composition — different technical domain, different prior art)
- Higher cost (~$30,000–40,000) but cleaner claim sets and independent prosecution
- Rejection in PL-P3 does not affect PL-P1/PL-P2

---

## Claim Strength Assessment

> Updated 2026-06-09 after deep codebase read + 30-source prior art research. See [NOVELTY_ANALYSIS.md](NOVELTY_ANALYSIS.md) for full analysis.

| Claim | Novelty | Non-Obviousness | Enablement | Closest Prior Art | Overall Strength |
|-------|---------|-----------------|------------|------------------|-----------------|
| **PL-P1: Coverage state machine** (3-state, sim-validated COVERED) | HIGH | HIGH | COMPLETE | CardinalOps (SIEM-layer only, no sim) | **STRONG** |
| **PL-P1: Risk-weighted gap selection** (freq × sev × time-weight formula) | HIGH | HIGH | COMPLETE | None found | **STRONG** |
| **PL-P1: Gap-only simulation dispatch** (uncovered techniques only) | HIGH | HIGH | COMPLETE | None found | **STRONG** |
| **PL-P1: Closed feedback loop** | HIGH | HIGH | COMPLETE | FireCompass US20210352100A1 (different domain) | **STRONG** |
| **PL-P2: Coverage-gated dispatch** (simulate IF AND ONLY IF uncovered) | HIGH | HIGH | COMPLETE | None found — absent from all 10+ papers reviewed | **STRONGEST** |
| **PL-P2: Sigma from live simulation logs** (not templates, not pre-recorded) | MODERATE-HIGH | HIGH | COMPLETE | IntelEX (pre-collected logs, no gate), CTI-REALM (pre-recorded) | **STRONG** |
| **PL-P2: Full 7-stage pipeline** | HIGH | HIGH | COMPLETE | CTI-REALM covers 3 of 7 stages only | **STRONG** |
| **PL-P3: Single-round LLM composition** | MODERATE-HIGH | MODERATE-HIGH | COMPLETE | US12537846 (LLM-in-loop, opposite arch) | **MODERATE** |
| **PL-P3: Type-preserving template resolver** | MODERATE-HIGH | HIGH | COMPLETE | None found in any template engine | **STRONG** |
| **PL-P3: Wave-based parallel execution** (Claims 11–14) | MODERATE | MODERATE | COMPLETE | Airflow (generic, not typed/security-domain) | **MODERATE** |
| **DES: 5-dimensional geometric mean** (sim-outcome data) | MODERATE | HIGH | PARTIAL (scoring stubs, fix H-1) | US11973788 (vuln scan, not sim) | **MODERATE** |
| **IHDS: Multiplicative 3-stage** intel×hunt×detection | MODERATE | HIGH | PARTIAL (scoring stubs, fix H-1) | None found | **MODERATE** |

**PL-P2's coverage-gated dispatch is the single strongest claim in the portfolio — it is absent from every paper and product reviewed.**  
**PL-P1 and PL-P2 are the primary commercial assets.** PL-P3 + wave execution claims add defensive depth but are harder to prosecute to grant.

---

## Freedom-to-Operate Summary

Before commercializing PurpleLab, confirm the following do not block your operations:

| Patent | Risk Level | Key Distinction | Action |
|--------|-----------|-----------------|--------|
| US9892260 (SafeBreach) — simulation execution DAG | LOW | We do not claim how simulations execute; only what drives their selection and what is done with outcomes | No action needed |
| US11991203 (Picus) — stateful intra-simulation branching | LOW | Picus claims *intra-simulation* step branching; PL-P1 claims *inter-simulation* technique selection — different scope | Confirm claim language |
| US11973788 (Tenable) — scoring controls via vuln scan data | LOW | Tenable scores against static vulnerability scan data; PL-P1 scores against dynamic simulation outcomes | Confirm claim language |
| US12537846 (Microsoft) — cybersecurity LLM iterative execution | LOW for PL-P1/P2, MODERATE for PL-P3 | Microsoft calls LLM repeatedly during execution; PL-P3 calls LLM once, zero LLM calls during execution | PL-P3 Claims 1–2 must explicitly distinguish |
| US20210352100A1 (FireCompass) — frontier-driven red teaming | LOW | FireCompass traverses attack paths; PL-P1 tracks per-ATT&CK-technique detection coverage states — different data model and objective | Confirm at utility application stage |
| US12223062 (Zafran) — security control gap identification | LOW | Asset-based control gap analysis; no ATT&CK technique state machine, no simulation dispatch, no Sigma generation | No action needed |

**Recommendation:** Commission a full freedom-to-operate (FTO) opinion before any commercial sales or fundraising that involves IP due diligence. Budget $5,000–10,000 for FTO opinion. The FTO is LOW risk based on current research — no blocking patents found for PL-P1 or PL-P2 core claims.

---

## Cost Summary

| Action | Timing | Estimated Cost |
|--------|--------|----------------|
| Provisional application (all 3 inventions) | Now | $1,500–3,000 |
| DES/IHDS defensive publication | Within 6 months | Free |
| Full utility application 1 (PL-P1 + PL-P2) | Within 12 months | $15,000–20,000 |
| Full utility application 2 (PL-P3) | Within 12 months | $10,000–15,000 |
| Freedom-to-operate opinion | Before commercialization | $5,000–10,000 |
| **Total** | | **~$35,000–50,000** |

This is a standard IP investment for a B2B SaaS security startup. Patents in the BAS/detection space have been central to SafeBreach and AttackIQ's competitive moats and M&A valuations.

---

## What to Give Your Patent Attorney

The following documents are ready to hand to an attorney for provisional drafting:

### Primary Disclosures (hand all six to attorney)

1. **[PL-P1_GAP_WEIGHTED_SIMULATION_DISPATCH.md](PL-P1_GAP_WEIGHTED_SIMULATION_DISPATCH.md)**  
   Gap-weighted closed-loop dispatch with coverage state machine. 12 claims (3 independent). Notes for Patent Counsel section at end identifies key prior art distinctions.

2. **[PL-P2_INTEL_TO_DETECTION_PIPELINE.md](PL-P2_INTEL_TO_DETECTION_PIPELINE.md)**  
   7-stage TI-to-detection pipeline with coverage-gated dispatch. 12 claims (3 independent). The coverage-gated dispatch (Claims 1–2) is the strongest claim in the entire portfolio.

3. **[PL-P3_LLM_PIPELINE_COMPOSITION.md](PL-P3_LLM_PIPELINE_COMPOSITION.md)**  
   Single-round LLM composition + wave execution engine. 14 claims (3 independent: Claims 1, 3, 11). Claims 11–14 cover the wave execution engine as a standalone invention (fallback if LLM composition claims challenged).

4. **[PRIOR_ART_LANDSCAPE.md](PRIOR_ART_LANDSCAPE.md)**  
   30-source prior art search: patents, academic papers, commercial products. FTO table with 15 entries. Will save 3–5 hours of attorney research time. **Read the "Direct Papers — Updated June 2026" section carefully** — IntelEX and CTI-REALM are the two most important academic papers to distinguish in PL-P2.

5. **[NOVELTY_ANALYSIS.md](NOVELTY_ANALYSIS.md)**  
   Full codebase read + online prior art verification. Identifies exactly which code is novel vs. commodity. Part 4 lists what must NOT appear in independent claims (Beta-Binomial, exponential decay, asyncio.gather, SQLAlchemy). Part 7 is the definitive patent-eligible vs. not table.

6. **[FILING_STRATEGY.md](FILING_STRATEGY.md)** — this document.

### Working Code (reduction to practice evidence)

Hand these source files to attorney as exhibits demonstrating reduction to practice:

| File | What It Proves |
|------|---------------|
| `backend/agent/pipeline/executor.py` | PL-P3: `_topological_waves()` (wave scheduler), `_resolve()` (type-preserving resolver), `validate_pipeline()` (pre-execution validator), `PipelineExecutor.run()` |
| `backend/agent/pipeline/blocks.py` | PL-P1 + PL-P2 + PL-P3: `BLOCK_REGISTRY`, `BlockDef`, `get_gap_analysis`, `run_scenario`, `import_sigma_rules`, `create_use_case` |
| `backend/agent/pipeline/tools.py` | PL-P3: `_run_pipeline()` (single LLM call composition), `_list_blocks()` (discovery endpoint) |
| `backend/scoring/des.py` | PL-P1 Claim 11: 5-dimension geometric mean DES formula |
| `backend/scoring/ihds.py` | IHDS multiplicative 3-stage formula |

### Critical Instructions for Attorney

- **File as provisional under 35 U.S.C. § 111(b)** — no formal claims required; use the technical disclosures as specification exhibits
- **Priority claim:** domestic, no prior PCT or foreign filing
- **Inventors:** [complete inventor list before filing — ALL individuals who contributed to the novel concepts]
- **Urgency flag:** CTI-REALM (arXiv:2603.13517, Microsoft, March 2026) covers TI-to-rule generation pipeline without the coverage gate — must be cited and distinguished in PL-P2. File before more papers appear.
- **PL-P2 distinguishing language:** The coverage gate is the independent claim — emphasize "dispatching simulation tasks IF AND ONLY IF no validated detection rule exists for the technique." IntelEX and CTI-REALM both lack this gate.
- **PL-P3 distinguishing language:** Explicitly reference US12537846 as the iterative LLM-in-loop system being improved upon. PL-P3 is architecturally inverted: LLM called once, zero LLM calls during execution.
- **PL-P1 distinguishing language:** FireCompass US20210352100A1 has a feedback loop but it optimizes attack PATH traversal (RL), not per-ATT&CK-technique detection COVERAGE (state machine). These are different objectives, different data models.
- **Do NOT claim:** generic asyncio concurrency, SQLAlchemy ORM patterns, exponential decay formulas, Beta-Binomial Bayesian estimators, YAML parsing, HTTP client libraries. These are commodity and will invite rejection.
- **Track One expedited examination:** Recommended if budget allows (~$4,000 additional). Halves typical prosecution time to 6–12 months. Particularly valuable here given the active publication activity in this space.

---

## Licensing and Commercial Strategy

Once patents are granted or published, the following commercial strategies are available:

**Defensive use (primary):** Patents prevent SafeBreach, Picus, AttackIQ, or Cymulate from claiming ownership of these techniques and blocking PurpleLab's operations.

**Licensing:** The gap-weighted simulation dispatch and intel-to-detection pipeline may be licensable to SIEM vendors (Splunk, Microsoft Sentinel, Elastic) who want to add coverage-driven simulation capabilities to their platforms without building from scratch.

**M&A:** IP portfolios are a primary value driver in security startup acquisitions. SafeBreach was acquired by Preempt Security (Crowdstrike) partially on IP value. Having these patents in prosecution (even if not yet granted) at exit time significantly improves valuation multiples.

**CardinalOps position:** If CardinalOps attempts to patent detection gap analysis, PurpleLab's filed provisional would constitute prior art for the gap analysis + simulation dispatch combination, limiting their claim scope.
