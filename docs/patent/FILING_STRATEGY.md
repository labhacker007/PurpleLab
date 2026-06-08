# Patent Filing Strategy & Timeline
## PurpleLab Platform — PL-P1, PL-P2, PL-P3

**Date:** 2026-06-08  
**Status:** Ready to file provisionals  
**Urgency:** HIGH — Picus announced partial commercial analog October 2025 with no patent filed

---

## Recommended Action Sequence

### Immediate (within 60 days)

**File one provisional patent application covering PL-P1 + PL-P2 + PL-P3.**

A single provisional filing establishes the same priority date for all three claims at lower cost than three separate applications. The provisional does not need complete claims — a detailed technical disclosure (already prepared as the three PL-P* documents in this directory) satisfies the enablement requirement.

**Why not wait:**
- Picus announced TI→simulation pipeline in October 2025. No patent filed as of research date (June 2026). This means they have been in market for 8 months without a patent. They could file at any time.
- Under 35 U.S.C. § 102, a third-party patent application published before your filing date can constitute prior art for your claims. First to file wins under the America Invents Act (2013).
- CardinalOps has no patents in the gap analysis space but has first-mover commercial position. They could file defensively.

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

| Claim | Novelty | Non-Obviousness | Enablement | Overall Strength |
|-------|---------|-----------------|------------|-----------------|
| PL-P1: Gap-weighted closed loop | HIGH | HIGH — no prior system closes this loop | COMPLETE — code exists | **STRONG** |
| PL-P2: Intel-to-detection pipeline | HIGH | HIGH — combination of 6 stages not taught | COMPLETE — code exists | **STRONG** |
| PL-P3: Single-LLM-round composition | MODERATE | MODERATE — general plan-then-execute exists | COMPLETE — code exists | **MODERATE** |

**PL-P1 and PL-P2 are the primary commercial assets.** PL-P3 strengthens the portfolio and creates defensive value but is harder to prosecute to grant.

---

## Freedom-to-Operate Summary

Before commercializing PurpleLab, confirm the following do not block your operations:

| Patent | Risk | Action |
|--------|------|--------|
| US9892260 (SafeBreach) — simulation execution DAG | LOW — we don't claim simulation execution mechanics | No action needed |
| US11991203 (Picus) — stateful intra-simulation branching | LOW — our gap dispatch is inter-simulation | Confirm claim language distinguishes |
| US11973788 (Tenable) — scoring controls via vuln scan data | LOW — our scoring uses simulation outcomes | Confirm claim language distinguishes |
| US12537846 — cybersecurity LLM iterative execution | LOW for PL-P1/P2, MODERATE for PL-P3 | PL-P3 claims must explicitly distinguish |

**Recommendation:** Commission a full freedom-to-operate (FTO) opinion before any commercial sales or fundraising that involves IP due diligence. Budget $5,000–10,000 for FTO opinion.

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

1. **[PL-P1_GAP_WEIGHTED_SIMULATION_DISPATCH.md](PL-P1_GAP_WEIGHTED_SIMULATION_DISPATCH.md)** — Full technical disclosure with independent and dependent claims for the gap-weighted closed loop. The "Notes for Patent Counsel" section at the end of each document identifies the key distinctions from prior art to preserve in claim language.

2. **[PL-P2_INTEL_TO_DETECTION_PIPELINE.md](PL-P2_INTEL_TO_DETECTION_PIPELINE.md)** — Full technical disclosure with independent and dependent claims for the intel-to-detection pipeline.

3. **[PL-P3_LLM_PIPELINE_COMPOSITION.md](PL-P3_LLM_PIPELINE_COMPOSITION.md)** — Full technical disclosure with independent and dependent claims for single-round LLM composition.

4. **[PRIOR_ART_LANDSCAPE.md](PRIOR_ART_LANDSCAPE.md)** — Full prior art search results with patent numbers, coverage analysis, and freedom-to-operate preliminary assessment. This will save 3–5 hours of attorney research time.

5. **Working code** — `backend/agent/pipeline/` (executor, blocks, tools), `backend/scoring/des.py`, `backend/scoring/ihds.py`. Code is the strongest proof of enablement and reduction to practice.

**Instructions for attorney:**
- File as provisional under 35 U.S.C. § 111(b)
- Include the technical disclosures as specification exhibits
- Priority claim: domestic, no prior PCT or foreign filing
- Inventors: [complete before filing]
- PL-P3 claims should explicitly distinguish from US12537846's iterative LLM execution pattern
- PL-P1 claims should distinguish from US11973788's vulnerability-scan-based scoring
- Request expedited examination (Track One) if budget allows (~$4,000 additional, typically halves prosecution time to 6–12 months)

---

## Licensing and Commercial Strategy

Once patents are granted or published, the following commercial strategies are available:

**Defensive use (primary):** Patents prevent SafeBreach, Picus, AttackIQ, or Cymulate from claiming ownership of these techniques and blocking PurpleLab's operations.

**Licensing:** The gap-weighted simulation dispatch and intel-to-detection pipeline may be licensable to SIEM vendors (Splunk, Microsoft Sentinel, Elastic) who want to add coverage-driven simulation capabilities to their platforms without building from scratch.

**M&A:** IP portfolios are a primary value driver in security startup acquisitions. SafeBreach was acquired by Preempt Security (Crowdstrike) partially on IP value. Having these patents in prosecution (even if not yet granted) at exit time significantly improves valuation multiples.

**CardinalOps position:** If CardinalOps attempts to patent detection gap analysis, PurpleLab's filed provisional would constitute prior art for the gap analysis + simulation dispatch combination, limiting their claim scope.
