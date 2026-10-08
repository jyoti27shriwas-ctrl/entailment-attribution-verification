# Entailment-Based Verification of LLM-Generated Threat Actor Attribution Claims

This is the code and dataset behind my paper, *"Entailment-Based Verification of LLM-Generated Threat Actor Attribution Claims: A Dataset and Baseline Study."* It's the first stage of my PhD work — later on I plan to extend this with Logic Tensor Networks (symbolic reasoning over the MITRE ATT&CK graph) on top of the entailment baseline built here.

## Why I built this

LLMs are now used a lot to summarize or generate cyber threat intelligence (CTI) — things like "APT28 used technique T1566 (phishing)." The problem is LLMs hallucinate, so you can't just take a claim like that at face value before using it for any real defensive decision. When I looked, I couldn't find prior work that actually checks whether a specific, already-stated attribution claim is true, false, or unverifiable — most existing work either predicts who the attacker is, or checks general CTI credibility, not this specific verification problem. So that's what I set out to do here, as a baseline before adding the symbolic reasoning layer.

## What's actually in the pipeline

1. Retrieve one evidence source for each attribution claim.
2. Feed the claim + evidence into a pretrained NLI (natural language inference) model, which decides if the evidence supports, contradicts, or doesn't resolve the claim.
3. Compare that against a no-retrieval baseline (just the model guessing without evidence), to see how much retrieval is actually helping.
4. Break the errors down into two buckets — did retrieval fail to find the right evidence, or did the entailment model get it wrong even with the right evidence in front of it? That split is the main thing this baseline study is trying to establish.

## Files in this repo

| File | What it is |
|---|---|
| `CTI_Entailment_Pipeline.ipynb` | The main notebook (built for Google Colab). Takes the dataset, retrieves evidence, runs entailment scoring, builds the no-retrieval baseline, and spits out the results used in the paper. |
| `attribution_claims_final_v2.csv` | My labeled dataset — 85 claims across five categories (True, True-Alias, False-Swap, Unsure, False-Fabricated), each tied back to MITRE ATT&CK's own STIX 2.1 relationship data, with a real sourced evidence URL per claim. |
| `week2_entailment_results.csv` | What the notebook produces — predictions per claim (with and without retrieval), next to the gold labels. |
| `CTI_Attribution_Dataset_Week1_v2.xlsx` | The fuller workbook from the dataset-building stage — the claims, the group-technique ground truth pulled from ATT&CK, group/alias summaries, and an alias lookup table. |
| `link_check_results.csv`, `link_check_summary.csv` | How I checked the evidence URLs weren't dead — automated HTTP checks plus my own notes where I had to verify manually. |
| `extract_groups_techniques.py` | Pulls group-technique relationships out of the raw ATT&CK STIX bundle. |
| `generate_claim_seeds.py` | Generates the first-pass template claims, before I filled in real evidence. |
| `fill_evidence_and_claims.py` | Turns those templates into the final claims with real sourced evidence — this is what produces `attribution_claims_final_v2.csv`. |
| `check_links.py` | Script I used to flag dead evidence links. |

## About the dataset

Each row in `attribution_claims_final_v2.csv`:

- `claim_id` — just an ID
- `label` — the gold category (TRUE, TRUE-ALIAS, FALSE-SWAP, UNSURE, FALSE-FAB)
- `claim_text` — the actual attribution claim, in natural language
- `group_name`, `technique_name`, `technique_attack_id`, `group_attack_id` — which ATT&CK group/technique it refers to
- `evidence_report` — the source I'm using as evidence
- `notes`, `validated_by`, `validation_notes` — how the claim was put together / checked

## How to run it

1. Open `CTI_Entailment_Pipeline.ipynb` in Google Colab.
2. Run the first cell to install what it needs (`transformers`, `torch`, `trafilatura`, `scikit-learn`, `pandas`, `openpyxl`).
3. It'll ask you to upload a file — upload `attribution_claims_final_v2.csv`.
4. Run the rest of the cells in order. It retrieves evidence, scores entailment, and computes accuracy/results.
5. At the end it saves and downloads `week2_entailment_results.csv`.

## What I found

| System | Accuracy |
|---|---|
| Retrieval + Entailment | 14.1% |
| No-Retrieval Baseline | 11.8% |

Both numbers are low — near or below chance. When I dug into why: out of 40 True/True-Alias claims, only 11 failed because retrieval couldn't find the right evidence. The other 29 had the correct evidence retrieved, and the entailment model *still* got 27 of those wrong. So the real bottleneck isn't retrieval — it's that the entailment model struggles to match messy, free-form CTI report text to a structured attribution claim, even when it has the right evidence in front of it. That's basically the whole motivation for the next stage of my dissertation, where I bring in Logic Tensor Networks to reason over the ATT&CK graph directly instead of relying on one black-box entailment score.
## Labeling note
All labels were assigned by a single author. True, True-Alias and
False-Swap labels follow MITRE ATT&CK STIX relationships; Unsure and
False-Fabricated claims were written manually. No second annotator was
used, so no inter-annotator agreement is reported.

## Column guide (attribution_claims_final_v2.csv)
- claim_id: unique ID (C0001 to C0085)
- label: TRUE, TRUE-ALIAS, FALSE-SWAP, UNSURE or FALSE-FAB
- claim_text: the attribution claim
- evidence_report: a source URL for TRUE and TRUE-ALIAS claims; for the
  other classes, explanatory text (no URL)
- notes, validation_notes: how the claim was built and checked

## Citing this

```
J. K. Shriwas, "Entailment-Based Verification of LLM-Generated Threat Actor
Attribution Claims: A Dataset and Baseline Study," 2026.

```

## Questions

Feel free to reach out — Jyoti K. Shriwas, jyoti27shriwas@gmail.com
