# Entailment-Based Verification of LLM-Generated Threat Actor Attribution Claims

This is the code and dataset behind my paper, "Entailment-Based Verification of LLM-Generated Threat Actor Attribution Claims: A Dataset and Baseline Study." It's the first stage of my PhD work. Later on I plan to extend it with Logic Tensor Networks (symbolic reasoning over the MITRE ATT&CK graph) on top of the entailment baseline built here.

## Why I built this

LLMs are now used a lot to summarize or generate cyber threat intelligence (CTI), for example "APT28 used technique T1566 (phishing)." The problem is that LLMs hallucinate, so a claim like that can't be taken at face value before it is used for a real defensive decision. I'm not aware of prior work that checks whether a specific, already-stated attribution claim is true, false, or unverifiable. Most existing work either predicts who the attacker is, or checks general CTI credibility, rather than this specific verification problem. That is what I set out to study here, as a baseline before adding the symbolic reasoning layer.

## What's in the pipeline

1. For each attribution claim that has a source URL, retrieve one evidence document. (Only True and True-Alias claims have a URL; see the column guide below.)
2. Feed the claim and the evidence into a pretrained NLI (natural language inference) model, which decides whether the evidence supports the claim, contradicts it, or does not resolve it.
3. Compare this against a no-retrieval baseline, where the same model sees the claim with an empty premise instead of evidence, to see how much retrieval helps.
4. Break the errors into two buckets: did retrieval fail to find the evidence, or did the entailment model get it wrong even with the right evidence in front of it? That split is the main thing this baseline study tries to establish.

## Files in this repo

| File | What it is |
|---|---|
| `CTI_Entailment_Pipeline.ipynb` | The main notebook (built for Google Colab). Takes the dataset, retrieves evidence, runs entailment scoring, builds the no-retrieval baseline, and produces the results used in the paper. |
| `attribution_claims_final_v2.csv` | The labeled dataset: 85 claims across five categories (True, True-Alias, False-Swap, Unsure, False-Fabricated), each tied back to MITRE ATT&CK's STIX 2.1 relationship data. True and True-Alias claims carry a sourced evidence URL. |
| `week2_entailment_results.csv` | What the notebook produces: predictions per claim (with and without retrieval) next to the gold labels. |
| `CTI_Attribution_Dataset_Week1_v2.xlsx` | The fuller workbook from the dataset-building stage: the claims, the group-technique ground truth pulled from ATT&CK, group/alias summaries, and an alias lookup table. |
| `link_check_results.csv`, `link_check_summary.csv` | How I checked that the evidence URLs were not dead: automated HTTP checks plus my own notes where I verified links manually. |
| `extract_groups_techniques.py` | Pulls group-technique relationships out of the raw ATT&CK STIX bundle. |
| `generate_claim_seeds.py` | Generates the first-pass template claims, before real evidence was filled in. |
| `fill_evidence_and_claims.py` | Turns those templates into the final claims with sourced evidence. |
| `check_links.py` | Script used to flag dead evidence links. |

## About the dataset

Columns in `attribution_claims_final_v2.csv`:

- `claim_id`: unique ID (C0001 to C0085)
- `label`: the gold category (TRUE, TRUE-ALIAS, FALSE-SWAP, UNSURE, FALSE-FAB)
- `claim_text`: the attribution claim in natural language
- `group_name`, `technique_name`, `technique_attack_id`, `group_attack_id`: the ATT&CK group and technique the claim refers to
- `evidence_report`: a source URL for TRUE and TRUE-ALIAS claims; for the other classes, explanatory text (no URL)
- `notes`, `validated_by`, `validation_notes`: how the claim was put together and checked

### Labeling note

All labels were assigned by a single author. True, True-Alias and False-Swap labels follow MITRE ATT&CK STIX relationships; Unsure and False-Fabricated claims were written manually. No second annotator was used, so no inter-annotator agreement is reported.

Seven of the ten Unsure claims (C0069 to C0075) reword relationships that ATT&CK does document as hedged statements, with no separate hedged source attached. For these claims the Unsure label reflects the hedged wording of the claim, not a gap in ATT&CK.

## How to run it

1. Open `CTI_Entailment_Pipeline.ipynb` in Google Colab.
2. Run the first cell to install what it needs (transformers, torch, trafilatura, scikit-learn, pandas, openpyxl).
3. When it asks for a file, upload `attribution_claims_final_v2.csv`.
4. Run the rest of the cells in order. It retrieves evidence, scores entailment, and computes accuracy and results.
5. At the end it saves and downloads `week2_entailment_results.csv`.

## What I found

| System | Accuracy |
|---|---|
| Retrieval + Entailment | 14.1% (12/85) |
| No-Retrieval Baseline | 11.8% (10/85) |

Both numbers are low, below the 33.3% chance level for three labels. When I looked into why: of the 40 True/True-Alias claims, retrieval failed to find usable evidence for only 11. For the other 29, the correct evidence was retrieved, and the entailment model still got 27 of those wrong. So the main bottleneck is not retrieval. The entailment model struggles to match messy, free-form CTI report text to a structured attribution claim, even when it has the right evidence in front of it. That motivates the next stage of my dissertation, where I bring in Logic Tensor Networks to reason over the ATT&CK graph directly, instead of relying on one entailment score.

## Citing this

J. K. Shriwas, "Entailment-Based Verification of LLM-Generated Threat Actor Attribution Claims: A Dataset and Baseline Study," 2026.

## Questions

Feel free to reach out: Jyoti K. Shriwas, jyoti27shriwas@gmail.com
Feel free to reach out — Jyoti K. Shriwas, jyoti27shriwas@gmail.com
