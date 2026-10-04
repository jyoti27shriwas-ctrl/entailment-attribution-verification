"""
Generate a seed set of True/False/Unsure attribution claims from the
Group-Technique ground truth, to bootstrap manual dataset construction.

Claim types:
  TRUE    - "<Group> has used <Technique>" where relationship exists in ATT&CK (verbatim from data)
  TRUE-ALIAS - same as TRUE but phrased using an alias instead of canonical name (tests alias resolution)
  FALSE-SWAP - "<Group> has used <Technique>" where Technique is real but NOT linked to that Group
               (drawn from a technique used by a *different* group, to keep it plausible)
  FALSE-FAB  - a claim linking a group to a technique that doesn't exist / is misattributed
  UNSURE     - a vaguer/hedged claim that isn't clearly confirmable from a single relationship
               (e.g., attributed only via a single low-confidence secondary-source citation,
               or a claim about a capability without a direct 'uses' edge)

This script produces well-validated TRUE, TRUE-ALIAS, and FALSE-SWAP claims
programmatically (grounded in real STIX data) and leaves FALSE-FAB / UNSURE
rows as templates for manual authoring, since those require human judgment
about what's genuinely ambiguous vs. fabricated.
"""
import csv
import random

random.seed(42)

# Load ground truth
with open("group_technique_ground_truth.csv", encoding="utf-8") as f:
    gt_rows = list(csv.DictReader(f))

# Load aliases (exclude self-rows where alias == canonical_name)
with open("group_aliases.csv", encoding="utf-8") as f:
    alias_rows = [r for r in csv.DictReader(f) if r["alias"] != r["canonical_name"]]

alias_by_group = {}
for r in alias_rows:
    alias_by_group.setdefault(r["canonical_name"], []).append(r["alias"])

# Only keep groups that appear in ground truth relationships (so we know their techniques)
groups_with_techniques = {}
for row in gt_rows:
    groups_with_techniques.setdefault(row["group_name"], []).append(row)

group_names = list(groups_with_techniques.keys())

claims = []
claim_id = 1

def add_claim(label, claim_text, group_name, technique_name, technique_id, group_id, notes):
    global claim_id
    claims.append({
        "claim_id": f"C{claim_id:04d}",
        "label": label,
        "claim_text": claim_text,
        "group_name": group_name,
        "technique_name": technique_name,
        "technique_attack_id": technique_id,
        "group_attack_id": group_id,
        "notes": notes,
        "evidence_report": "",     # fill in manually: CTI report / source used as retrieval evidence
        "validated_by": "",        # fill in manually: annotator name/initials
        "validation_notes": "",
    })
    claim_id += 1

# --- TRUE claims: sample real relationships, phrase as natural-language attribution claims ---
n_true = 25
true_sample = random.sample(gt_rows, min(n_true, len(gt_rows)))
for row in true_sample:
    text = f"{row['group_name']} has used the technique \"{row['technique_name']}\" ({row['technique_attack_id']})."
    add_claim("TRUE", text, row["group_name"], row["technique_name"],
              row["technique_attack_id"], row["group_attack_id"],
              "Directly grounded in ATT&CK 'uses' relationship")

# --- TRUE-ALIAS claims: same as above but use an alias name for the group ---
n_true_alias = 15
groups_with_aliases = [g for g in group_names if g in alias_by_group and alias_by_group[g]]
alias_sample_groups = random.sample(groups_with_aliases, min(n_true_alias, len(groups_with_aliases)))
for g in alias_sample_groups:
    row = random.choice(groups_with_techniques[g])
    alias = random.choice(alias_by_group[g])
    text = f"{alias} has used the technique \"{row['technique_name']}\" ({row['technique_attack_id']})."
    add_claim("TRUE-ALIAS", text, row["group_name"], row["technique_name"],
              row["technique_attack_id"], row["group_attack_id"],
              f"Canonical name is '{row['group_name']}'; claim uses alias '{alias}' — tests alias resolution")

# --- FALSE-SWAP claims: take a technique used by Group A, falsely attribute to Group B (who doesn't use it) ---
n_false_swap = 25
technique_users = {}  # technique_id -> set of group names that use it
for row in gt_rows:
    technique_users.setdefault(row["technique_attack_id"], set()).add(row["group_name"])

false_count = 0
attempts = 0
while false_count < n_false_swap and attempts < 2000:
    attempts += 1
    row = random.choice(gt_rows)
    tid = row["technique_attack_id"]
    tname = row["technique_name"]
    true_users = technique_users.get(tid, set())
    candidate_group = random.choice(group_names)
    if candidate_group in true_users:
        continue  # would accidentally be true
    text = f"{candidate_group} has used the technique \"{tname}\" ({tid})."
    add_claim("FALSE-SWAP", text, candidate_group, tname, tid, "",
              f"Technique is real and used by other groups (e.g. {row['group_name']}) but NOT documented for {candidate_group} in ATT&CK")
    false_count += 1

# --- UNSURE + FALSE-FAB templates: manual-authoring placeholders ---
unsure_templates = [
    "It has been suggested that {group} may have experimented with {technique}-style tradecraft, though this is not confirmed in public reporting.",
    "{group} is believed by some researchers to be linked to {technique}, based on partial infrastructure overlap.",
    "A single low-confidence vendor report attributes possible use of {technique} to {group}.",
]
for i in range(10):
    g = random.choice(group_names)
    row = random.choice(groups_with_techniques[g])
    tmpl = random.choice(unsure_templates)
    text = tmpl.format(group=g, technique=row["technique_name"])
    add_claim("UNSURE-TEMPLATE", text, g, row["technique_name"], row["technique_attack_id"], row["group_attack_id"],
               "TEMPLATE — needs manual review: find/attach a genuinely ambiguous or single-low-confidence-source CTI report as evidence")

for i in range(10):
    g = random.choice(group_names)
    fake_tid = "T9999" + str(i)
    text = f"{g} has used a technique called \"{fake_tid}\" which does not correspond to any real MITRE ATT&CK technique."
    add_claim("FALSE-FAB-TEMPLATE", text, g, "N/A (fabricated)", fake_tid, "",
               "TEMPLATE — needs manual review: replace with a plausible-sounding but fabricated/misattributed claim, ideally mirroring a real hallucination pattern from an LLM output")

# --- Write output ---
fieldnames = ["claim_id", "label", "claim_text", "group_name", "technique_name",
              "technique_attack_id", "group_attack_id", "notes",
              "evidence_report", "validated_by", "validation_notes"]
with open("attribution_claims_seed.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(claims)

print(f"Total seed claims generated: {len(claims)}")
from collections import Counter
print(Counter(c["label"] for c in claims))
