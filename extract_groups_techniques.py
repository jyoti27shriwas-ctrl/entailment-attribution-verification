"""
Extract Group-Technique ground truth + alias-resolution table from MITRE ATT&CK
Enterprise STIX 2.1 bundle.

Output files:
  - group_technique_ground_truth.csv : one row per (Group, Technique) relationship
  - group_aliases.csv                : one row per (canonical group name, alias)
  - groups_summary.csv               : one row per group with all aliases joined
"""
import json
import csv
from collections import defaultdict

with open("enterprise-attack.json", "r", encoding="utf-8") as f:
    bundle = json.load(f)

objects = bundle["objects"]

# Index objects by STIX id and by type
by_id = {}
intrusion_sets = []   # ATT&CK "Groups"
attack_patterns = []  # ATT&CK "Techniques" (and sub-techniques)
relationships = []
malware_tools = []

for obj in objects:
    obj_id = obj.get("id")
    if obj_id:
        by_id[obj_id] = obj
    otype = obj.get("type")
    if otype == "intrusion-set":
        intrusion_sets.append(obj)
    elif otype == "attack-pattern":
        attack_patterns.append(obj)
    elif otype == "relationship":
        relationships.append(obj)
    elif otype in ("malware", "tool"):
        malware_tools.append(obj)

def is_revoked_or_deprecated(obj):
    return obj.get("revoked", False) or obj.get("x_mitre_deprecated", False)

def get_attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None

def get_url(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None

# ---- 1. Build group alias table ----
groups_summary_rows = []
alias_rows = []
group_name_by_id = {}

for g in intrusion_sets:
    if is_revoked_or_deprecated(g):
        continue
    gid = g["id"]
    canonical = g["name"]
    group_name_by_id[gid] = canonical
    aliases = g.get("aliases", [])
    # aliases list from MITRE includes the canonical name itself sometimes; dedupe
    alias_set = sorted(set(a for a in aliases if a != canonical))
    attack_id = get_attack_id(g)
    url = get_url(g)
    groups_summary_rows.append({
        "attack_id": attack_id,
        "canonical_name": canonical,
        "aliases": "; ".join(alias_set),
        "num_aliases": len(alias_set),
        "url": url,
    })
    for a in alias_set:
        alias_rows.append({"canonical_name": canonical, "alias": a, "attack_id": attack_id})
    # also map canonical name to itself for lookup convenience
    alias_rows.append({"canonical_name": canonical, "alias": canonical, "attack_id": attack_id})

# ---- 2. Build technique lookup ----
technique_name_by_id = {}
technique_meta_by_id = {}
for t in attack_patterns:
    if is_revoked_or_deprecated(t):
        continue
    tid = t["id"]
    technique_name_by_id[tid] = t["name"]
    technique_meta_by_id[tid] = {
        "attack_id": get_attack_id(t),
        "name": t["name"],
        "is_subtechnique": t.get("x_mitre_is_subtechnique", False),
        "url": get_url(t),
        "description": (t.get("description") or "").split("\n")[0][:300],  # first line, truncated
    }

# ---- 3. Walk relationships: intrusion-set --uses--> attack-pattern ----
gt_rows = []
for r in relationships:
    if is_revoked_or_deprecated(r):
        continue
    if r.get("relationship_type") != "uses":
        continue
    src = r.get("source_ref", "")
    tgt = r.get("target_ref", "")
    if not src.startswith("intrusion-set--") or not tgt.startswith("attack-pattern--"):
        continue
    if src not in group_name_by_id or tgt not in technique_meta_by_id:
        continue
    group_name = group_name_by_id[src]
    tmeta = technique_meta_by_id[tgt]
    # source citation(s) for this relationship, if present
    ext_refs = r.get("external_references", [])
    source_names = "; ".join(sorted(set(
        e.get("source_name", "") for e in ext_refs if e.get("source_name") not in (None, "mitre-attack")
    )))
    desc = (r.get("description") or "").replace("\n", " ").strip()[:400]
    gt_rows.append({
        "group_attack_id": get_attack_id(by_id[src]),
        "group_name": group_name,
        "technique_attack_id": tmeta["attack_id"],
        "technique_name": tmeta["name"],
        "is_subtechnique": tmeta["is_subtechnique"],
        "relationship_description": desc,
        "citation_sources": source_names,
        "technique_url": tmeta["url"],
        "group_url": get_url(by_id[src]),
    })

# ---- Write outputs ----
with open("group_technique_ground_truth.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(gt_rows[0].keys()))
    w.writeheader()
    w.writerows(gt_rows)

with open("group_aliases.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["canonical_name", "alias", "attack_id"])
    w.writeheader()
    w.writerows(alias_rows)

with open("groups_summary.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["attack_id", "canonical_name", "aliases", "num_aliases", "url"])
    w.writeheader()
    w.writerows(groups_summary_rows)

print(f"Groups (intrusion-sets, non-deprecated): {len(groups_summary_rows)}")
print(f"Techniques (attack-patterns, non-deprecated): {len(technique_meta_by_id)}")
print(f"Group-Technique 'uses' relationships: {len(gt_rows)}")
print(f"Alias rows (incl. canonical self-rows): {len(alias_rows)}")

# Quick sanity peek at a well-known group
for row in groups_summary_rows:
    if "APT28" in row["canonical_name"] or "APT28" in row["aliases"]:
        print("\nSample group record:", row)
        break
