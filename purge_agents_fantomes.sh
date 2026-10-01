#!/usr/bin/env bash
#
# Purge les documents de wazuh-states-vulnerabilities-* dont l'agent.id ne
# correspond plus à aucun agent enregistré dans le manager Wazuh.
#
# Cause : un agent supprimé ou ré-enrôlé sous un nouvel ID laisse ses
# anciennes données de vulnérabilité dans l'indexer — rien côté Wazuh ne
# les purge automatiquement.
#
# Usage :
#   ./purge_agents_fantomes.sh --dry-run     # affiche ce qui serait supprimé, ne touche à rien
#   ./purge_agents_fantomes.sh --apply       # supprime réellement
#
# Variables d'environnement (surchargent les valeurs par défaut) :
#   COMPOSE_FILE       chemin du docker-compose.yml Wazuh
#                       (défaut: /kev/single-node/docker-compose.yml)
#   MANAGER_CONTAINER   nom du conteneur manager (défaut: single-node-wazuh-manager-1)
#   INDEXER_URL         URL de l'indexer (défaut: https://localhost:9200)

set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-/kev/single-node/docker-compose.yml}"
MANAGER_CONTAINER="${MANAGER_CONTAINER:-single-node-wazuh-manager-1}"
INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"

MODE="${1:-}"
if [[ "$MODE" != "--dry-run" && "$MODE" != "--apply" ]]; then
    echo "Usage: $0 --dry-run|--apply" >&2
    exit 1
fi

if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "Fichier compose introuvable : $COMPOSE_FILE" >&2
    exit 1
fi

INDEXER_USER=$(awk -F= '/INDEXER_USERNAME=/{print $2; exit}' "$COMPOSE_FILE" | tr -d "[:space:]'\"")
INDEXER_PASS=$(awk -F= '/INDEXER_PASSWORD=/{print $2; exit}' "$COMPOSE_FILE" | tr -d "[:space:]'\"")

if [[ -z "$INDEXER_USER" || -z "$INDEXER_PASS" ]]; then
    echo "Impossible de lire INDEXER_USERNAME/INDEXER_PASSWORD dans $COMPOSE_FILE" >&2
    exit 1
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"; unset INDEXER_USER INDEXER_PASS' EXIT

# --- 1. Agents actuellement enregistrés côté manager ---
docker exec "$MANAGER_CONTAINER" /var/ossec/bin/agent_control -l 2>&1 \
    | grep -oE "ID: [0-9]+" | awk '{print $2}' | sort -u > "$TMP_DIR/agents_actuels.txt"

NB_ACTUELS=$(wc -l < "$TMP_DIR/agents_actuels.txt")
if [[ "$NB_ACTUELS" -eq 0 ]]; then
    echo "Aucun agent lu depuis le manager — arrêt par sécurité (évite de tout considérer comme orphelin)." >&2
    exit 1
fi

# --- 2. Tous les agent.id présents dans l'index de vulnérabilités ---
curl -sS -k -u "${INDEXER_USER}:${INDEXER_PASS}" -X POST \
    "${INDEXER_URL}/wazuh-states-vulnerabilities-*/_search" \
    -H 'Content-Type: application/json' \
    -d '{"size":0,"aggs":{"par_agent":{"terms":{"field":"agent.id","size":2000}}}}' \
    > "$TMP_DIR/agg_agents.json"

# --- 3. Calcul des orphelins (dans l'index, absents du manager) ---
python3 - "$TMP_DIR/agg_agents.json" "$TMP_DIR/agents_actuels.txt" "$TMP_DIR/orphelins.json" <<'PYEOF'
import json, sys

agg_path, actuels_path, out_path = sys.argv[1:4]

d = json.load(open(agg_path))
buckets = d.get("aggregations", {}).get("par_agent", {}).get("buckets", [])
total_index = sum(b["doc_count"] for b in buckets)

actuels = set(l.strip() for l in open(actuels_path) if l.strip())
orphelins = [(b["key"], b["doc_count"]) for b in buckets if b["key"] not in actuels]

vol_orphelin = sum(c for _, c in orphelins)
print(f"Agents dans l'index vulnérabilités : {len(buckets)}")
print(f"Agents actuellement enregistrés    : {len(actuels)}")
print(f"Agent.id orphelins                 : {len(orphelins)}")
if total_index:
    print(f"Documents concernés                : {vol_orphelin:,} / {total_index:,} ({100*vol_orphelin/total_index:.1f}%)")

json.dump([aid for aid, _ in orphelins], open(out_path, "w"))
PYEOF

NB_ORPHELINS=$(python3 -c "import json; print(len(json.load(open('$TMP_DIR/orphelins.json'))))")

if [[ "$NB_ORPHELINS" -eq 0 ]]; then
    echo "Rien à purger."
    exit 0
fi

if [[ "$MODE" == "--dry-run" ]]; then
    echo
    echo "Dry-run : rien n'a été supprimé. Relancer avec --apply pour purger."
    exit 0
fi

# --- 4. Suppression effective (asynchrone, on attend la fin) ---
BODY=$(python3 -c "
import json
ids = json.load(open('$TMP_DIR/orphelins.json'))
print(json.dumps({'query': {'terms': {'agent.id': ids}}}))
")

echo
echo "Lancement de la suppression de $NB_ORPHELINS agent.id orphelins..."

TASK_JSON=$(curl -sS -k -u "${INDEXER_USER}:${INDEXER_PASS}" -X POST \
    "${INDEXER_URL}/wazuh-states-vulnerabilities-*/_delete_by_query?conflicts=proceed&wait_for_completion=false&slices=auto" \
    -H 'Content-Type: application/json' -d "$BODY")

TASK_ID=$(echo "$TASK_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['task'])")
echo "Tâche indexer : $TASK_ID"

# --- 5. Attente de la fin de la tâche ---
while true; do
    STATUS=$(curl -sS -k -u "${INDEXER_USER}:${INDEXER_PASS}" "${INDEXER_URL}/_tasks/${TASK_ID}")
    DONE=$(echo "$STATUS" | python3 -c "import json,sys; print(json.load(sys.stdin).get('completed', False))")
    if [[ "$DONE" == "True" ]]; then
        echo "$STATUS" | python3 -c "
import json, sys
d = json.load(sys.stdin)
s = d['response']
print(f\"Terminé : {s['deleted']:,} documents supprimés, {len(s['failures'])} échec(s).\")
if s['failures']:
    for f in s['failures'][:10]:
        print(' -', f)
"
        break
    fi
    sleep 15
done

echo
echo "=== Décompte final de l'index ==="
curl -sS -k -u "${INDEXER_USER}:${INDEXER_PASS}" \
    "${INDEXER_URL}/_cat/indices/wazuh-states-vulnerabilities*?v&h=index,docs.count,store.size"
