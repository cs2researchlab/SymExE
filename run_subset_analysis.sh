#!/bin/bash
#
# SymExE Fast Subset Analysis
# Analyzes representative samples for Friday deadline
#

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$#" -lt 2 ]; then
    echo -e "${RED}Usage: $0 <subset_list.txt> <output_directory>${NC}"
    echo ""
    echo "Example:"
    echo "  $0 subset_150_list.txt results_150"
    exit 1
fi

SUBSET_LIST="$1"
OUTPUT_DIR="$2"

if [ ! -f "$SUBSET_LIST" ]; then
    echo -e "${RED}[!] Error: Subset list not found: $SUBSET_LIST${NC}"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   SymExE - Fast Subset Analysis (samples)           ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Subset List: ${NC}$SUBSET_LIST"
echo -e "${CYAN}Output Directory: ${NC}$OUTPUT_DIR"
echo ""

# Count binaries
BINARY_COUNT=$(wc -l < "$SUBSET_LIST")
echo -e "${GREEN}[*] Processing $BINARY_COUNT binaries${NC}"

# Settings - OPTIMIZED FOR SPEED
MAX_STATES=2500
TIMEOUT=1800  # 30 minutes (reduced from 75 for faster results)

echo ""
echo -e "${CYAN}[*] Analysis Settings (OPTIMIZED):${NC}"
echo "    Max States: $MAX_STATES"
echo "    Timeout: $TIMEOUT seconds (30 minutes per binary)"
echo "    Est. Total Time: $(($BINARY_COUNT * 30 / 60)) hours"
echo ""

read -p "Start analysis? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

START_TIME=$(date +%s)
COUNT=0
SUCCESS=0
FAILED=0

# Process each binary
while IFS= read -r BINARY; do
    [ -z "$BINARY" ] && continue
    
    if [ ! -f "$BINARY" ]; then
        echo -e "${RED}[!] File not found: $BINARY${NC}"
        FAILED=$((FAILED + 1))
        continue
    fi
    
    COUNT=$((COUNT + 1))
    BASENAME=$(basename "$BINARY")
    
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  [$COUNT/$BINARY_COUNT] $BASENAME${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    
    OUTPUT_FILE="$OUTPUT_DIR/${BASENAME}.json"
    LOG_FILE="$OUTPUT_DIR/${BASENAME}.log"
    
    # Run analysis
    timeout $((TIMEOUT + 60)) python3 symexe.py "$BINARY" \
        --max-states $MAX_STATES \
        --timeout $TIMEOUT \
        --output "$OUTPUT_FILE" > "$LOG_FILE" 2>&1
    
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ] && [ -f "$OUTPUT_FILE" ]; then
        SUCCESS=$((SUCCESS + 1))
        echo -e "${GREEN}[+] SUCCESS${NC}"
        
        # Extract key result
        if command -v jq &> /dev/null; then
            SCORE=$(jq -r '.evasiveness_score // "N/A"' "$OUTPUT_FILE" 2>/dev/null)
            CLASS=$(jq -r '.classification // "N/A"' "$OUTPUT_FILE" 2>/dev/null)
            echo -e "${CYAN}    Score: $SCORE/100 | $CLASS${NC}"
        fi
    else
        FAILED=$((FAILED + 1))
        echo -e "${RED}[!] FAILED (exit code: $EXIT_CODE)${NC}"
    fi
    
    # Progress
    ELAPSED=$(($(date +%s) - START_TIME))
    ELAPSED_HR=$((ELAPSED / 3600))
    ELAPSED_MIN=$(((ELAPSED % 3600) / 60))
    
    if [ $COUNT -gt 0 ]; then
        AVG_TIME=$((ELAPSED / COUNT))
        REMAINING=$((BINARY_COUNT - COUNT))
        EST_REMAINING=$((AVG_TIME * REMAINING))
        EST_HR=$((EST_REMAINING / 3600))
        EST_MIN=$(((EST_REMAINING % 3600) / 60))
        
        echo -e "${CYAN}Progress: $COUNT/$BINARY_COUNT (${SUCCESS} success, ${FAILED} failed)${NC}"
        echo -e "${CYAN}Elapsed: ${ELAPSED_HR}h ${ELAPSED_MIN}m | Est. Remaining: ${EST_HR}h ${EST_MIN}m${NC}"
        
        # Calculate ETA
        ETA_TIMESTAMP=$(($(date +%s) + EST_REMAINING))
        ETA=$(date -d "@$ETA_TIMESTAMP" "+%a %b %d %I:%M %p" 2>/dev/null || date -r $ETA_TIMESTAMP "+%a %b %d %I:%M %p")
        echo -e "${CYAN}ETA: $ETA${NC}"
    fi
    
done < "$SUBSET_LIST"

# Final summary
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))
HOURS=$((TOTAL_TIME / 3600))
MINUTES=$(((TOTAL_TIME % 3600) / 60))

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                   ANALYSIS COMPLETE                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Total Binaries: ${NC}$BINARY_COUNT"
echo -e "${GREEN}Successful: ${NC}$SUCCESS"
echo -e "${RED}Failed: ${NC}$FAILED"
echo -e "${CYAN}Total Time: ${NC}${HOURS}h ${MINUTES}m"
echo -e "${GREEN}Results: ${NC}$OUTPUT_DIR/"
echo ""

# Generate summary
echo -e "${CYAN}[*] Generating summary...${NC}"

python3 - <<EOF
import json
from pathlib import Path

results_dir = Path("$OUTPUT_DIR")
results = []

for json_file in results_dir.glob("*.json"):
    try:
        with open(json_file) as f:
            data = json.load(f)
            results.append({
                'binary': data.get('binary', json_file.stem),
                'classification': data.get('classification', 'UNKNOWN'),
                'score': data.get('evasiveness_score', 0),
                'is_evasive': data.get('is_evasive', False),
                'states': data.get('symbolic_execution_stats', {}).get('states_analyzed', 0),
                'paths': data.get('symbolic_execution_stats', {}).get('paths_explored', 0),
                'constraints': data.get('symbolic_execution_stats', {}).get('constraints_found', 0),
            })
    except Exception as e:
        print(f"[!] Error: {json_file}: {e}")

if results:
    evasive = sum(1 for r in results if r['is_evasive'])
    
    summary = {
        'total_analyzed': len(results),
        'evasive_count': evasive,
        'evasive_percentage': round(evasive / len(results) * 100, 1),
        'average_score': round(sum(r['score'] for r in results) / len(results), 1),
        'average_states': round(sum(r['states'] for r in results) / len(results), 1),
        'average_paths': round(sum(r['paths'] for r in results) / len(results), 1),
        'average_constraints': round(sum(r['constraints'] for r in results) / len(results), 1),
        'classification_distribution': {
            'HIGHLY_EVASIVE': sum(1 for r in results if r['classification'] == 'HIGHLY EVASIVE'),
            'MODERATELY_EVASIVE': sum(1 for r in results if r['classification'] == 'MODERATELY EVASIVE'),
            'MINIMALLY_EVASIVE': sum(1 for r in results if r['classification'] == 'MINIMALLY EVASIVE'),
            'NON_EVASIVE': sum(1 for r in results if r['classification'] == 'NON-EVASIVE'),
        },
        'results': results
    }
    
    with open(results_dir / "SUMMARY.json", 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n{'='*60}")
    print(f"  FINAL RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"Total Analyzed: {len(results)}")
    print(f"Evasive: {evasive} ({evasive/len(results)*100:.1f}%)")
    print(f"Average Score: {summary['average_score']:.1f}/100")
    print(f"Average States: {summary['average_states']:.1f}")
    print(f"Average Paths: {summary['average_paths']:.1f}")
    print(f"Average Constraints: {summary['average_constraints']:.1f}")
    print(f"\nClassification Distribution:")
    for cls, count in summary['classification_distribution'].items():
        pct = count/len(results)*100
        print(f"  {cls.replace('_', ' ')}: {count} ({pct:.1f}%)")
    print(f"\n[+] Summary saved: {results_dir}/SUMMARY.json")
    print()
EOF

echo -e "${GREEN}✓ Analysis complete! Results ready for paper.${NC}"
echo ""
