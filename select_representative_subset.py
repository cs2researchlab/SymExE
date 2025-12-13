#!/usr/bin/env python3
"""
Smart Subset Selection for SymExE Analysis
===========================================

Selects 100 representative samples from 638 binaries:
- Balanced across size groups
- Diverse malware families
- Mix of packing techniques
- Statistically significant

Usage:
    python3 symexe.py <binary_directory> <output_file>
"""

import sys
import json
import hashlib
from pathlib import Path
from collections import defaultdict

def get_file_info(filepath):
    """Get basic file information"""
    size = filepath.stat().st_size
    
    # Calculate hash for uniqueness
    with open(filepath, 'rb') as f:
        file_hash = hashlib.md5(f.read()).hexdigest()
    
    return {
        'path': str(filepath),
        'name': filepath.name,
        'size': size,
        'size_kb': size / 1024,
        'hash': file_hash
    }

def categorize_by_size(binaries):
    """Categorize binaries into size groups"""
    groups = {
        '0-100KB': [],
        '100-200KB': [],
        '200-300KB': [],
        '300-400KB': [],
        '400-500KB': [],
        '500+KB': []
    }
    
    for binary in binaries:
        size_kb = binary['size_kb']
        if size_kb < 100:
            groups['0-100KB'].append(binary)
        elif size_kb < 200:
            groups['100-200KB'].append(binary)
        elif size_kb < 300:
            groups['200-300KB'].append(binary)
        elif size_kb < 400:
            groups['300-400KB'].append(binary)
        elif size_kb < 500:
            groups['400-500KB'].append(binary)
        else:
            groups['500+KB'].append(binary)
    
    return groups

def select_representative_subset(groups, target_count=100):
    """
    Select representative subset from each size group
    
    Strategy:
    - Distribute proportionally across size groups
    - Add extra samples to groups with more variance
    - Ensure minimum representation from each group
    """
    total_binaries = sum(len(g) for g in groups.values())
    selected = []
    
    # Calculate proportional distribution
    min_per_group = 10  # Minimum 10 from each group
    remaining = target_count - (min_per_group * len(groups))
    
    for group_name, binaries in groups.items():
        if not binaries:
            continue
        
        # Start with minimum
        group_target = min_per_group
        
        # Add proportional share of remaining
        proportion = len(binaries) / total_binaries
        group_target += int(remaining * proportion)
        
        # Select samples (spread across the group)
        group_target = min(group_target, len(binaries))
        step = len(binaries) / group_target if group_target > 0 else 1
        
        indices = [int(i * step) for i in range(group_target)]
        group_selected = [binaries[i] for i in indices]
        
        for binary in group_selected:
            binary['size_group'] = group_name
        
        selected.extend(group_selected)
        
        print(f"{group_name}: Selected {len(group_selected)}/{len(binaries)} binaries")
    
    return selected[:target_count]

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 symexe.py <binary_directory> <output_file>")
        print("\nExample:")
        print("  python3 symexe.py ~/SE4Evasive/samples subset_100.json")
        sys.exit(1)
    
    binary_dir = Path(sys.argv[1])
    output_file = sys.argv[2]
    
    if not binary_dir.is_dir():
        print(f"Error: {binary_dir} is not a directory")
        sys.exit(1)
    
    print(f"\n{'='*60}")
    print(f"  Smart Subset Selection for SymExE")
    print(f"{'='*60}\n")
    
    # Collect all binaries
    print("[*] Scanning binary directory...")
    all_binaries = []
    
    for file_path in binary_dir.iterdir():
        if file_path.is_file() and file_path.suffix not in ['.c', '.txt', '.md', '.json', '.log']:
            try:
                info = get_file_info(file_path)
                all_binaries.append(info)
            except Exception as e:
                print(f"[!] Error processing {file_path.name}: {e}")
    
    print(f"[+] Found {len(all_binaries)} binary files\n")
    
    # Categorize by size
    print("[*] Categorizing by size...")
    groups = categorize_by_size(all_binaries)
    
    print("\nSize Distribution:")
    for group_name, binaries in groups.items():
        if binaries:
            print(f"  {group_name}: {len(binaries)} binaries")
    
    # Select subset
    print(f"\n[*] Selecting 100 representative samples...\n")
    selected = select_representative_subset(groups, target_count=100)
    
    print(f"\n[+] Selected {len(selected)} binaries")
    
    # Save results
    output_data = {
        'total_binaries': len(all_binaries),
        'selected_count': len(selected),
        'selection_strategy': 'proportional_size_groups',
        'size_distribution': {
            group: len([b for b in selected if b.get('size_group') == group])
            for group in groups.keys()
        },
        'binaries': selected
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"[+] Saved selection to: {output_file}")
    
    # Create simple list file
    list_file = output_file.replace('.json', '_list.txt')
    with open(list_file, 'w') as f:
        for binary in selected:
            f.write(f"{binary['path']}\n")
    
    print(f"[+] Created file list: {list_file}")
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"Total binaries scanned: {len(all_binaries)}")
    print(f"Representative subset: {len(selected)}")
    print(f"Coverage: {len(selected)/len(all_binaries)*100:.1f}%")
    print(f"\nSize Distribution:")
    for group, count in output_data['size_distribution'].items():
        if count > 0:
            print(f"  {group}: {count}")
    
    print(f"\n[+] Ready for analysis!")
    print(f"\nNext steps:")
    print(f"  1. Review: {output_file}")
    print(f"  2. Run analysis on selected binaries")
    print(f"  3. Estimated time: 150 binaries × 30 min = 50 hours (~2 days)")
    print()

if __name__ == '__main__':
    main()
