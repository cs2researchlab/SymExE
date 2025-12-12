#!/usr/bin/env python3
"""
Statistical Analysis for IEEE CCWC 2026 Camera-Ready Revisions

Addresses Reviewer 3's concerns about statistical rigor by calculating:
- Pearson correlation coefficient (binary size vs SE difficulty)
- One-way ANOVA across size groups
- 95% confidence intervals
- Effect sizes
- P-values for all tests

Usage:
    python3 statistical_analysis.py aggregate_results.csv
"""

import pandas as pd
import numpy as np
from scipy import stats
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import sys


def calculate_correlation(df):
    """
    Calculate Pearson correlation between binary size and states-to-paths ratio.
    
    Addresses Reviewer 3: "If you want to claim 'no relationship between size 
    and solver strain,' you need to show me the numbers that back that up. 
    What's the p-value?"
    """
    print("=" * 80)
    print("PEARSON CORRELATION ANALYSIS")
    print("=" * 80)
    
    # Extract relevant columns
    size_kb = df['binary_size'] / 1024  # Convert to KB
    states_to_paths = df['states_to_paths_ratio']
    
    # Calculate Pearson correlation
    r, p_value = stats.pearsonr(size_kb, states_to_paths)
    
    print(f"\nBinary Size vs. States-to-Paths Ratio:")
    print(f"  Pearson r = {r:.4f}")
    print(f"  p-value = {p_value:.4f}")
    
    # Interpret result
    if p_value > 0.05:
        print(f"  Result: NO significant correlation (p > 0.05)")
        print(f"  Conclusion: Binary size does NOT predict SE difficulty")
    else:
        print(f"  Result: Significant correlation found (p < 0.05)")
    
    # Effect size interpretation (Cohen's guidelines)
    effect = abs(r)
    if effect < 0.1:
        interpretation = "negligible"
    elif effect < 0.3:
        interpretation = "small"
    elif effect < 0.5:
        interpretation = "medium"
    else:
        interpretation = "large"
    
    print(f"  Effect size: {interpretation} (|r| = {effect:.4f})")
    
    return r, p_value


def perform_anova(df):
    """
    One-way ANOVA across size groups to test for differences in mean 
    states-to-paths ratios.
    
    Addresses Reviewer 3: "No correlation coefficients, no confidence intervals, 
    no significance testing"
    """
    print("\n" + "=" * 80)
    print("ONE-WAY ANOVA ACROSS SIZE GROUPS")
    print("=" * 80)
    
    # Create size groups (from paper)
    df['size_group'] = pd.cut(
        df['binary_size'] / 1024,  # Convert to KB
        bins=[0, 100, 200, 300, 400, 500],
        labels=['0-100KB', '100-200KB', '200-300KB', '300-400KB', '400-500KB']
    )
    
    # Group data
    groups = [group['states_to_paths_ratio'].values 
              for name, group in df.groupby('size_group')]
    
    # Perform ANOVA
    f_stat, p_value = stats.f_oneway(*groups)
    
    print(f"\nANOVA Results:")
    print(f"  F-statistic = {f_stat:.4f}")
    print(f"  p-value = {p_value:.4f}")
    
    if p_value > 0.05:
        print(f"  Result: NO significant difference across size groups (p > 0.05)")
        print(f"  Conclusion: Size groups have similar SE difficulty")
    else:
        print(f"  Result: Significant difference found (p < 0.05)")
    
    # Calculate effect size (eta-squared)
    # η² = SS_between / SS_total
    grand_mean = df['states_to_paths_ratio'].mean()
    ss_between = sum([len(g) * (g.mean() - grand_mean)**2 for g in groups])
    ss_total = sum([(x - grand_mean)**2 for g in groups for x in g])
    eta_squared = ss_between / ss_total if ss_total > 0 else 0
    
    print(f"  Effect size (η²) = {eta_squared:.4f}")
    
    # Interpret eta-squared
    if eta_squared < 0.01:
        interpretation = "negligible"
    elif eta_squared < 0.06:
        interpretation = "small"
    elif eta_squared < 0.14:
        interpretation = "medium"
    else:
        interpretation = "large"
    
    print(f"  Effect interpretation: {interpretation}")
    
    return f_stat, p_value, eta_squared, df


def calculate_confidence_intervals(df):
    """
    Calculate 95% confidence intervals for mean states-to-paths ratio 
    per size group.
    
    Addresses Reviewer 3: "No confidence intervals"
    """
    print("\n" + "=" * 80)
    print("95% CONFIDENCE INTERVALS BY SIZE GROUP")
    print("=" * 80)
    
    results = []
    
    for name, group in df.groupby('size_group'):
        data = group['states_to_paths_ratio'].values
        n = len(data)
        mean = np.mean(data)
        std = np.std(data, ddof=1)
        se = std / np.sqrt(n)
        
        # 95% CI using t-distribution
        ci = stats.t.interval(0.95, n-1, loc=mean, scale=se)
        
        print(f"\n{name}:")
        print(f"  n = {n}")
        print(f"  Mean = {mean:.2f}")
        print(f"  SD = {std:.2f}")
        print(f"  95% CI = [{ci[0]:.2f}, {ci[1]:.2f}]")
        
        results.append({
            'size_group': name,
            'n': n,
            'mean': mean,
            'sd': std,
            'ci_lower': ci[0],
            'ci_upper': ci[1]
        })
    
    return pd.DataFrame(results)


def create_visualizations(df, ci_df, output_dir='figures'):
    """
    Create publication-quality visualizations with statistical annotations.
    """
    print("\n" + "=" * 80)
    print("GENERATING VISUALIZATIONS")
    print("=" * 80)
    
    Path(output_dir).mkdir(exist_ok=True)
    
    # Set publication style
    sns.set_style("whitegrid")
    plt.rcParams['figure.dpi'] = 300
    plt.rcParams['font.size'] = 10
    
    # Figure 1: Scatter plot with regression line and correlation
    fig, ax = plt.subplots(figsize=(6, 4))
    
    size_kb = df['binary_size'] / 1024
    ratio = df['states_to_paths_ratio']
    
    # Scatter points
    ax.scatter(size_kb, ratio, alpha=0.6, s=50, label='Samples')
    
    # Regression line
    z = np.polyfit(size_kb, ratio, 1)
    p = np.poly1d(z)
    x_line = np.linspace(size_kb.min(), size_kb.max(), 100)
    ax.plot(x_line, p(x_line), 'r--', alpha=0.8, label='Linear fit')
    
    # Add correlation text
    r, p_val = stats.pearsonr(size_kb, ratio)
    ax.text(0.05, 0.95, f'r = {r:.3f}, p = {p_val:.3f}',
            transform=ax.transAxes, va='top',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    ax.set_xlabel('Binary Size (KB)')
    ax.set_ylabel('States-to-Paths Ratio')
    ax.set_title('Binary Size vs. Symbolic Execution Difficulty')
    ax.legend()
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/size_vs_difficulty_scatter.png')
    print(f"  ✓ Saved: {output_dir}/size_vs_difficulty_scatter.png")
    
    # Figure 2: Box plot with confidence intervals
    fig, ax = plt.subplots(figsize=(8, 5))
    
    # Box plot
    df.boxplot(column='states_to_paths_ratio', by='size_group', ax=ax)
    
    # Add mean and CI as error bars
    positions = range(1, len(ci_df) + 1)
    ax.errorbar(positions, ci_df['mean'],
                yerr=[ci_df['mean'] - ci_df['ci_lower'],
                      ci_df['ci_upper'] - ci_df['mean']],
                fmt='ro', markersize=8, capsize=5, capthick=2,
                label='Mean ± 95% CI')
    
    ax.set_xlabel('Size Group')
    ax.set_ylabel('States-to-Paths Ratio')
    ax.set_title('SE Difficulty Across Binary Size Groups')
    plt.suptitle('')  # Remove default title
    ax.legend()
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/size_groups_boxplot.png')
    print(f"  ✓ Saved: {output_dir}/size_groups_boxplot.png")
    
    plt.close('all')


def generate_latex_table(ci_df):
    """
    Generate LaTeX table for paper inclusion.
    """
    print("\n" + "=" * 80)
    print("LATEX TABLE FOR PAPER")
    print("=" * 80)
    
    print("\n% Copy this into your paper's Results section:")
    print("\\begin{table}[h]")
    print("\\centering")
    print("\\caption{Descriptive Statistics and 95\\% Confidence Intervals by Size Group}")
    print("\\begin{tabular}{lcccc}")
    print("\\hline")
    print("Size Group & n & Mean & SD & 95\\% CI \\\\")
    print("\\hline")
    
    for _, row in ci_df.iterrows():
        print(f"{row['size_group']} & {row['n']} & "
              f"{row['mean']:.2f} & {row['sd']:.2f} & "
              f"[{row['ci_lower']:.2f}, {row['ci_upper']:.2f}] \\\\")
    
    print("\\hline")
    print("\\end{tabular}")
    print("\\label{tab:statistics}")
    print("\\end{table}")


def generate_paper_text(r, p_corr, f_stat, p_anova, eta_sq):
    """
    Generate text to add to paper Results section.
    """
    print("\n" + "=" * 80)
    print("TEXT FOR PAPER RESULTS SECTION")
    print("=" * 80)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 statistical_analysis.py <aggregate_csv>")
        print("\nExample:")
        print("  python3 statistical_analysis.py results/aggregate.csv")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    
    print(f"\nLoading data from: {csv_file}")
    df = pd.read_csv(csv_file)
    
    print(f"Loaded {len(df)} samples\n")
    
    # Perform all statistical tests
    r, p_corr = calculate_correlation(df)
    f_stat, p_anova, eta_sq, df = perform_anova(df)
    ci_df = calculate_confidence_intervals(df)
    
    # Generate visualizations
    create_visualizations(df, ci_df)
    
    # Generate paper materials
    generate_latex_table(ci_df)
    generate_paper_text(r, p_corr, f_stat, p_anova, eta_sq)
    
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print("\nNext steps:")
    print("  1. Review generated figures in figures/ directory")
    print("  2. Copy LaTeX table into paper")
    print("  3. Copy results text into paper Results section")
    print("  4. Update figure references in paper")


if __name__ == "__main__":
    main()
