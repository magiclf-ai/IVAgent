#!/usr/bin/env python3
"""LLM-driven semantic evaluator for testcase results."""

from __future__ import annotations

from pathlib import Path
from typing import List

from tests.eval.test_runner import TestRunResult, format_detection_results_as_markdown
from tests.eval.testcase_format import TestCase


def _response_to_text(response: object) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, list):
        return "\n".join(str(item) for item in content)
    return str(content)


def llm_evaluate_testcase(testcase_md: str, results_md: str, llm: object) -> str:
    """Ask the LLM to evaluate one testcase."""

    prompt = f"""You are evaluating an automated vulnerability detection system.

# Test Case

{testcase_md}

# Detection Results

{results_md}

# Task

Compare the detection results against the expected vulnerabilities in the testcase.
Use semantic matching, not exact string matching.
You MUST write the entire report in Simplified Chinese.
Return a Chinese markdown report only.

Return markdown with these sections:

## Evaluation Summary
- **True Positives**: <count>
- **False Positives**: <count>
- **False Negatives**: <count>
- **Precision**: <percentage>
- **Recall**: <percentage>

## True Positives
For each matched vulnerability:
### TP <n>: <title>
- **Expected**: <brief summary>
- **Detected**: <brief summary>
- **Match Quality**: <excellent/good/partial>
- **Reasoning**: <why they match>

## False Positives
For each unmatched detected vulnerability:
### FP <n>: <title>
- **Detected**: <brief summary>
- **Why False Positive**: <reason>

## False Negatives
For each missed expected vulnerability:
### FN <n>: <title>
- **Expected**: <brief summary>
- **Why Missed**: <reason>

## Overall Assessment
<short assessment>

## Recommendations
<specific improvements>
"""
    return _response_to_text(llm.invoke(prompt))


def llm_evaluate_all(
    testcases: List[TestCase],
    results: List[TestRunResult],
    llm: object,
) -> str:
    """Evaluate all testcase results and generate an aggregate report."""

    results_by_name = {item.testcase_name: item for item in results}
    individual_reports: List[dict[str, str]] = []

    for testcase in testcases:
        result = results_by_name.get(testcase.name)
        if result is None:
            report = (
                "## Evaluation Summary\n\n"
                "- **True Positives**: 0\n"
                "- **False Positives**: 0\n"
                "- **False Negatives**: unknown\n"
                "- **Precision**: 0%\n"
                "- **Recall**: 0%\n\n"
                "## Overall Assessment\n\nNo execution result found for this testcase.\n"
            )
        elif not result.success:
            report = (
                "## Evaluation Summary\n\n"
                "- **True Positives**: 0\n"
                "- **False Positives**: 0\n"
                "- **False Negatives**: unknown\n"
                "- **Precision**: 0%\n"
                "- **Recall**: 0%\n\n"
                f"## Overall Assessment\n\nExecution failed: {result.error}\n"
            )
        else:
            results_md = result.results_markdown or format_detection_results_as_markdown(
                {"vulnerabilities": result.vulnerabilities}
            )
            report = llm_evaluate_testcase(testcase.content, results_md, llm)

        individual_reports.append({"testcase_name": testcase.name, "report": report})

    combined_reports = ["# Individual Test Case Reports", ""]
    for item in individual_reports:
        combined_reports.extend([f"## {item['testcase_name']}", "", item["report"], "", "---", ""])
    combined_md = "\n".join(combined_reports)

    summary_prompt = f"""You are summarizing a multi-testcase vulnerability evaluation.

{combined_md}

# Task

You MUST write the entire report in Simplified Chinese.
Return a Chinese markdown report only.

Produce a markdown summary with:

## Overall Metrics
- **Total Test Cases**: <count>
- **Total True Positives**: <count>
- **Total False Positives**: <count>
- **Total False Negatives**: <count>
- **Overall Precision**: <percentage>
- **Overall Recall**: <percentage>
- **Overall F1 Score**: <percentage>

## Strengths
<what the system does well>

## Weaknesses
<main gaps>

## Priority Improvements
<highest-value next steps>

## Conclusion
<overall maturity and effectiveness>
"""
    summary = _response_to_text(llm.invoke(summary_prompt))
    return "# IVAgent 测评报告\n\n" + summary + "\n\n---\n\n" + combined_md + "\n"


def save_evaluation_report(report: str, output_file: str) -> None:
    """Persist evaluation markdown."""

    Path(output_file).write_text(report, encoding="utf-8")
    print(f"Evaluation report saved to {output_file}")


def load_evaluation_report(report_file: str) -> str:
    """Load a saved evaluation report."""

    return Path(report_file).read_text(encoding="utf-8")
