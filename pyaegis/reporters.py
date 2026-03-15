import json
from typing import IO
from pyaegis.models import ScanResult


class Reporter:
    """Base class for reporting scan results."""

    def __init__(self, output_stream: IO[str]):
        self.output_stream = output_stream

    def report(self, result: ScanResult):
        raise NotImplementedError


class TextReporter(Reporter):
    """Outputs human-readable text."""

    def report(self, result: ScanResult):
        if not result.findings:
            self.output_stream.write(
                "[+] No vulnerabilities detected. Subsystems secure.\n"
            )
            return

        self.output_stream.write(
            f"[-] Detected {len(result.findings)} Potential Vulnerabilities:\n"
        )
        for finding in result.findings:
            self.output_stream.write(
                f"    -> [{finding.severity}] {finding.description} "
                f"({finding.rule_id}) | "
                f"File: {finding.file_path}:{finding.line_number} | "
                f"Context: {finding.sink_context}\n"
            )


class JSONReporter(Reporter):
    """Outputs JSON array of findings."""

    def report(self, result: ScanResult):
        data = {
            "meta": {
                "total_files_scanned": result.total_files,
                "duration_seconds": result.duration_seconds,
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "description": f.description,
                    "file": f.file_path,
                    "line": f.line_number,
                    "severity": f.severity,
                    "context": f.sink_context,
                }
                for f in result.findings
            ],
        }
        json.dump(data, self.output_stream, indent=4)


class SARIFReporter(Reporter):
    """
    Outputs standard SARIF v2.1.0 format natively supported by GitHub.
    """

    def report(self, result: ScanResult):
        run_dict = {
            "tool": {
                "driver": {
                    "name": "PyAegis",
                    "informationUri": "https://github.com/PyAegis/PyAegis",
                    "rules": [],
                }
            },
            "results": [],
        }

        # Populate results
        for idx, finding in enumerate(result.findings):
            run_dict["results"].append(
                {
                    "ruleId": finding.rule_id,
                    "level": (
                        "error" if finding.severity.upper() == "CRITICAL" else "warning"
                    ),
                    "message": {"text": finding.description},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.file_path},
                                "region": {
                                    "startLine": finding.line_number,
                                    "snippet": {"text": finding.sink_context},
                                },
                            }
                        }
                    ],
                }
            )

        sarif_out = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [run_dict],
        }
        json.dump(sarif_out, self.output_stream, indent=4)
