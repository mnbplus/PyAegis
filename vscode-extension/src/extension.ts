/**
 * PyAegis VS Code Extension
 * Lightweight Python SAST: taint analysis + technical debt insights.
 *
 * Architecture:
 * - Spawns `pyaegis scan --format json` as a child process
 * - Parses JSON findings and publishes them as VS Code Diagnostics
 * - Decorates the editor with severity-coloured underlines
 * - Provides commands: scanFile, scanWorkspace, debtAnalysis, showOutput
 */

import * as vscode from 'vscode';
import { execFile, spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('pyaegis');
  outputChannel = vscode.window.createOutputChannel('PyAegis');

  context.subscriptions.push(diagnosticCollection);
  context.subscriptions.push(outputChannel);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand('pyaegis.scanFile', () => scanCurrentFile()),
    vscode.commands.registerCommand('pyaegis.scanWorkspace', () => scanWorkspace()),
    vscode.commands.registerCommand('pyaegis.debtAnalysis', () => runDebtAnalysis()),
    vscode.commands.registerCommand('pyaegis.showOutput', () => outputChannel.show()),
  );

  // Auto-scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const cfg = vscode.workspace.getConfiguration('pyaegis');
      if (cfg.get<boolean>('scanOnSave') && doc.languageId === 'python') {
        scanFile(doc.uri.fsPath);
      }
    }),
  );

  // Clear diagnostics when file is closed
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
    }),
  );

  outputChannel.appendLine('[PyAegis] Extension activated.');
  checkPyAegisInstalled();
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
  outputChannel?.dispose();
}

// ---------------------------------------------------------------------------
// Python / pyaegis resolution
// ---------------------------------------------------------------------------

function getPythonPath(): string {
  const cfg = vscode.workspace.getConfiguration('pyaegis');
  const configured = cfg.get<string>('pythonPath');
  if (configured && configured.trim()) {
    return configured.trim();
  }
  // Try to get from Python extension
  const pythonExt = vscode.extensions.getExtension('ms-python.python');
  if (pythonExt?.isActive) {
    const api = pythonExt.exports;
    const interpreter = api?.settings?.getExecutionDetails?.()?.execCommand?.[0];
    if (interpreter) return interpreter;
  }
  return process.platform === 'win32' ? 'python' : 'python3';
}

function checkPyAegisInstalled(): void {
  const python = getPythonPath();
  execFile(python, ['-m', 'pyaegis', 'version'], {}, (err, stdout) => {
    if (err) {
      outputChannel.appendLine('[PyAegis] WARNING: pyaegis not found. Install with: pip install pyaegis');
      vscode.window.showWarningMessage(
        'PyAegis not found. Install it with: pip install pyaegis',
        'Install'
      ).then((choice) => {
        if (choice === 'Install') {
          const terminal = vscode.window.createTerminal('PyAegis Install');
          terminal.sendText(`${python} -m pip install pyaegis`);
          terminal.show();
        }
      });
    } else {
      outputChannel.appendLine(`[PyAegis] Found: ${stdout.trim()}`);
    }
  });
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  CRITICAL: vscode.DiagnosticSeverity.Error,
  HIGH: vscode.DiagnosticSeverity.Error,
  MEDIUM: vscode.DiagnosticSeverity.Warning,
  LOW: vscode.DiagnosticSeverity.Information,
  INFO: vscode.DiagnosticSeverity.Hint,
};

function toVscodeSeverity(s: string): vscode.DiagnosticSeverity {
  return SEVERITY_MAP[s?.toUpperCase()] ?? vscode.DiagnosticSeverity.Warning;
}

// ---------------------------------------------------------------------------
// Core scan logic
// ---------------------------------------------------------------------------

interface PyAegisFinding {
  rule_id: string;
  severity: string;
  description: string;
  file_path: string;
  line_number: number;
  source_var: string;
  sink_context: string;
  cwe: string;
  fix: string;
}

interface PyAegisReport {
  findings: PyAegisFinding[];
  meta: { total_findings: number; duration_seconds: number };
}

function buildSeverityArgs(): string[] {
  const cfg = vscode.workspace.getConfiguration('pyaegis');
  const sevs = cfg.get<string[]>('severity') ?? ['CRITICAL', 'HIGH', 'MEDIUM'];
  return sevs.length > 0 ? ['--severity', sevs.join(',')] : [];
}

function buildRulesArgs(): string[] {
  const cfg = vscode.workspace.getConfiguration('pyaegis');
  const rulesPath = cfg.get<string>('rulesPath');
  return rulesPath && rulesPath.trim() ? ['--rules', rulesPath.trim()] : [];
}

function scanFile(filePath: string): void {
  const python = getPythonPath();
  const args = [
    '-m', 'pyaegis', 'scan',
    filePath,
    '--format', 'json',
    '--quiet',
    ...buildSeverityArgs(),
    ...buildRulesArgs(),
  ];

  outputChannel.appendLine(`[PyAegis] Scanning: ${filePath}`);

  let stdout = '';
  let stderr = '';
  const proc = spawn(python, args, { cwd: path.dirname(filePath) });
  proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
  proc.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
  proc.on('close', () => {
    if (stderr.trim()) outputChannel.appendLine(`[PyAegis] stderr: ${stderr.trim()}`);
    publishDiagnostics(stdout, filePath);
  });
}

function publishDiagnostics(jsonOutput: string, scannedPath: string): void {
  // Clear existing diagnostics for scanned file(s)
  if (fs.existsSync(scannedPath) && fs.statSync(scannedPath).isFile()) {
    diagnosticCollection.delete(vscode.Uri.file(scannedPath));
  }

  let report: PyAegisReport;
  try {
    report = JSON.parse(jsonOutput);
  } catch {
    // No findings or parse error — clear and return
    return;
  }

  if (!report.findings || report.findings.length === 0) {
    outputChannel.appendLine('[PyAegis] No issues found.');
    return;
  }

  // Group by file
  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const f of report.findings) {
    const uri = vscode.Uri.file(f.file_path);
    const line = Math.max(0, (f.line_number ?? 1) - 1);
    const range = new vscode.Range(line, 0, line, 999);
    const msg = `[${f.severity}] ${f.rule_id}: ${f.description}${f.cwe ? ` (${f.cwe})` : ''}`;
    const diag = new vscode.Diagnostic(range, msg, toVscodeSeverity(f.severity));
    diag.source = 'PyAegis';
    diag.code = { value: f.rule_id, target: vscode.Uri.parse(`https://github.com/mnbplus/PyAegis`) };
    if (f.fix) {
      diag.relatedInformation = [
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(vscode.Uri.file(f.file_path), range),
          `Fix: ${f.fix}`
        )
      ];
    }
    const key = uri.fsPath;
    if (!byFile.has(key)) byFile.set(key, []);
    byFile.get(key)!.push(diag);
  }

  for (const [filePath, diags] of byFile) {
    diagnosticCollection.set(vscode.Uri.file(filePath), diags);
  }

  outputChannel.appendLine(
    `[PyAegis] Found ${report.findings.length} issue(s) in ${byFile.size} file(s). ` +
    `Duration: ${report.meta?.duration_seconds?.toFixed(2) ?? '?'}s`
  );
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

function scanCurrentFile(): void {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showInformationMessage('PyAegis: No active file.');
    return;
  }
  if (editor.document.languageId !== 'python') {
    vscode.window.showInformationMessage('PyAegis: Only Python files are supported.');
    return;
  }
  scanFile(editor.document.uri.fsPath);
}

function scanWorkspace(): void {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showInformationMessage('PyAegis: No workspace folder open.');
    return;
  }
  const rootPath = folders[0].uri.fsPath;
  const python = getPythonPath();
  const args = [
    '-m', 'pyaegis', 'scan',
    rootPath,
    '--format', 'json',
    '--quiet',
    ...buildSeverityArgs(),
    ...buildRulesArgs(),
  ];

  outputChannel.appendLine(`[PyAegis] Scanning workspace: ${rootPath}`);
  outputChannel.show();
  vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'PyAegis: Scanning workspace...', cancellable: false },
    () => new Promise<void>((resolve) => {
      let stdout = '';
      let stderr = '';
      const proc = spawn(python, args, { cwd: rootPath });
      proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
      proc.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
      proc.on('close', () => {
        if (stderr.trim()) outputChannel.appendLine(`[PyAegis] stderr: ${stderr.trim()}`);
        publishDiagnostics(stdout, rootPath);
        resolve();
      });
    })
  );
}

function runDebtAnalysis(): void {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showInformationMessage('PyAegis: No workspace folder open.');
    return;
  }
  const rootPath = folders[0].uri.fsPath;
  const python = getPythonPath();
  const cfg = vscode.workspace.getConfiguration('pyaegis');
  const minChurn = cfg.get<number>('debtMinChurn') ?? 2;

  outputChannel.appendLine(`[PyAegis] Running debt analysis on: ${rootPath}`);
  outputChannel.show();

  vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'PyAegis: Analysing technical debt...', cancellable: false },
    () => new Promise<void>((resolve) => {
      let stdout = '';
      let stderr = '';
      const proc = spawn(python, [
        '-m', 'pyaegis', 'debt',
        '--repo', rootPath,
        '--top', '10',
        '--min-churn', String(minChurn),
      ], { cwd: rootPath });
      proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
      proc.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
      proc.on('close', () => {
        if (stderr.trim()) outputChannel.appendLine(`[PyAegis] ${stderr.trim()}`);
        outputChannel.appendLine('\n--- Technical Debt Report ---');
        outputChannel.appendLine(stdout);
        resolve();
      });
    })
  );
}
