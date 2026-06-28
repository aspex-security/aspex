import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';

// File patterns that look like MCP configs
const MCP_CONFIG_PATTERNS = [
  'claude_desktop_config.json',
  'claude.json',
  '.cursor/mcp.json',
  'mcp.json',
  '.vscode/mcp.json',
  'windsurf_mcp.json',
  'cline_mcp_settings.json',
];

interface AspexFinding {
  rule_id: string;
  name: string;
  severity: string;
  detail: string;
  fix: string;
  server?: string;
  tool?: string;
}

interface AspexServer {
  name: string;
  findings: AspexFinding[];
}

interface AspexOutput {
  servers: AspexServer[];
}

function isMcpConfig(uri: vscode.Uri): boolean {
  const base = path.basename(uri.fsPath);
  return MCP_CONFIG_PATTERNS.some(p => uri.fsPath.endsWith(p)) ||
    base === 'claude_desktop_config.json';
}

function severityToDiagnostic(sev: string): vscode.DiagnosticSeverity {
  switch (sev.toLowerCase()) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

async function runScan(
  uri: vscode.Uri,
  diagnostics: vscode.DiagnosticCollection,
  output: vscode.OutputChannel
): Promise<void> {
  const config = vscode.workspace.getConfiguration('aspex');
  const binary: string = config.get('binaryPath', 'aspex-scan');
  const minSeverity: string = config.get('minSeverity', 'medium');

  output.appendLine(`[aspex] Scanning ${uri.fsPath}`);

  return new Promise((resolve) => {
    const args = ['--json', '--no-color', '--clients', 'claude,cursor,vscode,windsurf,cline,roo-cline,continue,zed'];
    const proc = cp.spawn(binary, args, {
      cwd: path.dirname(uri.fsPath),
      timeout: 30000,
    });

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d: Buffer) => stdout += d.toString());
    proc.stderr.on('data', (d: Buffer) => stderr += d.toString());

    proc.on('close', () => {
      if (stderr) {
        output.appendLine(`[aspex] stderr: ${stderr}`);
      }

      let parsed: AspexOutput | null = null;
      try {
        parsed = JSON.parse(stdout) as AspexOutput;
      } catch {
        output.appendLine(`[aspex] Failed to parse output: ${stdout.slice(0, 200)}`);
        resolve();
        return;
      }

      const sevOrder = ['critical', 'high', 'medium', 'low'];
      const minIdx = sevOrder.indexOf(minSeverity.toLowerCase());

      const diags: vscode.Diagnostic[] = [];

      for (const server of parsed.servers ?? []) {
        for (const finding of server.findings ?? []) {
          const idx = sevOrder.indexOf(finding.severity.toLowerCase());
          if (idx > minIdx) continue; // below threshold

          // Best-effort: highlight the server name in the JSON
          let range = new vscode.Range(0, 0, 0, 0);
          try {
            const doc = vscode.workspace.textDocuments.find(d => d.uri.fsPath === uri.fsPath);
            if (doc) {
              const text = doc.getText();
              const nameIdx = text.indexOf(`"${server.name}"`);
              if (nameIdx >= 0) {
                const pos = doc.positionAt(nameIdx);
                range = new vscode.Range(pos, pos.translate(0, server.name.length + 2));
              }
            }
          } catch { /* no-op */ }

          const msg = `[${finding.rule_id}] ${finding.name}: ${finding.detail}${finding.fix ? `\n→ Fix: ${finding.fix}` : ''}`;
          const diag = new vscode.Diagnostic(range, msg, severityToDiagnostic(finding.severity));
          diag.source = 'aspex-scan';
          diag.code = finding.rule_id;
          diags.push(diag);
        }
      }

      diagnostics.set(uri, diags);
      output.appendLine(`[aspex] ${diags.length} finding(s) in ${uri.fsPath}`);
      resolve();
    });

    proc.on('error', (err) => {
      output.appendLine(`[aspex] Failed to run aspex-scan: ${err.message}`);
      output.appendLine(`[aspex] Make sure aspex-scan is installed: brew install aspex-security/tap/aspex`);
      resolve();
    });
  });
}

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection('aspex');
  const output = vscode.window.createOutputChannel('Aspex');
  context.subscriptions.push(diagnostics, output);

  // Scan on save if it looks like an MCP config.
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      const config = vscode.workspace.getConfiguration('aspex');
      if (!config.get<boolean>('scanOnSave', true)) return;
      if (doc.languageId !== 'json') return;
      if (!isMcpConfig(doc.uri)) return;
      await runScan(doc.uri, diagnostics, output);
    })
  );

  // Manual scan command.
  context.subscriptions.push(
    vscode.commands.registerCommand('aspex.scan', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('No active file to scan.');
        return;
      }
      await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'Aspex: Scanning…', cancellable: false },
        () => runScan(editor.document.uri, diagnostics, output)
      );
    })
  );

  // Workspace scan command.
  context.subscriptions.push(
    vscode.commands.registerCommand('aspex.scanWorkspace', async () => {
      const uris = await vscode.workspace.findFiles('**/{claude_desktop_config,mcp,cline_mcp_settings}.json', '**/node_modules/**');
      if (uris.length === 0) {
        vscode.window.showInformationMessage('No MCP config files found in workspace.');
        return;
      }
      await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: `Aspex: Scanning ${uris.length} config(s)…`, cancellable: false },
        async () => {
          for (const uri of uris) {
            await runScan(uri, diagnostics, output);
          }
        }
      );
    })
  );
}

export function deactivate(): void {}
