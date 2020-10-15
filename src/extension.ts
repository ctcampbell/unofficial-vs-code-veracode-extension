/* eslint-disable @typescript-eslint/naming-convention */
// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import * as url from 'url';
import * as fs from 'fs';
import * as path from 'path';
import { runPipelineScan } from 'unofficial-veracode-pipeline-scan';

const extensionId = 'ctcampbell.unofficial-vs-code-veracode-pipeline-scan';
const extension = vscode.extensions.getExtension(extensionId)!;
const extensionConfig = vscode.workspace.getConfiguration('unofficialVeracodePipelineScan');
const sourceRootDirectory = extensionConfig['sourceRoot'];
const jspRootDirectory = extensionConfig['jspRoot'];
const resultsFileName = extensionConfig['resultsFileName'];
const diagnosticSource = extension.packageJSON.displayName;
const outputChannel = vscode.window.createOutputChannel(extension.packageJSON.displayName);
const diagnosticsStatusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);

let pipelineScanDiagnosticCollection: vscode.DiagnosticCollection;
let watcher: vscode.FileSystemWatcher;

// this method is called when your extension is activated
// your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {

	// Use the console to output diagnostic information (console.log) and errors (console.error)
	// This line of code will only be executed once when your extension is activated
	pipelineScanDiagnosticCollection = vscode.languages.createDiagnosticCollection(extensionId);
	context.subscriptions.push(pipelineScanDiagnosticCollection);

	// The command has been defined in the package.json file
	// Now provide the implementation of the command with registerCommand
	// The commandId parameter must match the command field in package.json
	let scanFileDisposable = vscode.commands.registerCommand(`${extensionId}.scanFile`, (target: vscode.Uri) => {
		if (target) {
			scanFile(target);
		}
	});
	context.subscriptions.push(scanFileDisposable);
	let loadResultsDisposable = vscode.commands.registerCommand(`${extensionId}.loadResults`, (target: vscode.Uri) => {
		if (target) {
			parseResultsJson(target);
		}
	});
	context.subscriptions.push(loadResultsDisposable);

	watcher = vscode.workspace.createFileSystemWatcher(`**/${resultsFileName}`);
	watcher.onDidCreate(parseResultsJson);
	watcher.onDidChange(parseResultsJson);
	watcher.onDidDelete(() => {
		pipelineScanDiagnosticCollection.clear();
	});
	context.subscriptions.push(watcher);
}

// this method is called when your extension is deactivated
export function deactivate() {}

async function scanFile(target: vscode.Uri) {
	outputChannel.clear();
	outputChannel.show();
	pipelineScanDiagnosticCollection.clear();

	let fileName = target.fsPath.substring(target.fsPath.lastIndexOf(path.sep) + 1);
	diagnosticsStatusBarItem.text = `Scanning ${fileName}`;
	diagnosticsStatusBarItem.show();

	try {
		let fileUrl = url.pathToFileURL(target.fsPath);
		if (vscode.workspace.workspaceFolders) {
			let outputFile = url.pathToFileURL(path.join(vscode.workspace.workspaceFolders[0].uri.fsPath, resultsFileName));
			await runPipelineScan(fileUrl, outputFile, sendLogMessage);
			diagnosticsStatusBarItem.text = `Scan complete ${fileName}`;
			setTimeout(() => {
				diagnosticsStatusBarItem.hide();
			}, 10000);
		}
	} catch(error) {
		sendLogMessage(error.message);
	}
}

function parseResultsJson(target: vscode.Uri) {
	let jsonFile = fs.readFileSync(target.fsPath);
	let json = JSON.parse(jsonFile.toString());
	let diagnosticArraysByFile: { [key: string]: vscode.Diagnostic[] } = {};
	let absoluteSourceRoot = path.join((vscode.workspace.workspaceFolders?.[0].uri.toString() || ''), sourceRootDirectory);
	let absoluteJSPRoot = path.join((vscode.workspace.workspaceFolders?.[0].uri.toString() || ''), jspRootDirectory);
	let findings = json.findings;

	for (var i = 0; i < findings.length; i++) {
		let finding = findings[i];
		let line = finding.files.source_file.line;
		let range = new vscode.Range(line - 1 , 0, line - 1, Number.MAX_VALUE);
		let severity = mapSeverityToVSCodeSeverity(finding.severity);
		let diagnostic = new vscode.Diagnostic(range, finding.issue_type, severity);
		diagnostic.source = diagnosticSource;
		let issueDisplayText = finding.display_text.replace(/(<([^>]+)>)/ig,'');
		diagnostic.message = `${mapSeverityToString(finding.severity)} - CWE ${finding.cwe_id} - ${finding.issue_type}\r\n${issueDisplayText}`;
		let diagnosticArray = diagnosticArraysByFile[finding.files.source_file.file] || [];
		diagnosticArray.push(diagnostic);
		diagnosticArraysByFile[finding.files.source_file.file] = diagnosticArray;
	}
	for (let diagnosticArrayFile in diagnosticArraysByFile) {
		diagnosticArraysByFile[diagnosticArrayFile].sort((a, b) => a.severity - b.severity);
		let prefix = diagnosticArrayFile.startsWith('WEB-INF') ? absoluteJSPRoot : absoluteSourceRoot;
		pipelineScanDiagnosticCollection.set(vscode.Uri.parse(path.join(prefix, diagnosticArrayFile)), diagnosticArraysByFile[diagnosticArrayFile]);
	}
}

function mapSeverityToVSCodeSeverity(sev: number): vscode.DiagnosticSeverity {
	switch (sev) {
		case 5:
		case 4: return vscode.DiagnosticSeverity.Error;
		case 3: return vscode.DiagnosticSeverity.Warning;
		default: return vscode.DiagnosticSeverity.Information;
	}
}

function mapSeverityToString(sev: number): string | undefined {
	switch (sev) {
		case 5: return 'Very High';
		case 4: return 'High';
		case 3: return 'Medium';
		case 2: return 'Low';
		case 1: return 'Very Low';
		case 0: return 'Informational';
	}
}

function makeTimestamp(): string {
	let now = new Date();
	return `[${now.toISOString()}]`;
}

function sendLogMessage(message: string) {
	outputChannel.appendLine(`${makeTimestamp()} ${message}`);
}
