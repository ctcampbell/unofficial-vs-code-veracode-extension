/* eslint-disable @typescript-eslint/naming-convention */
// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import * as url from 'url';
import * as fs from 'fs';
import * as path from 'path';
import { runPipelineScan } from 'unofficial-veracode-pipeline-scan';

const extensionId = 'ctcampbell-com.unofficial-vs-code-veracode';
const extension = vscode.extensions.getExtension(extensionId)!;
const extensionConfig = vscode.workspace.getConfiguration('unofficialVeracodeExtension');

const sourceRootDirectory = extensionConfig['sourceRoot'];
const jspRootDirectory = extensionConfig['jspRoot'];

const pipelineScanResultsFilename = extensionConfig['pipelineScanResultsFilename'];
const pipelineScanDiagnosticSource = 'Veracode Pipeline Scan';

const scaResultsFilename = extensionConfig['scaResultsFilename'];
const scaDiagnosticSource = 'Veracode SCA';

const outputChannel = vscode.window.createOutputChannel(extension.packageJSON.displayName);
const diagnosticsStatusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);

let pipelineScanDiagnosticCollection: vscode.DiagnosticCollection;
let scaDiagnosticCollection: vscode.DiagnosticCollection;
let pipelineScanWatcher: vscode.FileSystemWatcher;
let scaWatcher: vscode.FileSystemWatcher;

// this method is called when your extension is activated
// your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
	pipelineScanDiagnosticCollection = vscode.languages.createDiagnosticCollection(`${extensionId}.pipelineScan`);
	context.subscriptions.push(pipelineScanDiagnosticCollection);

	scaDiagnosticCollection = vscode.languages.createDiagnosticCollection(`${extensionId}.sca`);
	context.subscriptions.push(scaDiagnosticCollection);

	let scanFileDisposable = vscode.commands.registerCommand(`${extensionId}.scanFileWithPipeline`, (target: vscode.Uri) => {
		if (target) {
			scanFileWithPipeline(target);
		}
	});
	context.subscriptions.push(scanFileDisposable);
	let loadResultsDisposable = vscode.commands.registerCommand(`${extensionId}.loadPipelineScanResults`, (target: vscode.Uri) => {
		if (target) {
			parsePipelineScanResultsJson(target);
		}
	});
	context.subscriptions.push(loadResultsDisposable);
	let loadSCAResultsDisposable = vscode.commands.registerCommand(`${extensionId}.loadSCAResults`, (target: vscode.Uri) => {
		if (target) {
			parseSCAResultsJson(target);
		}
	});
	context.subscriptions.push(loadSCAResultsDisposable);

	pipelineScanWatcher = vscode.workspace.createFileSystemWatcher(`**/${pipelineScanResultsFilename}`);
	pipelineScanWatcher.onDidCreate(parsePipelineScanResultsJson);
	pipelineScanWatcher.onDidChange(parsePipelineScanResultsJson);
	pipelineScanWatcher.onDidDelete(() => {
		pipelineScanDiagnosticCollection.clear();
	});
	context.subscriptions.push(pipelineScanWatcher);

	scaWatcher = vscode.workspace.createFileSystemWatcher(`**/${scaResultsFilename}`);
	scaWatcher.onDidCreate(parseSCAResultsJson);
	scaWatcher.onDidChange(parseSCAResultsJson);
	scaWatcher.onDidDelete(() => {
		scaDiagnosticCollection.clear();
	});
	context.subscriptions.push(scaWatcher);
}

async function scanFileWithPipeline(target: vscode.Uri) {
	outputChannel.clear();
	outputChannel.show();
	pipelineScanDiagnosticCollection.clear();

	let filename = target.fsPath.substring(target.fsPath.lastIndexOf(path.sep) + 1);
	diagnosticsStatusBarItem.text = `Scanning ${filename}`;
	diagnosticsStatusBarItem.show();

	try {
		let fileUrl = url.pathToFileURL(target.fsPath);
		if (vscode.workspace.workspaceFolders) {
			let outputFile = url.pathToFileURL(path.join(vscode.workspace.workspaceFolders[0].uri.fsPath, pipelineScanResultsFilename));
			await runPipelineScan(fileUrl, outputFile, sendLogMessage);
			diagnosticsStatusBarItem.text = `Scan complete ${filename}`;
			setTimeout(() => {
				diagnosticsStatusBarItem.hide();
			}, 10000);
		}
	} catch(error) {
		sendLogMessage(error.message);
	}
}

function parsePipelineScanResultsJson(target: vscode.Uri) {
	pipelineScanDiagnosticCollection.clear();
	
	let json: any = {};
	try {
		json = JSON.parse(fs.readFileSync(target.fsPath, 'utf8').trimStart());
	} catch(error) {
		if (error.message.startsWith('Unexpected token')) {
			try {
				json = JSON.parse(fs.readFileSync(target.fsPath, 'utf16le').trimStart());
			} catch(error) {
				console.log(error);
				return;
			}
		}
	}

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
		// diagnostic.source = pipelineScanDiagnosticSource;
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

function parseSCAResultsJson(target: vscode.Uri) {
	scaDiagnosticCollection.clear();

	let json: any = {};
	try {
		json = JSON.parse(fs.readFileSync(target.fsPath, 'utf8').trimStart());
	} catch(error) {
		if (error.message.startsWith('Unexpected token')) {
			try {
				json = JSON.parse(fs.readFileSync(target.fsPath, 'utf16le').trimStart());
			} catch(error) {
				console.log(error);
				return;
			}
		}
	}

	let graphs = json.records[0].graphs;
		let libraries = json.records[0].libraries;
		let librariesByFile = [];
		let vulnerabilities = json.records[0].vulnerabilities;

	for (let item of graphs) {
		librariesByFile.push({
			filename: item.filename,
			libraries: flattenGraph(item),
			diagnostics: [] as vscode.Diagnostic[]
		});
	}

	vulnerabilities.sort((a: any,b: any) => b.cvssScore - a.cvssScore);

	for (let vulnerability of vulnerabilities) {
		for (let vulnerableLibrary of vulnerability.libraries) {
			let libraryIndexParts = vulnerableLibrary._links.ref.split('/');
			let libraryIndex = parseInt(libraryIndexParts[4]);
			let libraryVersionIndex = parseInt(libraryIndexParts[6]);
			let library = libraries[libraryIndex];
			let libraryVersion = library.versions[libraryVersionIndex];
			let libraryCoord = `${library.coordinateType}.${library.coordinate1 || ''}.${library.coordinate2 || ''}.${libraryVersion.version}`;
			for (let file of librariesByFile) {
				if (file.filename) {
					let fileUri = vscode.Uri.parse(path.join((vscode.workspace.workspaceFolders?.[0].uri.toString() || ''), file.filename));
					let configFile = fs.readFileSync(fileUri.fsPath);

					if (file.libraries.has(libraryCoord)) {
						let lineNumber = getLineNumber(library.coordinate2 || library.coordinate1, configFile.toString());
						let range = new vscode.Range(lineNumber, 0, lineNumber, Number.MAX_VALUE);
						let cveString = vulnerability.cve ? `CVE ${vulnerability.cve}` : 'NO CVE';
						let coordinate1String = library.coordinate2 ? `${library.coordinate1}.` : library.coordinate1;
						let message = `CVSS ${vulnerability.cvssScore.toFixed(1)} - ${cveString} - ${vulnerability.title}\nAffected Library: ${coordinate1String}${library.coordinate2 || ''} ${libraryVersion.version}\nDescription: ${vulnerability.overview}`;
						let severity = mapCVSSToVSCodeSeverity(vulnerability.cvssScore);
						let diagnostic = new vscode.Diagnostic(range, message, severity);
						file.diagnostics.push(diagnostic);
					}
					
					scaDiagnosticCollection.set(fileUri, file.diagnostics);
				}
			}
		}
	}
}

// Utils

function getLineNumber(substring: string, text: string): number {
	let line = 0, matchedChars = 0;

	for (let i = 0; i < text.length; i++) {
		text[i] === substring[matchedChars] ? matchedChars++ : matchedChars = 0;

		if (matchedChars === substring.length){
			return line;                  
		}
		if (text[i] === '\n'){
			line++;
		}
	}

	return  0;
}

function flattenGraph(root: any): Map<string, object> {
	let stack = root.directs;
	let hashMap = new Map<string, object>();

    while(stack.length !== 0) {
		let node = stack.pop();
		if (node) {
			let uid = `${node.coords.coordinateType}.${node.coords.coordinate1 || ''}.${node.coords.coordinate2 || ''}.${node.coords.version}`;
			if (!hashMap.get(uid)) {
				hashMap.set(uid, node);
				for(let i: number = node.directs.length - 1; i >= 0; i--) {
					stack.push(node.directs[i]);
				}
			}
		}
    }

    return hashMap;
}

function mapSeverityToVSCodeSeverity(sev: number): vscode.DiagnosticSeverity {
	switch (sev) {
		case 5:
		case 4: return vscode.DiagnosticSeverity.Error;
		case 3: return vscode.DiagnosticSeverity.Warning;
		default: return vscode.DiagnosticSeverity.Information;
	}
}

function mapCVSSToVSCodeSeverity(sev: number): vscode.DiagnosticSeverity {
	if (sev >= 8.0) {
		return vscode.DiagnosticSeverity.Error;
	} else if (sev >= 6.0) {
		return vscode.DiagnosticSeverity.Warning;
	} else {
		return vscode.DiagnosticSeverity.Information;
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
