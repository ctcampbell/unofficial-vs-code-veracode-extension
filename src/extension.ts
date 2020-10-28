/* eslint-disable @typescript-eslint/naming-convention */
// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import * as url from 'url';
import * as fs from 'fs';
import * as path from 'path';
import { runPipelineScan } from 'unofficial-veracode-pipeline-scan';

const extensionId = 'ctcampbell-com.unofficial-vs-code-veracode';
const extensionConfigName = 'unofficialVeracodeExtension';
const extension = vscode.extensions.getExtension(extensionId)!;

const outputChannel = vscode.window.createOutputChannel(extension.packageJSON.displayName);
const diagnosticsStatusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);

let extensionConfig: vscode.WorkspaceConfiguration;
let sourceRootDirectory: string;
let jspRootDirectory: string;
let pipelineScanResultsFilename: string;
let scaRootFolder: string;
let scaResultsFilename: string;

let pipelineScanDiagnosticCollection = vscode.languages.createDiagnosticCollection(`${extensionId}.pipelineScan`);
let scaDiagnosticCollection = vscode.languages.createDiagnosticCollection(`${extensionId}.sca`);

function loadConfig() {
	extensionConfig = vscode.workspace.getConfiguration(extensionConfigName);
	sourceRootDirectory = extensionConfig['sourceRoot'];
	jspRootDirectory = extensionConfig['jspRoot'];
	pipelineScanResultsFilename = extensionConfig['pipelineScanResultsFilename'];
	scaRootFolder = extensionConfig['scaRootFolder'];
	scaResultsFilename = extensionConfig['scaResultsFilename'];
}

export function activate(context: vscode.ExtensionContext) {
	loadConfig();

	context.subscriptions.push(pipelineScanDiagnosticCollection);
	context.subscriptions.push(scaDiagnosticCollection);

	context.subscriptions.push(vscode.commands.registerCommand(`${extensionId}.scanFileWithPipeline`, scanFileWithPipeline));
	context.subscriptions.push(vscode.commands.registerCommand(`${extensionId}.loadPipelineScanResults`, loadPipelineScanResultsJson));
	context.subscriptions.push(vscode.commands.registerCommand(`${extensionId}.loadSCAResults`, loadSCAResultsJson));

	let pipelineScanWatcher = vscode.workspace.createFileSystemWatcher(`**/${pipelineScanResultsFilename}`);
	pipelineScanWatcher.onDidCreate(loadPipelineScanResultsJson);
	pipelineScanWatcher.onDidChange(loadPipelineScanResultsJson);
	pipelineScanWatcher.onDidDelete(() => {
		pipelineScanDiagnosticCollection.clear();
	});
	context.subscriptions.push(pipelineScanWatcher);

	let scaWatcher = vscode.workspace.createFileSystemWatcher(`**/${scaResultsFilename}`);
	scaWatcher.onDidCreate(loadSCAResultsJson);
	scaWatcher.onDidChange(loadSCAResultsJson);
	scaWatcher.onDidDelete(() => {
		scaDiagnosticCollection.clear();
	});
	context.subscriptions.push(scaWatcher);
}

async function scanFileWithPipeline(target: vscode.Uri) {
	loadConfig();
	outputChannel.clear();
	outputChannel.show();
	pipelineScanDiagnosticCollection.clear();

	if (!target && vscode.workspace.workspaceFolders) {
		if (extensionConfig['pipelineScanFilepath'] === '') {
			sendLogMessage('No default Pipeline Scan filepath set, see extension help for configuration settings');
			return;
		}
		target = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, extensionConfig['pipelineScanFilepath']);
	}

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

function loadPipelineScanResultsJson(target: vscode.Uri) {
	loadConfig();
	pipelineScanDiagnosticCollection.clear();

	if (!target && vscode.workspace.workspaceFolders) {
		target = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, pipelineScanResultsFilename);
	}
 	
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

	let absoluteSourceRoot = vscode.Uri.parse('');
	let absoluteJSPRoot = vscode.Uri.parse('');
	if (vscode.workspace.workspaceFolders) {
		absoluteSourceRoot = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, sourceRootDirectory);
		absoluteJSPRoot = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, jspRootDirectory);
	}

	let findings = json.findings;
	for (var i = 0; i < findings.length; i++) {
		let finding = findings[i];
		let line = finding.files.source_file.line;
		let range = new vscode.Range(line - 1 , 0, line - 1, Number.MAX_VALUE);
		let severity = mapSeverityToVSCodeSeverity(finding.severity);
		let diagnostic = new vscode.Diagnostic(range, finding.issue_type, severity);
		let issueDisplayText = finding.display_text.replace(/(<([^>]+)>)/ig,'');
		diagnostic.message = `${mapSeverityToString(finding.severity)} - CWE ${finding.cwe_id} - ${finding.issue_type}\r\n${issueDisplayText}`;
		let diagnosticArray = diagnosticArraysByFile[finding.files.source_file.file] || [];
		diagnosticArray.push(diagnostic);
		diagnosticArraysByFile[finding.files.source_file.file] = diagnosticArray;
	}
	for (let diagnosticArrayFile in diagnosticArraysByFile) {
		diagnosticArraysByFile[diagnosticArrayFile].sort((a, b) => a.severity - b.severity);
		let prefixUri = diagnosticArrayFile.startsWith('WEB-INF') ? absoluteJSPRoot : absoluteSourceRoot;
		pipelineScanDiagnosticCollection.set(vscode.Uri.joinPath(prefixUri, diagnosticArrayFile), diagnosticArraysByFile[diagnosticArrayFile]);
	}
}

function loadSCAResultsJson(target: vscode.Uri) {
	loadConfig();
	scaDiagnosticCollection.clear();

	if (!target && vscode.workspace.workspaceFolders) {
		target = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, scaResultsFilename);
	}

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
				if (file.filename && vscode.workspace.workspaceFolders) {
					let fileUri = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, scaRootFolder, file.filename);
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
