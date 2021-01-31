// Ochrona Security 2019
// ascott
import * as vscode from 'vscode';
import * as request from 'request';
import fs = require('fs');

// Custom Types
import * as PotentialVulnerabilities from './models/PotentialVulnerabilities';
import * as ModuleCheck from './models/ModuleCheckResult'

// Core
import {checkPrimaryDependenciesFile} from './core/core';

// Check Modules
import * as pythonVirtualenvVersionCheck from './local_modules/checks/virtualenv/pythonVersionCheck';
import * as pythonPipenvVersionCheck from './local_modules/checks/pipenv/pythonVersionCheck';

const registeredCheckModules = [pythonVirtualenvVersionCheck, pythonPipenvVersionCheck];
const CHECK_MODULES_ENABLED = false;

const OCHRONA_ANALYSIS_URL = 'https://api.ochrona.dev/python/analyze';
let API_KEY: string = ''

let StatusBarItem: vscode.StatusBarItem;

export function activate({ subscriptions }: vscode.ExtensionContext) {
	console.log('Ochrona is running! ');

	const commandID = 'extension.ochrona';
	let disposable = vscode.commands.registerCommand(commandID, async () => {
		StatusBarItem.tooltip = 'Ochrona VS Code plugin for python dependency management.'

		await checkForUpdates();
	});

	StatusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
	StatusBarItem.command = commandID;
	subscriptions.push(StatusBarItem);
	subscriptions.push(disposable);
}

//
// Makes a request to `OCHRONA_ANALYSIS_URL` for any found requirements files.
//
function callApi(file: string[], parsed: string[]): any {

	const options = {
		method: 'POST',
		url: OCHRONA_ANALYSIS_URL,
		headers: {
			'Content-Type': 'application/json',
			'x-api-key': API_KEY
		},
		body: JSON.stringify({'dependencies': parsed })
	};
	
	console.log(`Making request to ${OCHRONA_ANALYSIS_URL}`);
	request(options, function (err, res, body) {
		if(err) {
			console.log(err);
		} else {
			if (res.statusCode == 200) {
				let parsed = JSON.parse(body);
				let potentialVulnerabilities: PotentialVulnerabilities.PotentialVulnerability[] = parsed.potential_vulnerabilities || [];
				let confirmedVulnerabilities: PotentialVulnerabilities.PotentialVulnerability[] = parsed.confirmed_vulnerabilities || [];
				updateView(potentialVulnerabilities, confirmedVulnerabilities, file);
			} else {
				console.log(`Status Code: ${res.statusCode} Response: ${res.body}`);
				updateStatusBarItem(0, true);
			}
		}
	});
}

//
// Pushes an Warning message to use the user when dependency vulnerabilities are found
//
function notify(potential_vulnerabilities: PotentialVulnerabilities.PotentialVulnerability[], 
				confirmed_vulnerabilities: PotentialVulnerabilities.PotentialVulnerability[],
				file: string[]) {
        vscode.window.showWarningMessage(
			`Found ${confirmed_vulnerabilities.length} confirmed vulnerabilities and ${potential_vulnerabilities.length} potential vulnerabilities in ${file}`
        );
}

//
// Pushes an Warning message to use the user when module vulnerabilities are found
//
function _notify(general_module_check: ModuleCheck.ModuleCheckResult) {
	vscode.window.showWarningMessage(general_module_check.value!.message!);
}

//
// Updates the status bar item when results arrive
//
function updateStatusBarItem(total_vulns: number, error: boolean = false): void {
	if (error) {
		StatusBarItem.text = `$(report) Ochrona reported an Error`;
		StatusBarItem.show();
	} else if (total_vulns > 0) {
		StatusBarItem.text = `$(report) ${total_vulns} python vulnerabilites found!`;
		StatusBarItem.show();
	} else {
		StatusBarItem.text = `$(thumbsup) No python vulnerabilites found`;
		StatusBarItem.show();
	}
}

//
// Main method, sets the status to updating and calls the remote API for any found files
//
async function checkForUpdates() {

	// ensure API key is configured
	API_KEY = vscode.workspace.getConfiguration().get('conf.ochrona.apiKey') || '';
	if (API_KEY == '') {
		vscode.window.showWarningMessage(
			'API Key has not been configured for Ochrona. Please provide an API key in Settings.'
		);
		return;
	}
	statusBarUpdating();

	// vuln checks
	checkPrimaryDependenciesFile(callApi, updateStatusBarItem);

	// other module checks
	if (CHECK_MODULES_ENABLED) {
		registeredCheckModules.forEach( async (module) => {
			let checkResponse = await module.check()
			if (checkResponse.violated) {
				_notify(checkResponse)
			}
		});
	}
}

//
// Bundled method to update whole view (status bar item & warning message)
//
function updateView(potential_vulnerabilities: PotentialVulnerabilities.PotentialVulnerability[], 
					confirmed_vulnerabilities: PotentialVulnerabilities.PotentialVulnerability[],
					file: string[]): void {
	if ((potential_vulnerabilities && potential_vulnerabilities.length > 0) || (confirmed_vulnerabilities && confirmed_vulnerabilities.length > 0)) {
		notify(potential_vulnerabilities, confirmed_vulnerabilities, file);
		var outputChannel = vscode.window.createOutputChannel('Ochrona')
		outputChannel.show()
		outputChannel.appendLine('Ochrona Dependency Scan');
		outputChannel.appendLine(`\nFiles Scanned: \n\t${file.join('\n\t')}` );
		outputChannel.appendLine('Scan Time: \n\t' + Date());
		if (confirmed_vulnerabilities.length > 0) {
			outputChannel.appendLine(`\nDiscovered ${confirmed_vulnerabilities.length} confirmed vulnerabilities.\n`);
			confirmed_vulnerabilities.forEach((vuln: any) => {
				outputChannel.appendLine(`\tPackage Name - ${vuln.name}`);
				outputChannel.appendLine(`\tInstalled Version - ${vuln.found_version}`);
				outputChannel.appendLine(`\tCVE - ${vuln.cve_id || 'None'}`);
				outputChannel.appendLine(`\tSeverity - ${vuln.ochrona_severity_score || 'Unknown'}`);
				outputChannel.appendLine(`\tReason - ${vuln.reason || 'Unknown'}`);
				outputChannel.appendLine(`\tDescription - ${vuln.description || 'Unknown'}`);
				outputChannel.appendLine(`\tReferences - \n\t\t${vuln.references.join('\n\t\t')}`);
				outputChannel.appendLine(`\t-------------------------------------------------------`);
				outputChannel.appendLine(`\n`);
			});
		}
		if (potential_vulnerabilities.length > 0) {
			outputChannel.appendLine(`Discovered ${potential_vulnerabilities.length} potential vulnerabilities.`);
			potential_vulnerabilities.forEach((vuln: any) => {
				outputChannel.appendLine(`\tPackage Name - ${vuln.name}`);
				outputChannel.appendLine(`\tInstalled Version - ${vuln.found_version}`);
				outputChannel.appendLine(`\tCVE - ${vuln.cve_id || 'None'}`);
				outputChannel.appendLine(`\tSeverity - ${vuln.ochrona_severity_score || 'Unknown'}`);
				outputChannel.appendLine(`\tReason - ${vuln.reason || 'Unknown'}`);
				outputChannel.appendLine(`\tDescription - ${vuln.description || 'Unknown'}`);
				outputChannel.appendLine(`\tReferences - \n\t\t${vuln.references.join('\n\t\t')}`);
				outputChannel.appendLine(`\t-------------------------------------------------------`);
				outputChannel.appendLine(`\n`);
			});
		}
	}
	updateStatusBarItem(potential_vulnerabilities.concat(confirmed_vulnerabilities).length);
}

//
// Updates the status bar to be in the processing state.
//
function statusBarUpdating(): void {
	StatusBarItem.hide();
	StatusBarItem.text = `$(sync~spin) Checking for python vulnerabilities..`
	StatusBarItem.show();
}

// this method is called when your extension is deactivated
export function deactivate() {}
