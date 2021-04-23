// Ochrona Security 2019
// ascott
import * as vscode from 'vscode';
import * as request from 'request';
import fs = require('fs');
import jwt_decode from "jwt-decode";

// Custom Types
import * as PotentialVulnerabilities from './models/PotentialVulnerabilities';
import * as ModuleCheck from './models/ModuleCheckResult'

// Core
import {checkPrimaryDependenciesFile, checkExplicitDependencyFile, isApplicableFile} from './core/core';

// Check Modules
import * as pythonVirtualenvVersionCheck from './local_modules/checks/virtualenv/pythonVersionCheck';
import * as pythonPipenvVersionCheck from './local_modules/checks/pipenv/pythonVersionCheck';

const registeredCheckModules = [pythonVirtualenvVersionCheck, pythonPipenvVersionCheck];
const CHECK_MODULES_ENABLED = false;

const OCHRONA_ANALYSIS_URL = 'https://api.ochrona.dev/python/analyze';
const OCHRONA_AUTH_URL = 'https://authn.ochrona.dev/oauth2/token';
let API_KEY: string = ''
let JWT: string = ''

let StatusBarItem: vscode.StatusBarItem;

export function activate({ subscriptions }: vscode.ExtensionContext) {
	vscode.workspace.onDidSaveTextDocument((document: vscode.TextDocument) => {
		console.log(document.fileName);
		if (isApplicableFile(document.fileName)) {
			console.log(`Ochrona check for ${document.fileName}`);
			checkForUpdatesExplicit(document.fileName);
		}
	});

	const commandID = 'extension.ochrona';
	let disposable = vscode.commands.registerCommand(commandID, async () => {
		console.log("Ochrona check all files");
		await checkForUpdates();
	});

	StatusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
	StatusBarItem.tooltip = 'Ochrona VS Code plugin for python dependency management.'
	StatusBarItem.command = commandID;
	subscriptions.push(StatusBarItem);
	subscriptions.push(disposable);
}

//
// Makes a request to `OCHRONA_ANALYSIS_URL` for any found requirements files.
//
async function callApi(file: string[], parsed: string[]): Promise<any> {

	// Pre-call checks
	if (parsed.length == 0 && file.length == 0) {
		console.log("Did not find any matching files.");
		updateStatusBarItem(0, false, true);
		return;
	}

	let jwt: string;
	jwt = await getJwt(API_KEY);
	const options = {
		method: 'POST',
		url: OCHRONA_ANALYSIS_URL,
		headers: {
			'Content-Type': 'application/json',
			'Authorization': jwt 
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
// Refreshed the global JWT
//
function getJwt(apiKey: string): Promise<string> {
	return new Promise((resolve, reject) => {
		if (isJwtExpired()) {
			const options = {
				method: 'POST',
				url: OCHRONA_AUTH_URL,
				headers: {"Content-Type": "application/x-www-form-urlencoded"},
				form: {
					grant_type: "refresh_token",
					client_id: "2asm97h0jq5299qgpeeom91iod",
					refresh_token: apiKey
				}
			};

			console.log(`Making request to ${OCHRONA_AUTH_URL}`);
			request(options, function (err, res, body) {
				if(err) {
					console.log(err);
					reject(err)
				} else {
					if (res.statusCode == 200) {
						let parsed = JSON.parse(body);
						JWT = parsed.id_token;
						resolve(JWT);
					} else {
						console.log(`Status Code: ${res.statusCode} Response: ${res.body}`);
						reject(res.body);
					}
				}
			});
		} else {
			resolve(JWT);
		}
	});
}

//
// Checks if the JWT is expired
//
function isJwtExpired(): boolean {
	if (!!JWT) {
		let decoded: any = jwt_decode(JWT);
		let now = Math.floor(Date.now() / 1000);
		if (decoded.exp && now >= decoded.exp) {
			return true;
		} else {
			return false;
		}
	}
	return true;
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
function updateStatusBarItem(total_vulns: number, error: boolean = false, empty: boolean = false): void {
	if (error) {
		StatusBarItem.text = `$(report) Ochrona reported an Error`;
		StatusBarItem.show();
	} else if (empty) {
		StatusBarItem.text = `$(report) Ochrona could not locate dependency files`;
		StatusBarItem.show();
	}else if (total_vulns > 0) {
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
// Explicit Check for a file
//
async function checkForUpdatesExplicit(file: string) {

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
	checkExplicitDependencyFile(file, callApi, updateStatusBarItem);

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
