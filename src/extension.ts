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

// Output View
import {OutputView} from './local_modules/ui/outputView';

const registeredCheckModules = [pythonVirtualenvVersionCheck, pythonPipenvVersionCheck];
const CHECK_MODULES_ENABLED = false;

const OCHRONA_ANALYSIS_URL = 'http://127.0.0.1:5000/python/analyze';
let API_KEY: string = ''

let StatusBarItem: vscode.StatusBarItem;

export function activate({ subscriptions }: vscode.ExtensionContext) {

	console.log('Ochrona is running! ');

	API_KEY = vscode.workspace.getConfiguration().get('conf.ochrona.apiKey') || '';

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
			'Authorization': API_KEY
		},
		body: JSON.stringify({'dependencies': parsed })
	};
	
	request(options, function (err, res, body) {
		if(err) {
			console.log(err);
		} else {
			if (res.statusCode == 200) {
				let parsed = JSON.parse(body);
				let potentialVulnerabilities: PotentialVulnerabilities.PotentialVulnerability[] = parsed.potential_vulnerabilities || [];
				let confirmedVulnerabilities: PotentialVulnerabilities.PotentialVulnerability[] = parsed.confirmed_vulnerabilities || [];
				updateView(potentialVulnerabilities, confirmedVulnerabilities, file);
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
function updateStatusBarItem(total_vulns: number): void {
	if (total_vulns > 0) {
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
	statusBarUpdating();

	// vuln checks
	checkPrimaryDependenciesFile(callApi);

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
		createWebView(file, potential_vulnerabilities, confirmed_vulnerabilities);
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

//
// Generates new WebView of scan output
//
function createWebView(paths: string[], 
						potential_vulnerabilities: PotentialVulnerabilities.PotentialVulnerability[],
						confirmed_vulnerabilities: PotentialVulnerabilities.PotentialVulnerability[]): void {
	OutputView.createOrShow(paths, potential_vulnerabilities, confirmed_vulnerabilities);
}

// this method is called when your extension is deactivated
export function deactivate() {}
