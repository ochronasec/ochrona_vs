// Ochrona Security 2019
// ascott
import * as vscode from 'vscode';
import * as request from 'request';
import fs = require('fs');

// Custom Types
import * as PotentialVulnerabilities from './models/PotentialVulnerabilities';
import * as ModuleCheck from './models/ModuleCheckResult'

// Check Modules
import * as pythonVersionCheck from './local_modules/checks/pythonVersionCheck';

const registeredCheckModules = [pythonVersionCheck];

const OCHRONA_ANALYSIS_URL = 'http://127.0.0.1:5000/analyze/python';

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
// Makes a request to `OCHRONA_ANALYSIS_URL` for any found requirements.txt files.
//
function callApi(file: string): any {

	const options = {
		method: "POST",
		url: OCHRONA_ANALYSIS_URL,
		headers: {
			"Content-Type": "multipart/form-data"
		},
		formData : {
			"file" : fs.createReadStream(file)
		}
	};
	
	request(options, function (err, res, body) {
		if(err) {
			console.log(err);
		} else {
			let potentialVulnerabilities: PotentialVulnerabilities.PotentialVulnerability[] = JSON.parse(body).potential_vulnerabilities;
			if (potentialVulnerabilities.length > 0) {
				updateView(potentialVulnerabilities, file);
			}
		}
	});
}

//
// Pushes an Warning message to use the user when vulnerabilities are found
//
function notify(potential_vulnerabilities: PotentialVulnerabilities.PotentialVulnerability[], file: string) {
        vscode.window.showWarningMessage(
            `Found ${potential_vulnerabilities.length} potential vulnerabilities in ${file}`
        );
}

//
// Pushes an Warning message to use the user when vulnerabilities are found
//
function _notify(general_module_check: ModuleCheck.ModuleCheckResult) {
	vscode.window.showWarningMessage(general_module_check.value!.message!);
}

//
// Updates the status bar item when results arrive
//
function updateStatusBarItem(total_vulns: number): void {
	if (total_vulns > 0) {
		StatusBarItem.text = `$(report) ${total_vulns} potential python vulnerabilites found!`;
		StatusBarItem.show();
	} else {
		StatusBarItem.text = `$(thumbsup) No python vulnerabilites found`;
		StatusBarItem.hide();
	}
}

//
// Main method, sets the status to updating and calls the remote API for any found files
//
async function checkForUpdates() {
	statusBarUpdating();

	// vuln checks
	let files = await vscode.workspace.findFiles('*requirements*.txt', null, 10);
	if (files.length > 0) {
		files.forEach( async function(file) {
			if (file.path) {
				callApi(file.path);
			}
		});
	};

	// other module checks
	registeredCheckModules.forEach( async (module) => {
		let checkResponse = await module.check()
		if (checkResponse.violated) {
			_notify(checkResponse)
		}
	});
}

//
// Bundled method to update whole view (status bar item & warning message)
//
function updateView(potential_vulnerabilities: PotentialVulnerabilities.PotentialVulnerability[], file: string): void {
	if (potential_vulnerabilities) {
		notify(potential_vulnerabilities, file);
	}
	updateStatusBarItem(potential_vulnerabilities.length);
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
