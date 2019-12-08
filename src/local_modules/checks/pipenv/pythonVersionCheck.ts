// Ochrona Security 2019
// ascott
import * as vscode from 'vscode';
import fs = require('fs');
import semver = require('semver');

// Custom Types
import * as ModuleCheck from '../../../models/ModuleCheckResult';

const MINIMUM_VERSION = '3.5.0';
const PIPFILE_LOCK = '*Pipfile.lock';


export async function check() {
    console.log('Python pipenv version check is running');
    let lessThanMinimumVersionDetected: ModuleCheck.ModuleCheckResult = {
        violated: false
    }
    let files = await vscode.workspace.findFiles(PIPFILE_LOCK, null, 10);
	if (files.length > 0) {
		files.forEach( async function(file) {
			if (file.path) {
                // How to read to json
                const pipContents = JSON.parse(fs.readFileSync(file.path, 'utf8'));
                const parsedVersion = ensureValidSemVer(pipContents._meta.requires.python_version);
                if (semver.gt(MINIMUM_VERSION, parsedVersion)) {
                    lessThanMinimumVersionDetected = {
                        violated: true,
                        value: {
                            path: file.path,
                            result: parsedVersion,
                            message: `Found python version ${parsedVersion} required in ${file.path} - Minimum is ${MINIMUM_VERSION}`
                        }
                    };
                    console.log(lessThanMinimumVersionDetected.value!.message!);
                }
			}
		});
    };
    return lessThanMinimumVersionDetected;
}

function ensureValidSemVer(version: string) {
    if (version.split('.').length == 2) {
        return `${version}.0`;
    } else if (version.split('.').length == 2) {
        return `${version}.0.0`;
    }
    return version;
}
