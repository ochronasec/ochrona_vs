// Ochrona Security 2019
// ascott
import * as vscode from 'vscode';
import fs = require('fs');
import semver = require('semver');

// Custom Types
import * as ModuleCheck from '../../../models/ModuleCheckResult';

// util
import * as exec from '../../utils/execUtil';

const MINIMUM_VERSION = '3.5.0';
const VERSION_PATTERN = /\/python(\d\.\d+)$/;

export async function check() {
    console.log('Python virtualenv version check is running');
    let lessThanMinimumVersionDetected: ModuleCheck.ModuleCheckResult = {
        violated: false
    }
    let files = await vscode.workspace.findFiles('**/bin/python*', null, 10);
    if (files) {
        files.forEach(file => {
            const found = VERSION_PATTERN.exec(file.path);
            if (found && found.length >= 2) {
                const parsedVersion = callPythonBinaryForVersion(file.path);
                if (semver.gt(MINIMUM_VERSION, parsedVersion)) {
                    lessThanMinimumVersionDetected = {
                        violated: true,
                        value: {
                            path: file.path,
                            result: parsedVersion,
                            message: `Found python version ${parsedVersion} on path ${file.path} - Minimum is ${MINIMUM_VERSION}`
                        }
                    };
                    console.log(lessThanMinimumVersionDetected.value!.message!);
                }
            }
        });
    }
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

function callPythonBinaryForVersion(path: string) {
    const execOutput = exec._exec(path, ['--version']);
    return ensureValidSemVer(execOutput.replace('Python ', '').trim());
}