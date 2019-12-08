// Ochrona Security 2019
// ascott
import * as vscode from 'vscode';

const fs = require('fs');

const REQUIREMENTS_TXT = '*requirements*.txt';
const PIPFILE_LOCK = '*Pipfile.lock';

async function findRequirementsTxt() {
    let files = await vscode.workspace.findFiles(REQUIREMENTS_TXT, null, 10);
    let findings: string[] = [];
    let paths: string[] = [];
	if (files.length > 0) {
		files.forEach( async function(file) {
			if (file.path) {
                console.log(`Found requirements.txt type file at ${file.path}`);
                paths.push(file.path);
                findings = findings.concat(parseRequirementsTxt(file.path))
			}
		});
    };
    return toObj(paths, findings)
}

function parseRequirementsTxt(path: string): string[] {
    let parsed: string[] = [];
    fs.readFileSync(path, 'utf-8').split(/\r?\n/).forEach(function(line: string) {
        parsed.push(line)
    });
    return parsed;
}

async function findPipfileLock() {
    let files = await vscode.workspace.findFiles(PIPFILE_LOCK, null, 10);
    let findings: string[] = [];
    let paths: string[] = [];
	if (files.length > 0) {
		files.forEach( async function(file) {
			if (file.path) {
                console.log(`Found Pipfile.lock type file at ${file.path}`);
                paths.push(file.path);
                findings = findings.concat(parsePipfileLock(file.path))
			}
		});
    };
    return toObj(paths, findings)
}

function parsePipfileLock(path: string): string[] {
    var file = fs.readFileSync(path, 'utf-8');
    let j = JSON.parse(file.toString());
    return Object.keys(j.default).map((k: string) => `${k}${j.default[k].version}`);
}

function toObj(path: string[], pkgs: string[]): any {
    return {
        path,
        pkgs
    };
}

export async function checkPrimaryDependenciesFile(callback: Function) {
    let pips: any = await findPipfileLock();
    let reqs: any = await findRequirementsTxt()
    callback(pips.path.concat(reqs.path), pips.pkgs.concat(reqs.pkgs))
}