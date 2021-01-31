// Ochrona Security 2019
// ascott
import * as vscode from 'vscode';
import * as FileTypes from '../models/FileTypes';


const fs = require('fs');
const toml = require('toml');

const REQUIREMENTS_TXT = '*requirements*.txt';
const PIPFILE_LOCK = '*Pipfile.lock';
const POETRY_LOCK = '*poetry.lock';
const INVALID_REQUIREMENTS_LINES = [
    "#",
    "-i",
    "-f",
    "-Z",
    "--index-url",
    "--extra-index-url",
    "--find-links",
    "--no-index",
    "--allow-external",
    "--allow-unverified",
    "--always-unzip",
];

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
        for (let pattern of INVALID_REQUIREMENTS_LINES) {
            if (!line.startsWith(pattern) && line != "") {
                parsed.push(line);
                break;
            }
        }
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

async function findPoetryLock() {
    let files = await vscode.workspace.findFiles(POETRY_LOCK, null, 10);
    let findings: string[] = [];
    let paths: string[] = [];
	if (files.length > 0) {
		files.forEach( async function(file) {
			if (file.path) {
                console.log(`Found poetry.lock type file at ${file.path}`);
                paths.push(file.path);
                findings = findings.concat(parsePoetryLock(file.path))
			}
		});
    };
    return toObj(paths, findings)
}

function parsePoetryLock(path: string): string[] {
    var file = fs.readFileSync(path, 'utf-8');
    let t = toml.parse(file.toString());
    console.log(t)
    let results: string[] = [];
    let packages: FileTypes.PoetryPackage[] = t.package;
    for (let pkg of packages) {
        results.push(`${pkg.name}==${pkg.version}`);
    }
    console.log(results);
    return results;
}

function toObj(path: string[], pkgs: string[]): any {
    return {
        path,
        pkgs
    };
}

export async function checkPrimaryDependenciesFile(callback: Function, err: Function) {
    try {
        let pips: any = await findPipfileLock();
        let poems: any = await findPoetryLock();
        let reqs: any = await findRequirementsTxt();
        console.log(pips.pkgs, reqs.pkgs, poems.pkgs);
        callback(pips.path.concat(reqs.path, poems.path), pips.pkgs.concat(reqs.pkgs, poems.pkgs));
    } catch (e) {
        console.log(e);
        err(0, true);
    }
}
