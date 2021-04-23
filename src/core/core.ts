// Ochrona Security 2019
// ascott
import * as vscode from 'vscode';
import * as FileTypes from '../models/FileTypes';


const fs = require('fs');
const path = require('path');
const toml = require('toml');
const ini = require("ini");
const yaml = require('js-yaml');

const REQUIREMENTS_TXT = '**/*requirements*.txt';
const REQUIREMENTS_TXT_PATTERN = '.*requirements.*\.txt'
const PIPFILE_LOCK = '**/*Pipfile.lock';
const PIPFILE_LOCK_PATTERN = '.*Pipfile\.lock'
const POETRY_LOCK = '**/*poetry.lock';
const POETRY_LOCK_PATTERN = '.*poetry\.lock'
const TOX_INI = '**/*tox.ini';
const TOX_INI_PATTERN = '.*tox\.ini'
const ENVIRONMENT_YML = '**/*environment.yml';
const ENVIRONMENT_YML_PATTERN = '.*environment\.yml'
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

async function findRequirementsTxt(explicit?: string) {
    let files: vscode.Uri[];
    if (explicit != null) {
        files = [vscode.Uri.parse(explicit)];
    } else {
        files = await vscode.workspace.findFiles(REQUIREMENTS_TXT, null, 10);
    }
    let findings: string[] = [];
    let paths: string[] = [];
	if (files.length > 0) {
		files.forEach( async function(file) {
			if (file.path) {
                let normalized_path = path.normalize(file.path);
                console.log(`Found requirements.txt type file at ${normalized_path}`);
                paths.push(normalized_path);
                findings = findings.concat(parseRequirementsTxt(normalized_path))
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

async function findPipfileLock(explicit?: string) {
    let files: vscode.Uri[];
    if (explicit != null) {
        files = [vscode.Uri.parse(explicit)];
    } else {
        files = await vscode.workspace.findFiles(PIPFILE_LOCK, null, 10);
    }
    let findings: string[] = [];
    let paths: string[] = [];
	if (files.length > 0) {
		files.forEach( async function(file) {
			if (file.path) {
                let normalized_path = path.normalize(file.path);
                console.log(`Found Pipfile.lock type file at ${normalized_path}`);
                paths.push(normalized_path);
                findings = findings.concat(parsePipfileLock(normalized_path))
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

async function findPoetryLock(explicit? : string) {
    let files: vscode.Uri[];
    if (explicit != null) {
        files = [vscode.Uri.parse(explicit)];
    } else {
        files = await vscode.workspace.findFiles(POETRY_LOCK, null, 10);
    }
    let findings: string[] = [];
    let paths: string[] = [];
	if (files.length > 0) {
		files.forEach( async function(file) {
			if (file.path) {
                let normalized_path = path.normalize(file.path);
                console.log(`Found poetry.lock type file at ${normalized_path}`);
                paths.push(normalized_path);
                findings = findings.concat(parsePoetryLock(normalized_path))
			}
		});
    };
    return toObj(paths, findings)
}

function parsePoetryLock(path: string): string[] {
    var file = fs.readFileSync(path, 'utf-8');
    let t = toml.parse(file.toString());
    let results: string[] = [];
    let packages: FileTypes.PoetryPackage[] = t.package;
    for (let pkg of packages) {
        results.push(`${pkg.name}==${pkg.version}`);
    }
    return results;
}

async function findToxini(explicit? : string) {
    let files: vscode.Uri[];
    if (explicit != null) {
        files = [vscode.Uri.parse(explicit)];
    } else {
        files = await vscode.workspace.findFiles(TOX_INI, null, 10);
    }
    let findings: string[] = [];
    let paths: string[] = [];
	if (files.length > 0) {
		files.forEach( async function(file) {
			if (file.path) {
                let normalized_path = path.normalize(file.path);
                console.log(`Found tox.ini type file at ${normalized_path}`);
                paths.push(normalized_path);
                findings = findings.concat(parseToxini(normalized_path))
			}
		});
    };
    return toObj(paths, findings)
}

function parseToxini(path: string): string[] {
    try {
        let results: string[] = [];
        var file = fs.readFileSync(path, 'utf-8');
        let value = ini.parse(file);
        Object.keys(value).forEach(function(section) {
            let val = value[section];
            if ('deps' in val) {
                if (value[section]['deps'] != '') {
                    results.push(value[section]['deps'])
                } else {
                    // node's ini parser doesn't like line continuation
                    for (let opt of Object.keys(val)) {
                        if (value[section][opt] == '' && opt != 'deps') {
                            // break once we encounter a new option entry
                            break;
                        }
                        if (opt.includes(':')) {
                            // This will be a dependency secified with a specific version of python
                            // @ts-ignore
                            let extractedDep: string = opt.split(':').pop().trim();
                            if (typeof value[section][opt] == 'string') {
                                // more super gross ini parsing
                                extractedDep = `${extractedDep}=${value[section][opt]}`;
                            }
                            results.push(extractedDep);
                        } else if (opt.startsWith('-r')){
                            // This will be a referenced requirements.txt file
                            let referencedBasePath: string = vscode.Uri.parse(path).path.replace('tox.ini', '');
                            let referencedFileName: string = opt.replace('-r', '').trim();
                            console.log(`Found referenced requirements file in tox.ini at ${referencedBasePath}${referencedFileName}`);
                            let referencedRequirementsParsed: string[] = parseRequirementsTxt(`${referencedBasePath}${referencedFileName}`)
                            results = results.concat(referencedRequirementsParsed);
                        } else if (opt != 'deps') {
                            // We assume this is just a plain dependency
                            let extractedDep: string = opt.trim()
                            if (typeof value[section][opt] == 'string') {
                                // more super gross ini parsing
                                extractedDep = `${extractedDep}=${value[section][opt]}`
                            }
                            results.push(extractedDep)
                        }
                    }
                }
            }
        });
        return results;
    } catch (e) {
        console.warn(e);
        return [];
    }
}

async function findEnvironmentYml(explicit?: string) {
    let files: vscode.Uri[];
    if (explicit != null) {
        files = [vscode.Uri.parse(explicit)];
    } else {
        files = await vscode.workspace.findFiles(ENVIRONMENT_YML, null, 10);
    }
    let findings: string[] = [];
    let paths: string[] = [];
	if (files.length > 0) {
		files.forEach( async function(file) {
			if (file.path) {
                let normalized_path = path.normalize(file.path);
                console.log(`Found environment.yml type file at ${normalized_path}`);
                paths.push(normalized_path);
                findings = findings.concat(parseEnvironmentYml(normalized_path))
			}
		});
    };
    return toObj(paths, findings)
}

function parseEnvironmentYml(path: string): string[] {
    try {
        let file = fs.readFileSync(path, 'utf-8');
        let value = yaml.load(file);
        let results: string[] = [];
        if ('dependencies' in value) {
            value.dependencies.forEach(function(dep: any) {
                if (typeof dep == 'string') {
                    results.push(dep);
                } else if (typeof dep == 'object') {
                    if ('pip' in dep) {
                        dep.pip.forEach(function(subDep: string) {
                            results.push(subDep);
                        })
                    }
                }
            })
        }
        return results;
    } catch (e) {
        console.warn(e);
        return [];
    }
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
        let toxs: any = await findToxini();
        let envs: any = await findEnvironmentYml();
        callback(pips.path.concat(reqs.path, poems.path, toxs.path, envs.path), pips.pkgs.concat(reqs.pkgs, poems.pkgs, toxs.pkgs, envs.pkgs));
    } catch (e) {
        console.warn(e);
        err(0, true);
    }
}

export async function checkExplicitDependencyFile(file: string, callback: Function, err: Function) {
    try {
        let reqs: any = {path: [], pkgs: []};
        if (file.match(REQUIREMENTS_TXT_PATTERN)) {
            reqs = await findRequirementsTxt(file);
        } else if (file.match(PIPFILE_LOCK_PATTERN)) {
            reqs = await findPipfileLock(file);
        } else if (file.match(POETRY_LOCK_PATTERN)) {
            reqs = await findPoetryLock(file);
        } else if (file.match(TOX_INI_PATTERN)) {
            reqs = await findToxini(file);
        } else if (file.match(ENVIRONMENT_YML_PATTERN)) {
            reqs = await findEnvironmentYml(file);
        }
        
        callback(reqs.path, reqs.pkgs);
    } catch (e) {
        console.warn(e);
        err(0, true);
    }
}

export function isApplicableFile(file: string): boolean {
    if (file.match(REQUIREMENTS_TXT_PATTERN)) {
        return true;
    } else if (file.match(PIPFILE_LOCK_PATTERN)) {
        return true;
    } else if (file.match(POETRY_LOCK_PATTERN)) {
        return true;
    } else if (file.match(TOX_INI_PATTERN)) {
        return true;
    } else if (file.match(ENVIRONMENT_YML_PATTERN)) {
        return true;
    } else {
        return false;
    }
}
