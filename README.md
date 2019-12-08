# Ochrona

Ochrona is an easy to use Dependency Analysis tool for python designed to shift security as far left as possible (into your IDE).

Read more at [Ochrona.dev](https://ochrona.dev)

## Usage

This Extension adds the `Ochrona` command which will detect all known python dependencies files and check them against Ochrona's repository of known python vulnerabilities. 

In the command palette (`CMD` + `SHIFT` + `P`), type `Ochrona`.
![run ochrona](resources/command.png)

## Features

Ochrona supports the following file types:
- `*requirements*.txt`
- `Pipfile.lock`

A warning is displayed if a vulnerability is discovered.
![vulns found alert](resources/found_vuln_warning.png)

A brief report is included in the VS Code Output tab for any discovered vulnerabilities.
![vulns found output](resources/found_vuln_output.png)

You can re-run the plugin by clicking the Ochrona Status Bar Icon.
![vulns found sb](resources/found_vuln_status_bar.png)
![vulns not found sb](resources/no_vuln_status_bar.png)

## Extension Settings

An Ochrona API key is required for use of this extension. You may register for a free license at [Ochrona.dev](https://ochrona.dev).

To set this open the VS Code Settings (Code -> Preferences -> Settings) or (`CMD` + `,`)
![settings](resources/settings.png)

## Demo
![demo](resources/ochrona_vs.gif)

## Release Notes

### 0.0.1
- Support for checking `*requirement*.txt` and `Pipfile.lock` files for known python vulnerabilities.
