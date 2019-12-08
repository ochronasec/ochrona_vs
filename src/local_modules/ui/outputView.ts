// Ochrona Security 2019
// ascott
import * as vscode from 'vscode';

import { PotentialVulnerability, Vulnerability } from '../../models/PotentialVulnerabilities';

/**
 * Manages cat coding webview panels
 */
export class OutputView {
	/**
	 * Track the currently panel. Only allow a single panel to exist at a time.
	 */
	public static currentPanel: OutputView | undefined;

	public static readonly viewType = 'outputView';

	private readonly _panel: vscode.WebviewPanel;
	private _disposables: vscode.Disposable[] = [];

	public static createOrShow(paths: string[], pvulns: any[], cvulns: any[]) {
		const column = vscode.window.activeTextEditor
			? vscode.window.activeTextEditor.viewColumn
			: undefined;

		// // If we already have a panel, show it.
		if (OutputView.currentPanel) {
			OutputView.currentPanel._panel.reveal(column);
			return;
		}

		// Otherwise, create a new panel.
		const panel = vscode.window.createWebviewPanel(
			OutputView.viewType,
			'Ochrona',
			vscode.ViewColumn.One,
			{
				// Enable javascript in the webview
				enableScripts: false
			}
		);

		OutputView.currentPanel = new OutputView(panel, paths, pvulns, cvulns);
	}

	public static revive(panel: vscode.WebviewPanel, paths: string[], pvulns: any[], cvulns: any[]) {
		OutputView.currentPanel = new OutputView(panel, paths, pvulns, cvulns);
	}

	private constructor(panel: vscode.WebviewPanel, paths: string[], pvulns: any[], cvulns: any[]) {
		this._panel = panel;
		// Set the webview's initial html content
		this._update(paths, pvulns, cvulns);

		// Listen for when the panel is disposed
		// This happens when the user closes the panel or when the panel is closed programatically
		this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

		// Update the content based on view changes
		this._panel.onDidChangeViewState(
			e => {
				if (this._panel.visible) {
					this._update(paths, pvulns, cvulns);
				}
			},
			null,
			this._disposables
		);

		// Handle messages from the webview
		this._panel.webview.onDidReceiveMessage(
			message => {
				switch (message.command) {
					case 'alert':
						vscode.window.showErrorMessage(message.text);
						return;
				}
			},
			null,
			this._disposables
		);
	}

	public doRefactor() {
		// Send a message to the webview webview.
		// You can send any JSON serializable data.
		this._panel.webview.postMessage({ command: 'refactor' });
	}

	public dispose() {
		OutputView.currentPanel = undefined;

		// Clean up our resources
		this._panel.dispose();

		while (this._disposables.length) {
			const x = this._disposables.pop();
			if (x) {
				x.dispose();
			}
		}
	}

	private _update(paths: string[], pvulns: any[], cvulns: any[]) {
        const webview = this._panel.webview;
        this._panel.webview.html = this._getHtmlForWebview(webview, paths, pvulns, cvulns);
    }
    
    private _generate_tr(vuln: any): string {
		console.log('[[[[[', vuln)
        return `<tr>
			<td>${vuln.name}</td>
			<td>${vuln.found_version}</td>
			<td>${vuln.ochrona_severity_score}</td>
		</tr>
		<tr>
			<td colspan="3">${vuln.description}</td>
		</tr>
		<tr>
			<td colspan="3">${vuln.reason}</td>
		</tr>`
    }

	private _getHtmlForWebview(webview: vscode.Webview, 
								paths: string[], 
								pvulns: PotentialVulnerability[], 
								cvulns: PotentialVulnerability[]) {

		// potential
		let prows = pvulns.map((v: any) => this._generate_tr(v))
		let pcount = `Discovered ${prows.length} potential vulnerabilies`;
		let ptable = `<table class="tg">
		<tr>
			<th>Package Name</th>
			<th>Version Detected</th>
			<th>Severity</th>
		</tr>
		${prows}
		</table>`;

		// confirmed
		let crows = cvulns.map((v: any) => this._generate_tr(v))
		let ccount = `Discovered ${crows.length} confirmed vulnerabilies`;
		let ctable = `<table class="tg">
		<tr>
			<th>Package Name</th>
			<th>Version Detected</th>
			<th>Severity</th>
		</tr>
		${crows}
		</table>`;

		let html = `<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Ochrona Scan Results</title>
				<style type="text/css">
					td{text-align:center;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;word-break:normal;border-color:white;}
					th{text-align:center;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;word-break:normal;border-color:white;}
				</style>
            </head>
            <body>
				<h1>Ochrona Results</h1>
				</br>
				<p>Analysis complete on the following dependency files: ${paths.join('</br>')}</p>
				</br>
				${prows.length > 0 ? `<b>${pcount}</b>${ptable}` : ''}
				</br>
				${crows.length > 0 ? `<b>${ccount}</b>${ctable}` : ''}
            </body>
            </html>`;
        console.log(html);
        return html;
	}
}