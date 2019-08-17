const { spawnSync } = require('child_process');

//
// Calls cmd line and returns stderr or stdout
// Note: This call is blocking
// Note: *nix support only
//
export function _exec(cmd: string, args: string[]) {
    const resp = spawnSync( cmd, args);
    return resp.stderr.toString() || resp.stdout.toString();
}