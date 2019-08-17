# Check Modules

## Overview
"Checks" are the name given by Ochrona to additional tests or plugins, usually security related, that are run by Ochrona in addition to dependency checks.

## Rules for Checks
1. Check modules must expose a single method named `check`
2. Checks must take no arguments, but may be configured at a global level.
3. Checks must return a `ModuleCheckResults` object.
4. Checks must be `async`.

### Example Check Response
```
// Version Check 
{
    violated: true,
    value: {
        path:  '/Users/andrewscott/Dev/vulnerable_python_app/.venv/bin python2.7',
        result: '2.7.10'
    }
}
```