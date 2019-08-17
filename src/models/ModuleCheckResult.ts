export interface ModuleCheckResult {
    violated: boolean,
    value?: ModuleCheckResultValue
}

interface ModuleCheckResultValue {
    path?: string,
    result?: string
    message?: string
}