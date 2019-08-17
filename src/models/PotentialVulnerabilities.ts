export interface PotentialVulnerability {
    package_name: string,
    vulnerabilities: Vulnerability[]
}

interface Vulnerability {
    name?: string,
    language?: string,
    description?: string,
    owner?: string,
    license?: string,
    pypi_summary?: string,
    references?: string,
    latest_version?: string,
    cve_id?: string,
    affected_versions?: AffectedVersion[]
}

interface AffectedVersion {
    version_value?: string,
    version_affected?: string
}