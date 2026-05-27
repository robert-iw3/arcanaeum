import { FC } from 'react'

type CveMatch = {
  dependency: string
  version: string
  cve_id: string
  file: string
}

type Summary = {
  total_files?: number
  files_scanned?: number
  vulnerabilities?: number
  scan_start?: string
  scan_end?: string
  by_owasp?: Record<string, number>
  by_severity?: Record<string, number>
  cve_matches?: CveMatch[]
}

interface SummaryPanelProps {
  summary: Summary
  cveMatches: CveMatch[]
}

const SummaryPanel: FC<SummaryPanelProps> = ({ summary, cveMatches }) => (
  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
    <div className="bg-gray-50 p-4 rounded-md shadow-sm">
      <h2 className="text-xl font-semibold mb-2 text-gray-800">Scan Summary</h2>
      <p><strong>Total Files:</strong> {summary.total_files || 0}</p>
      <p><strong>Files Scanned:</strong> {summary.files_scanned || 0}</p>
      <p><strong>Vulnerabilities:</strong> {summary.vulnerabilities || 0}</p>
      <p><strong>Scan Start:</strong> {summary.scan_start || 'N/A'}</p>
      <p><strong>Scan End:</strong> {summary.scan_end || 'N/A'}</p>
      {summary.by_owasp && (
        <>
          <h3 className="mt-3 font-semibold text-gray-700">By OWASP Category</h3>
          {Object.entries(summary.by_owasp).map(([cat, count]) => (
            <p key={cat}><strong>{cat}:</strong> {count}</p>
          ))}
        </>
      )}
      {summary.by_severity && (
        <>
          <h3 className="mt-3 font-semibold text-gray-700">By Severity</h3>
          {Object.entries(summary.by_severity).map(([sev, count]) => (
            <p key={sev}><strong>{sev}:</strong> {count}</p>
          ))}
        </>
      )}
    </div>
    <div className="bg-gray-50 p-4 rounded-md shadow-sm">
      <h2 className="text-xl font-semibold mb-2 text-gray-800">CVE Matches</h2>
      <div className="overflow-x-auto">
        <table className="w-full table-auto">
          <thead>
            <tr className="bg-gray-200 text-left">
              <th className="px-3 py-2">Dependency</th>
              <th className="px-3 py-2">Version</th>
              <th className="px-3 py-2">CVE ID</th>
              <th className="px-3 py-2">File</th>
            </tr>
          </thead>
          <tbody>
            {cveMatches.length > 0 ? (
              cveMatches.map((cve, i) => (
                <tr key={i} className="hover:bg-gray-100">
                  <td className="border px-3 py-2">{cve.dependency || 'N/A'}</td>
                  <td className="border px-3 py-2">{cve.version || 'N/A'}</td>
                  <td className="border px-3 py-2">{cve.cve_id || 'N/A'}</td>
                  <td className="border px-3 py-2">{cve.file || 'N/A'}</td>
                </tr>
              ))
            ) : (
              <tr><td colSpan={4} className="border px-3 py-2 text-center">No CVE matches found</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  </div>
)

export default SummaryPanel