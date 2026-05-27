import { FC } from 'react'

type Result = {
  file: string
  line: number
  function: string
  description: string
  category: string
  severity: string
  owasp_category: string
  language: string
  timestamp: string
  scan_id: string
  confidence: string
}

interface ResultsTableProps {
  paginatedResults: Result[]
}

const ResultsTable: FC<ResultsTableProps> = ({ paginatedResults }) => (
  <div className="overflow-x-auto">
    <table className="w-full border-collapse">
      <thead>
        <tr className="bg-gray-200 text-left">
          <th className="border p-3">File</th>
          <th className="border p-3">Line</th>
          <th className="border p-3">Function</th>
          <th className="border p-3">Description</th>
          <th className="border p-3">Category</th>
          <th className="border p-3">Severity</th>
          <th className="border p-3">OWASP</th>
          <th className="border p-3">Language</th>
          <th className="border p-3">Confidence</th>
        </tr>
      </thead>
      <tbody>
        {paginatedResults.length > 0 ? (
          paginatedResults.map((r, i) => (
            <tr key={i} className="hover:bg-gray-50">
              <td className="border p-3">{r.file}</td>
              <td className="border p-3">{r.line}</td>
              <td className="border p-3">{r.function}</td>
              <td className="border p-3">{r.description}</td>
              <td className="border p-3">{r.category}</td>
              <td className="border p-3">{r.severity}</td>
              <td className="border p-3">{r.owasp_category}</td>
              <td className="border p-3">{r.language}</td>
              <td className="border p-3">{r.confidence}</td>
            </tr>
          ))
        ) : (
          <tr><td colSpan={9} className="border p-3 text-center">No results found</td></tr>
        )}
      </tbody>
    </table>
  </div>
)

export default ResultsTable