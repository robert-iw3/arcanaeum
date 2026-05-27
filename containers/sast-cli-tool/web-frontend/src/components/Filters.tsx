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

interface FiltersProps {
  severityFilter: string
  setSeverityFilter: (val: string) => void
  owaspFilter: string
  setOwaspFilter: (val: string) => void
  languageFilter: string
  setLanguageFilter: (val: string) => void
  categoryFilter: string
  setCategoryFilter: (val: string) => void
  searchQuery: string
  setSearchQuery: (val: string) => void
  results: Result[]
  exportToCsv: () => void
}

const Filters: FC<FiltersProps> = ({
  severityFilter,
  setSeverityFilter,
  owaspFilter,
  setOwaspFilter,
  languageFilter,
  setLanguageFilter,
  categoryFilter,
  setCategoryFilter,
  searchQuery,
  setSearchQuery,
  results,
  exportToCsv
}) => (
  <div className="mb-6 flex flex-wrap gap-4">
    <div className="w-full sm:w-48">
      <label className="block text-sm font-medium text-gray-700" htmlFor="severity-filter">Severity</label>
      <select
        id="severity-filter"
        className="mt-1 block w-full border rounded-md p-2"
        value={severityFilter}
        onChange={e => setSeverityFilter(e.target.value)}
        aria-label="Severity Filter"
      >
        <option value="">All Severities</option>
        {[...new Set(results.map(r => r.severity))]
          .sort((a, b) => ['Critical', 'High', 'Medium', 'Low'].indexOf(a) - ['Critical', 'High', 'Medium', 'Low'].indexOf(b))
          .map(sev => (
            <option key={sev} value={sev}>{sev}</option>
          ))}
      </select>
    </div>
    <div className="w-full sm:w-48">
      <label className="block text-sm font-medium text-gray-700" htmlFor="owasp-filter">OWASP Category</label>
      <select
        id="owasp-filter"
        className="mt-1 block w-full border rounded-md p-2"
        value={owaspFilter}
        onChange={e => setOwaspFilter(e.target.value)}
        aria-label="OWASP Filter"
      >
        <option value="">All OWASP</option>
        {[...new Set(results.map(r => r.owasp_category))].sort().map(cat => (
          <option key={cat} value={cat}>{cat}</option>
        ))}
      </select>
    </div>
    <div className="w-full sm:w-48">
      <label className="block text-sm font-medium text-gray-700" htmlFor="language-filter">Language</label>
      <select
        id="language-filter"
        className="mt-1 block w-full border rounded-md p-2"
        value={languageFilter}
        onChange={e => setLanguageFilter(e.target.value)}
        aria-label="Language Filter"
      >
        <option value="">All Languages</option>
        {[...new Set(results.map(r => r.language))].sort().map(lang => (
          <option key={lang} value={lang}>{lang}</option>
        ))}
      </select>
    </div>
    <div className="w-full sm:w-48">
      <label className="block text-sm font-medium text-gray-700" htmlFor="category-filter">Category</label>
      <select
        id="category-filter"
        className="mt-1 block w-full border rounded-md p-2"
        value={categoryFilter}
        onChange={e => setCategoryFilter(e.target.value)}
        aria-label="Category Filter"
      >
        <option value="">All Categories</option>
        {[...new Set(results.map(r => r.category))].sort().map(cat => (
          <option key={cat} value={cat}>{cat}</option>
        ))}
      </select>
    </div>
    <div className="w-full sm:w-48">
      <label className="block text-sm font-medium text-gray-700" htmlFor="search-input">Search</label>
      <input
        id="search-input"
        className="mt-1 block w-full border rounded-md p-2"
        value={searchQuery}
        onChange={e => setSearchQuery(e.target.value.replace(/[<>"'&]/g, ''))}
        placeholder="Search function, file, or description"
        aria-label="Search Input"
      />
    </div>
    <button
      className="mt-6 bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition"
      onClick={exportToCsv}
      aria-label="Export to CSV"
    >
      Export to CSV
    </button>
  </div>
)

export default Filters