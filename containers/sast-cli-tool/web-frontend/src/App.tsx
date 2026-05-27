import { useState, useEffect } from 'react';
import axios from 'axios';
import Cookies from 'js-cookie';
import toast from 'react-hot-toast';
import { z } from 'zod';

const ResultSchema = z.object({
  file: z.string(),
  line: z.number(),
  function: z.string(),
  description: z.string(),
  category: z.string(),
  severity: z.string(),
  owasp_category: z.string(),
  language: z.string(),
  timestamp: z.string(),
  scan_id: z.string(),
  confidence: z.string(),
});

const SummarySchema = z.object({
  total_files: z.number(),
  files_scanned: z.number(),
  vulnerabilities: z.number(),
  scan_start: z.string().optional(),
  scan_end: z.string().optional(),
  by_owasp: z.record(z.number()),
  by_severity: z.record(z.number()),
  by_category: z.record(z.number()),
  by_language: z.record(z.number()),
  cve_matches: z.array(
    z.object({
      dependency: z.string(),
      version: z.string(),
      cve_id: z.string(),
      file: z.string(),
      severity: z.string(),
      description: z.string(),
      published_date: z.string().optional(),
      cvss_score: z.number().optional(),
    })
  ),
});

const ResponseSchema = z.object({
  results: z.array(ResultSchema),
  summary: SummarySchema,
});

type ResponseData = z.infer<typeof ResponseSchema>;

const App = () => {
  const [data, setData] = useState<ResponseData>({ results: [], summary: { total_files: 0, files_scanned: 0, vulnerabilities: 0, by_owasp: {}, by_severity: {}, by_category: {}, by_language: {}, cve_matches: [] } });
  const [theme, setTheme] = useState<'light' | 'dark'>('light');

  useEffect(() => {
    // Load theme from local storage
    const savedTheme = localStorage.getItem('theme') as 'light' | 'dark' | null;
    if (savedTheme) {
      setTheme(savedTheme);
      document.documentElement.setAttribute('data-theme', savedTheme);
    } else {
      document.documentElement.setAttribute('data-theme', 'light');
    }

    // Fetch scan results
    const fetchData = async () => {
      try {
        const token = Cookies.get('jwt_token');
        const response = await axios.get(`${import.meta.env.VITE_API_URL}/results`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        const parsed = ResponseSchema.parse(response.data);
        setData(parsed);
        toast.success('Results loaded successfully', { position: 'top-right' });
      } catch (error) {
        toast.error('Failed to load results', { position: 'top-right' });
        console.error(error);
      }
    };
    fetchData();
  }, []);

  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-100 to-gray-200 dark:from-gray-800 dark:to-gray-900 transition-colors duration-300">
      <div className="container mx-auto p-6">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-4xl font-extrabold text-gray-800 dark:text-gray-100 tracking-tight">Static Code Analyzer</h1>
          <div className="flex items-center space-x-2">
            <span className="text-sm font-medium text-gray-600 dark:text-gray-300">
              {theme === 'light' ? 'Light' : 'Dark'} Mode
            </span>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" checked={theme === 'dark'} onChange={toggleTheme} className="sr-only" />
              <div className="w-12 h-6 bg-gray-300 dark:bg-gray-600 rounded-full shadow-inner transition-all duration-300"></div>
              <div className={`absolute w-5 h-5 bg-white dark:bg-gray-200 rounded-full shadow transform transition-transform duration-300 ${theme === 'dark' ? 'translate-x-6' : 'translate-x-1'}`}></div>
            </label>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 shadow-lg rounded-lg p-6 mb-6 transform hover:scale-[1.01] transition-transform duration-200">
          <h2 className="text-2xl font-bold text-gray-800 dark:text-gray-100 mb-4">Vulnerabilities</h2>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  {['File', 'Line', 'Function', 'Description', 'Severity', 'OWASP Category', 'Language', 'Confidence'].map((header) => (
                    <th key={header} className="p-4 text-sm font-semibold text-gray-600 dark:text-gray-300 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
                      {header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.results.map((result, index) => (
                  <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors duration-200">
                    <td className="p-4 text-sm text-gray-800 dark:text-gray-100">{result.file}</td>
                    <td className="p-4 text-sm text-gray-800 dark:text-gray-100">{result.line}</td>
                    <td className="p-4 text-sm text-gray-800 dark:text-gray-100">{result.function}</td>
                    <td className="p-4 text-sm text-gray-800 dark:text-gray-100">{result.description}</td>
                    <td
                      className={`p-4 text-sm font-medium ${
                        result.severity === 'Critical' ? 'text-red-600 dark:text-red-400' : 'text-yellow-600 dark:text-yellow-400'
                      }`}
                    >
                      {result.severity}
                    </td>
                    <td className="p-4 text-sm text-gray-800 dark:text-gray-100">{result.owasp_category}</td>
                    <td className="p-4 text-sm text-gray-800 dark:text-gray-100">{result.language}</td>
                    <td className="p-4 text-sm text-gray-800 dark:text-gray-100">{result.confidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white dark:bg-gray-800 shadow-lg rounded-lg p-6 transform hover:scale-[1.01] transition-transform duration-200">
            <h2 className="text-2xl font-bold text-gray-800 dark:text-gray-100 mb-4">Summary</h2>
            <p className="text-sm text-gray-600 dark:text-gray-300 mb-2">Total Files: {data.summary.total_files}</p>
            <p className="text-sm text-gray-600 dark:text-gray-300 mb-2">Files Scanned: {data.summary.files_scanned}</p>
            <p className="text-sm text-gray-600 dark:text-gray-300 mb-2">Vulnerabilities: {data.summary.vulnerabilities}</p>
            <p className="text-sm text-gray-600 dark:text-gray-300 mb-2">Scan Start: {data.summary.scan_start || 'N/A'}</p>
            <p className="text-sm text-gray-600 dark:text-gray-300">Scan End: {data.summary.scan_end || 'N/A'}</p>
          </div>
          <div className="bg-white dark:bg-gray-800 shadow-lg rounded-lg p-6 transform hover:scale-[1.01] transition-transform duration-200">
            <h2 className="text-2xl font-bold text-gray-800 dark:text-gray-100 mb-4">CVE Matches</h2>
            {data.summary.cve_matches.length > 0 ? (
              data.summary.cve_matches.map((cve, index) => (
                <div key={index} className="text-sm text-gray-600 dark:text-gray-300 mb-4">
                  <p className="font-medium">CVE: {cve.cve_id}</p>
                  <p>Dependency: {cve.dependency}@{cve.version}</p>
                  <p>Severity: {cve.severity}</p>
                  <p>Description: {cve.description}</p>
                </div>
              ))
            ) : (
              <p className="text-sm text-gray-600 dark:text-gray-300">No CVE matches found</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;