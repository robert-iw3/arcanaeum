import { FC } from 'react'

interface PaginationProps {
  currentPage: number
  totalPages: number
  setCurrentPage: (val: number) => void
}

const Pagination: FC<PaginationProps> = ({ currentPage, totalPages, setCurrentPage }) => (
  <div className="mt-4 flex justify-between items-center">
    <button
      className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:bg-gray-400 transition"
      disabled={currentPage === 1}
      onClick={() => setCurrentPage(currentPage - 1)}
      aria-label="Previous Page"
    >
      Previous
    </button>
    <span className="text-gray-700">Page {currentPage} of {totalPages}</span>
    <button
      className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:bg-gray-400 transition"
      disabled={currentPage === totalPages}
      onClick={() => setCurrentPage(currentPage + 1)}
      aria-label="Next Page"
    >
      Next
    </button>
  </div>
)

export default Pagination