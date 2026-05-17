import { FileUploadProps } from '@/types/security';

/**
 * File upload button component for selecting Python files, entering URLs, or scanning websites
 */
export default function FileUpload({
  fileName,
  onFileUpload,
  onAnalyzeCode,
  isAnalyzing,
  hasCode,
  urlInput,
  onUrlInputChange,
  onFetchUrl,
  websiteInput,
  onWebsiteInputChange,
  inputMode,
  onToggleInputMode
}: FileUploadProps) {
  return (
    <div className="flex flex-col gap-4">
      {/* Toggle between File, URL, and Website modes */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => onToggleInputMode('file')}
          className={`px-4 py-2 rounded-lg transition-colors font-medium ${
            inputMode === 'file'
              ? 'bg-primary text-white'
              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
          }`}
        >
          📁 File
        </button>
        <button
          onClick={() => onToggleInputMode('url')}
          className={`px-4 py-2 rounded-lg transition-colors font-medium ${
            inputMode === 'url'
              ? 'bg-primary text-white'
              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
          }`}
        >
          🔗 URL
        </button>
        <button
          onClick={() => onToggleInputMode('website')}
          className={`px-4 py-2 rounded-lg transition-colors font-medium ${
            inputMode === 'website'
              ? 'bg-primary text-white'
              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
          }`}
        >
          🌐 Website
        </button>
      </div>

      <div className="flex items-center gap-4">
        {fileName && (
          <span className="text-sm text-accent bg-secondary/20 px-3 py-1 rounded-full">
            {fileName}
          </span>
        )}

        {inputMode === 'file' ? (
          <>
            <input
              type="file"
              accept=".py"
              onChange={onFileUpload}
              className="hidden"
              id="file-upload"
            />
            <label
              htmlFor="file-upload"
              className="bg-primary hover:bg-primary/90 text-white px-4 py-2 rounded-lg cursor-pointer transition-colors font-medium"
            >
              Open python file...
            </label>
          </>
        ) : inputMode === 'url' ? (
          <>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => onUrlInputChange(e.target.value)}
              placeholder="Enter Python file URL (e.g., https://raw.githubusercontent.com/user/repo/main/file.py)"
              className="flex-1 border border-border rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
            <button
              onClick={onFetchUrl}
              disabled={!urlInput || isAnalyzing}
              className="bg-primary hover:bg-primary/90 disabled:bg-gray-400 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg transition-colors font-medium"
            >
              Fetch
            </button>
          </>
        ) : (
          <>
            <input
              type="text"
              value={websiteInput}
              onChange={(e) => onWebsiteInputChange(e.target.value)}
              placeholder="Enter website URL (e.g., https://example.com)"
              className="flex-1 border border-border rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
          </>
        )}

        <button
          onClick={onAnalyzeCode}
          disabled={!hasCode || isAnalyzing}
          className="bg-accent hover:bg-accent/90 disabled:bg-gray-400 disabled:cursor-not-allowed text-white px-6 py-2 rounded-lg transition-colors font-medium"
        >
          {isAnalyzing ? 'Analyzing...' : inputMode === 'website' ? 'Scan website' : 'Analyze code'}
        </button>
      </div>
    </div>
  );
}