import { CodeInputProps } from '@/types/security';
import FileUpload from './FileUpload';

/**
 * Code input section with file upload, URL input, website scanning, and code display
 */
export default function CodeInput({
  codeContent,
  fileName,
  onFileUpload,
  onAnalyzeCode,
  isAnalyzing,
  urlInput,
  onUrlInputChange,
  onFetchUrl,
  websiteInput,
  onWebsiteInputChange,
  inputMode,
  onToggleInputMode
}: CodeInputProps) {
  const getPlaceholder = () => {
    switch (inputMode) {
      case 'file':
        return "Select a Python file to display its contents here...";
      case 'url':
        return "Enter a URL to fetch Python code...";
      case 'website':
        return "Enter a website URL to scan for security vulnerabilities...";
      default:
        return "Select an input method...";
    }
  };

  return (
    <div className="bg-white rounded-lg border border-border shadow-sm p-6 flex flex-col">
      <div className="flex items-center justify-between mb-4 flex-shrink-0">
        <label htmlFor="code-input" className="text-lg font-semibold text-foreground">
          {inputMode === 'website' ? 'Website to scan' : 'Code to analyze'}
        </label>

        <FileUpload
          fileName={fileName}
          onFileUpload={onFileUpload}
          onAnalyzeCode={onAnalyzeCode}
          isAnalyzing={isAnalyzing}
          hasCode={!!codeContent || !!websiteInput}
          urlInput={urlInput}
          onUrlInputChange={onUrlInputChange}
          onFetchUrl={onFetchUrl}
          websiteInput={websiteInput}
          onWebsiteInputChange={onWebsiteInputChange}
          inputMode={inputMode}
          onToggleInputMode={onToggleInputMode}
        />
      </div>

      <textarea
        id="code-input"
        value={codeContent}
        readOnly
        placeholder={getPlaceholder()}
        className="flex-1 w-full resize-none border border-border rounded-lg p-4 font-mono text-sm bg-input-bg focus:outline-none focus:ring-2 focus:ring-primary/50"
      />
    </div>
  );
}