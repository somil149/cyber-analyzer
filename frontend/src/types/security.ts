/**
 * Type definitions for security analysis components
 */

export interface SecurityIssue {
  title: string;
  description: string;
  code: string;
  fix: string;
  cvss_score: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface AnalysisResponse {
  summary: string;
  issues: SecurityIssue[];
}

export interface FileUploadProps {
  fileName: string;
  onFileUpload: (event: React.ChangeEvent<HTMLInputElement>) => void;
  onAnalyzeCode: () => void;
  isAnalyzing: boolean;
  hasCode: boolean;
  urlInput: string;
  onUrlInputChange: (url: string) => void;
  onFetchUrl: () => void;
  websiteInput: string;
  onWebsiteInputChange: (url: string) => void;
  inputMode: 'file' | 'url' | 'website';
  onToggleInputMode: (mode: 'file' | 'url' | 'website') => void;
}

export interface CodeInputProps {
  codeContent: string;
  fileName: string;
  onFileUpload: (event: React.ChangeEvent<HTMLInputElement>) => void;
  onAnalyzeCode: () => void;
  isAnalyzing: boolean;
  urlInput: string;
  onUrlInputChange: (url: string) => void;
  onFetchUrl: () => void;
  websiteInput: string;
  onWebsiteInputChange: (url: string) => void;
  inputMode: 'file' | 'url' | 'website';
  onToggleInputMode: (mode: 'file' | 'url' | 'website') => void;
}

export interface AnalysisResultsProps {
  analysisResults: AnalysisResponse | null;
  isAnalyzing: boolean;
  error: string | null;
}