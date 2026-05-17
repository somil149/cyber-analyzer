'use client'

import { useState } from 'react';
import { AnalysisResponse } from '@/types/security';
import CodeInput from '@/components/CodeInput';
import AnalysisResults from '@/components/AnalysisResults';

// Force relative URLs in production builds
// Only use localhost when explicitly running in development mode
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 
  (process.env.NODE_ENV === 'development' && typeof window !== 'undefined' && window.location?.hostname === 'localhost' 
    ? 'http://localhost:8000' 
    : 'https://cyber-analyzer-api-gateway.goyal-somil2011.workers.dev'); // Cloudflare Worker API Gateway


/**
 * Main application page for cybersecurity code analysis
 */
export default function Home() {
  const [codeContent, setCodeContent] = useState('');
  const [fileName, setFileName] = useState('');
  const [analysisResults, setAnalysisResults] = useState<AnalysisResponse | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [urlInput, setUrlInput] = useState('');
  const [websiteInput, setWebsiteInput] = useState('');
  const [inputMode, setInputMode] = useState<'file' | 'url' | 'website'>('file');

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file && file.name.endsWith('.py')) {
      setFileName(file.name);
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setCodeContent(content);
        setAnalysisResults(null);
        setError(null);
      };
      reader.readAsText(file);
    } else {
      alert('Please select a Python (.py) file');
    }
  };

  const handleFetchUrl = async () => {
    if (!urlInput) {
      alert('Please enter a URL first');
      return;
    }

    setIsAnalyzing(true);
    setError(null);

    try {
      // First, fetch the code from the URL using our backend
      const response = await fetch(`${API_BASE_URL}/api/fetch-url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: urlInput }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      setCodeContent(data.code);
      setFileName(data.filename || 'fetched_code.py');
      setAnalysisResults(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred while fetching the URL');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAnalyzeCode = async () => {
    if (inputMode === 'website') {
      await handleWebsiteScan();
      return;
    }

    if (!codeContent) {
      alert('Please upload a Python file or fetch from URL first');
      return;
    }

    setIsAnalyzing(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE_URL}/api/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code: codeContent }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const results: AnalysisResponse = await response.json();
      setAnalysisResults(results);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during analysis');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleWebsiteScan = async () => {
    if (!websiteInput) {
      alert('Please enter a website URL first');
      return;
    }

    setIsAnalyzing(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE_URL}/api/scan-website`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: websiteInput }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const results: AnalysisResponse = await response.json();
      setAnalysisResults(results);
      setFileName(websiteInput);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during website scan');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleToggleInputMode = (mode: 'file' | 'url' | 'website') => {
    setInputMode(mode);
    setCodeContent('');
    setFileName('');
    setAnalysisResults(null);
    setError(null);
    setUrlInput('');
    setWebsiteInput('');
  };

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-7xl mx-auto">
        <header className="mb-8">
          <h1 className="text-3xl font-bold text-foreground">Cybersecurity Analyst</h1>
          <p className="text-accent mt-2">Python code analysis tool for security assessment</p>
        </header>

        <div className="grid grid-rows-2 gap-6 h-[calc(100vh-200px)]">
          <CodeInput
            codeContent={codeContent}
            fileName={fileName}
            onFileUpload={handleFileUpload}
            onAnalyzeCode={handleAnalyzeCode}
            isAnalyzing={isAnalyzing}
            urlInput={urlInput}
            onUrlInputChange={setUrlInput}
            onFetchUrl={handleFetchUrl}
            websiteInput={websiteInput}
            onWebsiteInputChange={setWebsiteInput}
            inputMode={inputMode}
            onToggleInputMode={handleToggleInputMode}
          />

          <AnalysisResults
            analysisResults={analysisResults}
            isAnalyzing={isAnalyzing}
            error={error}
          />
        </div>
      </div>
    </div>
  );
}