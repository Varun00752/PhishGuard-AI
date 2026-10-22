import React, { useState, useEffect } from 'react'
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Mail,
  Send,
  RefreshCw,
  FileText,
  Activity,
  CheckCircle2,
  UploadCloud,
  FileUp,
  X,
  HelpCircle,
  Info
} from 'lucide-react'

interface Indicator {
  id: string
  title: string
  category: string
  severity: string
  score_delta: number
  matched_terms: string[]
  explanation: string
}

interface ExtractedURL {
  url: string
  domain: string
  is_suspicious: boolean
  flags: string[]
  risk_level: string
}

interface AnalysisResult {
  score: number
  risk_category: string
  summary: string
  indicators: Indicator[]
  extracted_urls: ExtractedURL[]
  recommendations: string[]
  stats: {
    char_count: number
    word_count: number
    url_count: number
    suspicious_url_count: number
  }
  disclaimer: string
  analyzed_at: string
}

interface SampleEmail {
  id: string
  label?: string
  name?: string
  type?: string
  description?: string
  sender: string
  subject: string
  body: string
}

export default function App() {
  const [sender, setSender] = useState('')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')
  const [samples, setSamples] = useState<SampleEmail[]>([])
  const [selectedSample, setSelectedSample] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [backendStatus, setBackendStatus] = useState<'checking' | 'connected' | 'disconnected'>('checking')
  const [isDragging, setIsDragging] = useState(false)
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null)
  const [uploadLoading, setUploadLoading] = useState(false)
  const [showGmailHelp, setShowGmailHelp] = useState(false)

  useEffect(() => {
    // Check backend health
    fetch('/api/health')
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then(() => setBackendStatus('connected'))
      .catch(() => setBackendStatus('disconnected'))

    // Load sample emails
    fetch('/api/samples')
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => setSamples(data))
      .catch(() => setSamples([]))
  }, [])

  const handleSampleChange = (sampleId: string) => {
    setSelectedSample(sampleId)
    setUploadedFileName(null)
    const found = samples.find((s) => s.id === sampleId)
    if (found) {
      setSender(found.sender)
      setSubject(found.subject)
      setBody(found.body)
      setResult(null)
      setError(null)
    }
  }

  const handleFileUpload = async (file: File) => {
    if (!file) return
    setUploadLoading(true)
    setError(null)
    setUploadedFileName(file.name)
    setSelectedSample('')

    try {
      const formData = new FormData()
      formData.append('file', file)

      const response = await fetch('/api/upload-email', {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.detail || 'Failed to parse uploaded email file.')
      }

      const data = await response.json()
      setSender(data.sender || '')
      setSubject(data.subject || '')
      setBody(data.body || '')
      setResult(null)
    } catch (err: any) {
      // Client-side fallback: read as text if server upload fails
      const reader = new FileReader()
      reader.onload = (e) => {
        const text = (e.target?.result as string) || ''
        const fromMatch = text.match(/^From:\s*(.+)$/im)
        const subjectMatch = text.match(/^Subject:\s*(.+)$/im)
        if (fromMatch) setSender(fromMatch[1].trim())
        if (subjectMatch) setSubject(subjectMatch[1].trim())
        const parts = text.split(/\r?\n\r?\n/)
        if (parts.length > 1) {
          setBody(parts.slice(1).join('\n\n').trim())
        } else {
          setBody(text)
        }
        setResult(null)
      }
      reader.onerror = () => {
        setError(err.message || 'Error processing email file.')
      }
      reader.readAsText(file)
    } finally {
      setUploadLoading(false)
    }
  }

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0])
    }
  }

  const handleClearFile = () => {
    setUploadedFileName(null)
    setSender('')
    setSubject('')
    setBody('')
    setResult(null)
  }

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!sender.trim() && !subject.trim() && !body.trim()) {
      setError('Please provide at least a sender, subject, or email body.')
      return
    }

    setAnalyzing(true)
    setError(null)

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender, subject, body }),
      })

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.detail || 'Failed to analyze email.')
      }

      const data: AnalysisResult = await response.json()
      setResult(data)
    } catch (err: any) {
      setError(err.message || 'Error communicating with backend service.')
    } finally {
      setAnalyzing(false)
    }
  }

  const getScoreColor = (score: number) => {
    if (score < 30) return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10'
    if (score < 60) return 'text-amber-400 border-amber-500/30 bg-amber-500/10'
    return 'text-rose-400 border-rose-500/30 bg-rose-500/10'
  }

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-rose-950 text-rose-300 border border-rose-800'
      case 'high':
        return 'bg-orange-950 text-orange-300 border border-orange-800'
      case 'medium':
        return 'bg-amber-950 text-amber-300 border border-amber-800'
      default:
        return 'bg-slate-800 text-slate-300 border border-slate-700'
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 antialiased selection:bg-indigo-500 selection:text-white">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 rounded-xl">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                PhishGuard AI
                <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-medium">
                  v1.0.0
                </span>
              </h1>
              <p className="text-xs text-slate-400">Explainable Phishing Assessment & Risk Engine</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <span
              className={`text-xs px-2.5 py-1 rounded-full border flex items-center gap-1.5 ${
                backendStatus === 'connected'
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : backendStatus === 'checking'
                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                  : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
              }`}
            >
              <Activity className="w-3.5 h-3.5 animate-pulse" />
              {backendStatus === 'connected'
                ? 'Backend Online'
                : backendStatus === 'checking'
                ? 'Connecting...'
                : 'Backend Offline (:8000)'}
            </span>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 py-8 grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Form & Sample Picker */}
        <section className="lg:col-span-6 space-y-6">
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <Mail className="w-4 h-4 text-indigo-400" />
                Analyze Email
              </h2>

              {samples.length > 0 && (
                <div className="flex items-center gap-2">
                  <select
                    className="bg-slate-800 text-xs text-slate-300 border border-slate-700 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                    value={selectedSample}
                    onChange={(e) => handleSampleChange(e.target.value)}
                  >
                    <option value="">Load Sample Email...</option>
                    {samples.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.label || s.name || s.id}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            {/* Drag & Drop Upload Zone */}
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={`mb-5 relative border-2 border-dashed rounded-xl p-4 transition-all duration-200 text-center ${
                isDragging
                  ? 'border-indigo-500 bg-indigo-500/10 scale-[1.01]'
                  : uploadedFileName
                  ? 'border-emerald-500/40 bg-emerald-500/5'
                  : 'border-slate-700/80 hover:border-slate-600 bg-slate-950/40'
              }`}
            >
              <input
                type="file"
                id="email-file-input"
                accept=".eml,.txt"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files.length > 0) {
                    handleFileUpload(e.target.files[0])
                  }
                }}
              />

              {uploadedFileName ? (
                <div className="flex items-center justify-between gap-3 text-left">
                  <div className="flex items-center gap-3 overflow-hidden">
                    <div className="p-2 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-lg shrink-0">
                      <FileUp className="w-5 h-5" />
                    </div>
                    <div className="truncate">
                      <p className="text-xs font-semibold text-slate-200 truncate">
                        {uploadedFileName}
                      </p>
                      <p className="text-[11px] text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" />
                        Email parsed & loaded into form
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <label
                      htmlFor="email-file-input"
                      className="cursor-pointer text-xs font-medium text-slate-400 hover:text-white px-2.5 py-1 bg-slate-800 hover:bg-slate-700 rounded-md transition"
                    >
                      Change
                    </label>
                    <button
                      type="button"
                      onClick={handleClearFile}
                      className="text-slate-400 hover:text-rose-400 p-1 rounded-md hover:bg-rose-500/10 transition"
                      title="Clear file"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ) : (
                <label
                  htmlFor="email-file-input"
                  className="cursor-pointer flex flex-col items-center justify-center gap-2 py-2"
                >
                  <div className={`p-2.5 rounded-xl border transition ${
                    isDragging
                      ? 'bg-indigo-600 text-white border-indigo-400'
                      : 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20'
                  }`}>
                    {uploadLoading ? (
                      <RefreshCw className="w-5 h-5 animate-spin" />
                    ) : (
                      <UploadCloud className="w-5 h-5" />
                    )}
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-slate-200">
                      {isDragging ? 'Drop your email file here' : 'Drop Gmail .eml or .txt here, or click to browse'}
                    </p>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Supports raw RFC-822 / .eml downloaded directly from Gmail
                    </p>
                  </div>
                </label>
              )}

              {/* Gmail Guide Collapsible Trigger */}
              <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-center">
                <button
                  type="button"
                  onClick={() => setShowGmailHelp((prev) => !prev)}
                  className="text-[11px] text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition"
                >
                  <HelpCircle className="w-3 h-3" />
                  {showGmailHelp ? 'Hide Gmail download instructions' : 'How to download email from Gmail?'}
                </button>
              </div>

              {showGmailHelp && (
                <div className="mt-2.5 p-3 rounded-lg bg-slate-950/70 border border-slate-800 text-left text-[11px] text-slate-300 space-y-1.5">
                  <p className="font-semibold text-indigo-300 flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5" />
                    Quick Steps in Gmail:
                  </p>
                  <ol className="list-decimal list-inside space-y-1 text-slate-400 pl-1">
                    <li>Open the target email in <strong className="text-slate-200">Gmail</strong>.</li>
                    <li>Click the <strong className="text-slate-200">More (⋮)</strong> menu near the top right of the message (next to the reply icon).</li>
                    <li>Select <strong className="text-slate-200">"Download message"</strong> — this saves the email as a <code className="text-indigo-300 bg-slate-900 px-1 py-0.5 rounded">.eml</code> file.</li>
                    <li>Drag and drop that downloaded <code className="text-indigo-300 bg-slate-900 px-1 py-0.5 rounded">.eml</code> file right here!</li>
                  </ol>
                </div>
              )}
            </div>

            <form onSubmit={handleAnalyze} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Sender (Header or Address)
                </label>
                <input
                  type="text"
                  placeholder='e.g., "IT Support" <support@secure-update-notice.com>'
                  className="w-full bg-slate-950/80 border border-slate-700/80 rounded-xl px-3.5 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Subject Line</label>
                <input
                  type="text"
                  placeholder="e.g., URGENT: Password expired - verify your account within 24 hours"
                  className="w-full bg-slate-950/80 border border-slate-700/80 rounded-xl px-3.5 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Email Content / Body
                </label>
                <textarea
                  rows={8}
                  placeholder="Paste raw email text, headers, and hyperlinks here..."
                  className="w-full bg-slate-950/80 border border-slate-700/80 rounded-xl px-3.5 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 font-mono text-xs leading-relaxed"
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                />
              </div>

              {error && (
                <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  {error}
                </div>
              )}

              <div className="flex items-center gap-3 pt-2">
                <button
                  type="submit"
                  disabled={analyzing}
                  className="flex-1 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium text-sm py-2.5 px-4 rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/20"
                >
                  {analyzing ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Analyzing Risk...
                    </>
                  ) : (
                    <>
                      <Send className="w-4 h-4" />
                      Run PhishGuard Analysis
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setSender('')
                    setSubject('')
                    setBody('')
                    setResult(null)
                    setError(null)
                    setSelectedSample('')
                  }}
                  className="px-3.5 py-2.5 border border-slate-700 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded-xl text-sm transition"
                >
                  Clear
                </button>
              </div>
            </form>
          </div>
        </section>

        {/* Right Column: Analysis Results */}
        <section className="lg:col-span-6 space-y-6">
          {!result && !analyzing && (
            <div className="bg-slate-900/50 border border-dashed border-slate-800 rounded-2xl p-12 text-center text-slate-500 flex flex-col items-center justify-center h-full min-h-[350px]">
              <FileText className="w-12 h-12 text-slate-700 mb-3" />
              <p className="text-sm font-medium text-slate-400">No email analyzed yet</p>
              <p className="text-xs text-slate-600 mt-1 max-w-sm">
                Paste an email or select a sample from the dropdown to review risk indicators, suspicious URLs, and remediation guidance.
              </p>
            </div>
          )}

          {analyzing && (
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-12 text-center text-slate-400 flex flex-col items-center justify-center h-full min-h-[350px]">
              <RefreshCw className="w-10 h-10 text-indigo-400 animate-spin mb-4" />
              <p className="text-sm font-semibold text-slate-200">Evaluating Phishing Signatures</p>
              <p className="text-xs text-slate-500 mt-1">
                Checking heuristic indicators, lookalike domains, credential harvesting cues, and urgency...
              </p>
            </div>
          )}

          {result && !analyzing && (
            <div className="space-y-6">
              {/* Score Card */}
              <div
                className={`border rounded-2xl p-6 ${getScoreColor(result.score)} transition-all`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-xs font-semibold uppercase tracking-wider opacity-80">
                      Overall Risk Assessment
                    </span>
                    <h3 className="text-2xl font-black mt-1 flex items-center gap-2 text-white">
                      {result.score >= 60 ? (
                        <ShieldAlert className="w-7 h-7 text-rose-400" />
                      ) : result.score >= 30 ? (
                        <AlertTriangle className="w-7 h-7 text-amber-400" />
                      ) : (
                        <ShieldCheck className="w-7 h-7 text-emerald-400" />
                      )}
                      {result.risk_category}
                    </h3>
                  </div>

                  <div className="text-right">
                    <span className="text-xs opacity-75">Risk Score</span>
                    <div className="text-4xl font-extrabold tracking-tight">{result.score}/100</div>
                  </div>
                </div>

                <p className="mt-4 text-xs leading-relaxed text-slate-200 border-t border-slate-700/50 pt-3">
                  {result.summary}
                </p>

                {/* Stats Bar */}
                <div className="grid grid-cols-4 gap-2 mt-4 pt-3 border-t border-slate-700/50 text-center">
                  <div>
                    <div className="text-[10px] text-slate-400 uppercase">Words</div>
                    <div className="text-xs font-semibold text-white">{result.stats.word_count}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-400 uppercase">Chars</div>
                    <div className="text-xs font-semibold text-white">{result.stats.char_count}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-400 uppercase">URLs</div>
                    <div className="text-xs font-semibold text-white">{result.stats.url_count}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-400 uppercase">Suspicious</div>
                    <div
                      className={`text-xs font-semibold ${
                        result.stats.suspicious_url_count > 0 ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {result.stats.suspicious_url_count}
                    </div>
                  </div>
                </div>
              </div>

              {/* Indicators */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center justify-between">
                  <span>Detected Indicators ({result.indicators.length})</span>
                </h4>

                {result.indicators.length === 0 ? (
                  <p className="text-xs text-slate-500 italic py-2">
                    No malicious patterns or phishing markers were detected.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {result.indicators.map((ind) => (
                      <div
                        key={ind.id}
                        className="bg-slate-950/70 border border-slate-800 rounded-xl p-3 space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium text-slate-200">{ind.title}</span>
                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${getSeverityBadge(
                                ind.severity
                              )}`}
                            >
                              {ind.severity} (+{ind.score_delta})
                            </span>
                          </div>
                        </div>
                        <p className="text-xs text-slate-400">{ind.explanation}</p>
                        {ind.matched_terms.length > 0 && (
                          <div className="flex flex-wrap gap-1 pt-1">
                            {ind.matched_terms.map((term, i) => (
                              <span
                                key={i}
                                className="text-[10px] px-1.5 py-0.5 bg-slate-800 text-slate-300 rounded font-mono"
                              >
                                {term}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Extracted URLs */}
              {result.extracted_urls.length > 0 && (
                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Extracted Hyperlinks ({result.extracted_urls.length})
                  </h4>
                  <div className="space-y-2">
                    {result.extracted_urls.map((u, i) => (
                      <div
                        key={i}
                        className={`text-xs p-3 rounded-xl border ${
                          u.is_suspicious
                            ? 'bg-rose-950/30 border-rose-800/60 text-rose-200'
                            : 'bg-slate-950 border-slate-800 text-slate-300'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono break-all font-medium">{u.url}</span>
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded-full uppercase font-bold ml-2 ${
                              u.is_suspicious
                                ? 'bg-rose-900 text-rose-200'
                                : 'bg-emerald-950 text-emerald-300'
                            }`}
                          >
                            {u.risk_level}
                          </span>
                        </div>
                        {u.flags.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1">
                            {u.flags.map((f, fi) => (
                              <span
                                key={fi}
                                className="text-[10px] bg-rose-900/40 text-rose-300 px-2 py-0.5 rounded"
                              >
                                {f}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendations */}
              {result.recommendations.length > 0 && (
                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Actionable Guidance
                  </h4>
                  <ul className="space-y-2 text-xs text-slate-300">
                    {result.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <CheckCircle2 className="w-4 h-4 text-indigo-400 mt-0.5 flex-shrink-0" />
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <p className="text-[11px] text-slate-500 italic text-center px-4">
                {result.disclaimer}
              </p>
            </div>
          )}
        </section>
      </main>
    </div>
  )
}
