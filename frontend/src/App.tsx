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
  Info,
  Sun,
  Moon,
  ExternalLink,
  Trash2,
  Lock,
  Globe,
  Sparkles
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
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    try {
      const saved = localStorage.getItem('phishguard-theme')
      if (saved === 'light' || saved === 'dark') return saved
    } catch (_) {}
    return 'dark'
  })

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

  // Sync theme with DOM
  useEffect(() => {
    const root = document.documentElement
    if (theme === 'dark') {
      root.classList.add('dark')
    } else {
      root.classList.remove('dark')
    }
    try {
      localStorage.setItem('phishguard-theme', theme)
    } catch (_) {}
  }, [theme])

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'))
  }

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

  const getScoreTheme = (score: number) => {
    if (score < 30) {
      return {
        cardBorder: 'border-emerald-500/40 dark:border-emerald-500/30',
        cardBg: 'bg-emerald-500/5 dark:bg-emerald-500/10',
        text: 'text-emerald-700 dark:text-emerald-400',
        bar: 'bg-emerald-500',
        badge: 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800',
        icon: <ShieldCheck className="w-8 h-8 text-emerald-600 dark:text-emerald-400" />,
      }
    }
    if (score < 60) {
      return {
        cardBorder: 'border-amber-500/40 dark:border-amber-500/30',
        cardBg: 'bg-amber-500/5 dark:bg-amber-500/10',
        text: 'text-amber-700 dark:text-amber-400',
        bar: 'bg-amber-500',
        badge: 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800',
        icon: <AlertTriangle className="w-8 h-8 text-amber-600 dark:text-amber-400" />,
      }
    }
    return {
      cardBorder: 'border-rose-500/40 dark:border-rose-500/30',
      cardBg: 'bg-rose-500/5 dark:bg-rose-500/10',
      text: 'text-rose-700 dark:text-rose-400',
      bar: 'bg-rose-500',
      badge: 'bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950 dark:text-rose-300 dark:border-rose-800',
      icon: <ShieldAlert className="w-8 h-8 text-rose-600 dark:text-rose-400" />,
    }
  }

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-rose-100 text-rose-800 border-rose-200 dark:bg-rose-950/80 dark:text-rose-300 dark:border-rose-800'
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-950/80 dark:text-orange-300 dark:border-orange-800'
      case 'medium':
        return 'bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-800'
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700'
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 antialiased selection:bg-indigo-500 selection:text-white transition-colors duration-200">
      {/* Subtle Background Glow */}
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(ellipse_80%_60%_at_50%_-20%,rgba(99,102,241,0.08),rgba(255,255,255,0))] dark:bg-[radial-gradient(ellipse_80%_60%_at_50%_-20%,rgba(99,102,241,0.15),rgba(15,23,42,0))] -z-10" />

      {/* Header */}
      <header className="border-b border-slate-200/80 dark:border-slate-800/80 bg-white/80 dark:bg-slate-900/80 backdrop-blur-md sticky top-0 z-30 transition-colors duration-200">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          {/* Logo & Title */}
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-gradient-to-tr from-indigo-600 to-violet-500 text-white rounded-xl shadow-md shadow-indigo-500/20">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-base sm:text-lg font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
                Phishguard
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-700 border border-indigo-200 dark:bg-indigo-500/20 dark:text-indigo-300 dark:border-indigo-500/30 font-semibold">
                  v1.0.0
                </span>
              </h1>
              <p className="text-[11px] sm:text-xs text-slate-500 dark:text-slate-400">
                Explainable Phishing Assessment & Risk Engine
              </p>
            </div>
          </div>

          {/* Right Controls: Backend Status, Theme Toggle, GitHub */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* Backend Status Indicator */}
            <span
              className={`text-xs px-2.5 py-1 rounded-full border flex items-center gap-1.5 transition ${
                backendStatus === 'connected'
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-300 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/30'
                  : backendStatus === 'checking'
                  ? 'bg-amber-50 text-amber-700 border-amber-300 dark:bg-amber-500/10 dark:text-amber-400 dark:border-amber-500/30'
                  : 'bg-rose-50 text-rose-700 border-rose-300 dark:bg-rose-500/10 dark:text-rose-400 dark:border-rose-500/30'
              }`}
            >
              <Activity className="w-3.5 h-3.5 animate-pulse" />
              <span className="hidden sm:inline">
                {backendStatus === 'connected'
                  ? 'Backend Online'
                  : backendStatus === 'checking'
                  ? 'Connecting...'
                  : 'Backend Offline'}
              </span>
            </span>

            {/* Light / Dark Mode Toggle */}
            <button
              type="button"
              onClick={toggleTheme}
              aria-label="Toggle light or dark theme"
              className="p-2 sm:px-3 sm:py-1.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-100/80 dark:bg-slate-800/80 text-slate-700 dark:text-slate-200 hover:text-indigo-600 dark:hover:text-indigo-400 hover:border-indigo-300 dark:hover:border-indigo-500/40 transition-all flex items-center gap-1.5 text-xs font-medium shadow-sm"
              title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            >
              {theme === 'dark' ? (
                <>
                  <Sun className="w-4 h-4 text-amber-400" />
                  <span className="hidden sm:inline">Light Mode</span>
                </>
              ) : (
                <>
                  <Moon className="w-4 h-4 text-indigo-600" />
                  <span className="hidden sm:inline">Dark Mode</span>
                </>
              )}
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 py-8 grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Form & Sample Picker */}
        <section className="lg:col-span-6 space-y-6">
          <div className="bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 sm:p-7 shadow-xl shadow-slate-200/40 dark:shadow-2xl transition-colors duration-200">
            {/* Header: Title & Sample Picker */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5">
              <h2 className="text-sm font-bold text-slate-800 dark:text-slate-100 uppercase tracking-wider flex items-center gap-2">
                <Mail className="w-4 h-4 text-indigo-500" />
                Analyze Email
              </h2>

              {samples.length > 0 && (
                <div className="flex items-center gap-2">
                  <select
                    className="w-full sm:w-auto bg-slate-50 dark:bg-slate-800 text-xs text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700 rounded-xl px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition"
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
              className={`mb-5 relative border-2 border-dashed rounded-2xl p-4 transition-all duration-200 text-center ${
                isDragging
                  ? 'border-indigo-500 bg-indigo-50/80 dark:bg-indigo-500/10 scale-[1.01]'
                  : uploadedFileName
                  ? 'border-emerald-500/40 bg-emerald-50/50 dark:bg-emerald-500/5'
                  : 'border-slate-200 dark:border-slate-700/80 hover:border-indigo-300 dark:hover:border-slate-600 bg-slate-50/50 dark:bg-slate-950/40'
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
                    <div className="p-2 bg-emerald-100 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/20 rounded-xl shrink-0">
                      <FileUp className="w-5 h-5" />
                    </div>
                    <div className="truncate">
                      <p className="text-xs font-semibold text-slate-800 dark:text-slate-200 truncate">
                        {uploadedFileName}
                      </p>
                      <p className="text-[11px] text-emerald-600 dark:text-emerald-400 flex items-center gap-1 font-medium">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Email parsed & loaded into form
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <label
                      htmlFor="email-file-input"
                      className="cursor-pointer text-xs font-semibold text-slate-700 dark:text-slate-300 hover:text-indigo-600 dark:hover:text-white px-3 py-1 bg-slate-200/70 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 rounded-lg transition"
                    >
                      Change
                    </label>
                    <button
                      type="button"
                      onClick={handleClearFile}
                      className="text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 p-1.5 rounded-lg hover:bg-rose-50 dark:hover:bg-rose-500/10 transition"
                      title="Clear file"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ) : (
                <label
                  htmlFor="email-file-input"
                  className="cursor-pointer flex flex-col items-center justify-center gap-2.5 py-3"
                >
                  <div
                    className={`p-3 rounded-2xl border transition shadow-sm ${
                      isDragging
                        ? 'bg-indigo-600 text-white border-indigo-400 scale-105'
                        : 'bg-indigo-50 text-indigo-600 border-indigo-200/80 dark:bg-indigo-500/10 dark:text-indigo-400 dark:border-indigo-500/20'
                    }`}
                  >
                    {uploadLoading ? (
                      <RefreshCw className="w-5 h-5 animate-spin" />
                    ) : (
                      <UploadCloud className="w-5 h-5" />
                    )}
                  </div>
                  <div>
                    <p className="text-xs font-bold text-slate-800 dark:text-slate-200">
                      {isDragging ? 'Drop your email file here' : 'Drop Gmail .eml or .txt here, or click to browse'}
                    </p>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                      Supports raw RFC-822 / .eml downloaded directly from Gmail
                    </p>
                  </div>
                </label>
              )}

              {/* Gmail Guide Collapsible Trigger */}
              <div className="mt-2.5 pt-2 border-t border-slate-200/70 dark:border-slate-800/80 flex items-center justify-center">
                <button
                  type="button"
                  onClick={() => setShowGmailHelp((prev) => !prev)}
                  className="text-[11px] text-indigo-600 dark:text-indigo-400 hover:underline flex items-center gap-1 font-medium transition"
                >
                  <HelpCircle className="w-3.5 h-3.5" />
                  {showGmailHelp ? 'Hide Gmail download instructions' : 'How to download email from Gmail?'}
                </button>
              </div>

              {showGmailHelp && (
                <div className="mt-2.5 p-3.5 rounded-xl bg-slate-100/70 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 text-left text-[11px] text-slate-600 dark:text-slate-300 space-y-1.5 transition">
                  <p className="font-semibold text-indigo-700 dark:text-indigo-300 flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5" />
                    Quick Steps in Gmail:
                  </p>
                  <ol className="list-decimal list-inside space-y-1 text-slate-600 dark:text-slate-400 pl-1">
                    <li>Open the target email in <strong className="text-slate-900 dark:text-slate-200">Gmail</strong>.</li>
                    <li>Click the <strong className="text-slate-900 dark:text-slate-200">More (⋮)</strong> menu near the top right of the message (next to Reply).</li>
                    <li>Select <strong className="text-slate-900 dark:text-slate-200">"Download message"</strong> — this saves the email as a <code className="text-indigo-700 dark:text-indigo-300 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 px-1 py-0.5 rounded font-mono">.eml</code> file.</li>
                    <li>Drag and drop that downloaded <code className="text-indigo-700 dark:text-indigo-300 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 px-1 py-0.5 rounded font-mono">.eml</code> file right here!</li>
                  </ol>
                </div>
              )}
            </div>

            {/* Email Form */}
            <form onSubmit={handleAnalyze} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                  Sender (Header or Address)
                </label>
                <input
                  type="text"
                  placeholder='e.g., "IT Support" <support@secure-update-notice.com>'
                  className="w-full bg-slate-50/80 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-700/80 rounded-xl px-3.5 py-2 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition"
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                  Subject Line
                </label>
                <input
                  type="text"
                  placeholder="e.g., URGENT: Password expired - verify your account within 24 hours"
                  className="w-full bg-slate-50/80 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-700/80 rounded-xl px-3.5 py-2 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                  Email Content / Body
                </label>
                <textarea
                  rows={8}
                  placeholder="Paste raw email text, headers, and hyperlinks here..."
                  className="w-full bg-slate-50/80 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-700/80 rounded-xl px-3.5 py-2 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 font-mono text-xs leading-relaxed transition"
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                />
              </div>

              {error && (
                <div className="p-3.5 rounded-xl bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-500/10 dark:border-rose-500/30 dark:text-rose-300 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  {error}
                </div>
              )}

              <div className="flex items-center gap-3 pt-2">
                <button
                  type="submit"
                  disabled={analyzing}
                  className="flex-1 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 disabled:opacity-50 text-white font-semibold text-sm py-2.5 px-4 rounded-xl transition-all shadow-md shadow-indigo-500/25 flex items-center justify-center gap-2 active:scale-[0.99]"
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
                    setUploadedFileName(null)
                  }}
                  className="px-4 py-2.5 border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 rounded-xl text-sm font-medium transition flex items-center gap-1.5"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Clear
                </button>
              </div>
            </form>
          </div>
        </section>

        {/* Right Column: Analysis Results */}
        <section className="lg:col-span-6 space-y-6">
          {!result && !analyzing && (
            <div className="bg-white/60 dark:bg-slate-900/50 border border-dashed border-slate-300 dark:border-slate-800 rounded-3xl p-10 text-center text-slate-500 flex flex-col items-center justify-center h-full min-h-[380px] shadow-sm">
              <div className="p-4 bg-indigo-50 dark:bg-slate-800/80 text-indigo-600 dark:text-indigo-400 rounded-2xl mb-4 border border-indigo-100 dark:border-slate-700">
                <FileText className="w-10 h-10" />
              </div>
              <h3 className="text-sm font-bold text-slate-800 dark:text-slate-200">
                No Email Analyzed Yet
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-sm leading-relaxed">
                Upload a Gmail <code className="text-indigo-600 dark:text-indigo-300 bg-slate-100 dark:bg-slate-800 px-1 py-0.5 rounded font-mono">.eml</code> file, pick a sample, or paste an email to inspect phishing signatures.
              </p>

              {/* Security Inspection Checklist */}
              <div className="mt-6 grid grid-cols-2 gap-2.5 w-full max-w-sm text-left">
                <div className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200/80 dark:border-slate-800 text-[11px] flex items-center gap-2">
                  <Globe className="w-3.5 h-3.5 text-indigo-500" />
                  <span>URL Inspection</span>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200/80 dark:border-slate-800 text-[11px] flex items-center gap-2">
                  <Lock className="w-3.5 h-3.5 text-indigo-500" />
                  <span>Credential Traps</span>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200/80 dark:border-slate-800 text-[11px] flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-indigo-500" />
                  <span>Urgency Detection</span>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200/80 dark:border-slate-800 text-[11px] flex items-center gap-2">
                  <Sparkles className="w-3.5 h-3.5 text-indigo-500" />
                  <span>BEC / Scam Cues</span>
                </div>
              </div>
            </div>
          )}

          {analyzing && (
            <div className="bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-3xl p-12 text-center text-slate-400 flex flex-col items-center justify-center h-full min-h-[380px] shadow-xl">
              <RefreshCw className="w-12 h-12 text-indigo-600 dark:text-indigo-400 animate-spin mb-4" />
              <p className="text-sm font-bold text-slate-800 dark:text-slate-100">
                Evaluating Phishing Signatures
              </p>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-sm">
                Running static heuristic checks, domain reputation inspection, credential harvesting cues, and urgency analysis...
              </p>
            </div>
          )}

          {result && !analyzing && (
            <div className="space-y-6">
              {/* Score Hero Card */}
              {(() => {
                const themeConf = getScoreTheme(result.score)
                return (
                  <div
                    className={`border rounded-3xl p-6 sm:p-7 ${themeConf.cardBorder} ${themeConf.cardBg} transition-all shadow-lg`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="text-[11px] font-bold uppercase tracking-wider opacity-75">
                          Overall Risk Assessment
                        </span>
                        <h3 className="text-2xl sm:text-3xl font-black mt-1 flex items-center gap-2 text-slate-900 dark:text-white">
                          {themeConf.icon}
                          {result.risk_category}
                        </h3>
                      </div>

                      <div className="text-right">
                        <span className="text-xs opacity-75 font-semibold">Risk Score</span>
                        <div className={`text-4xl sm:text-5xl font-black tracking-tight ${themeConf.text}`}>
                          {result.score}
                          <span className="text-lg opacity-60 font-semibold">/100</span>
                        </div>
                      </div>
                    </div>

                    {/* Progress Bar */}
                    <div className="w-full bg-slate-200 dark:bg-slate-800 h-2.5 rounded-full overflow-hidden mt-5">
                      <div
                        className={`h-full ${themeConf.bar} transition-all duration-500 rounded-full`}
                        style={{ width: `${Math.max(result.score, 4)}%` }}
                      />
                    </div>

                    <p className="mt-4 text-xs leading-relaxed text-slate-700 dark:text-slate-300 border-t border-slate-200 dark:border-slate-700/60 pt-3">
                      {result.summary}
                    </p>

                    {/* Stats Metric Pills */}
                    <div className="grid grid-cols-4 gap-2 mt-4 pt-3 border-t border-slate-200 dark:border-slate-700/60 text-center">
                      <div className="p-2 rounded-xl bg-white/60 dark:bg-slate-950/40 border border-slate-200/60 dark:border-slate-800">
                        <div className="text-[10px] text-slate-500 uppercase font-semibold">Words</div>
                        <div className="text-sm font-bold text-slate-900 dark:text-white mt-0.5">
                          {result.stats.word_count}
                        </div>
                      </div>
                      <div className="p-2 rounded-xl bg-white/60 dark:bg-slate-950/40 border border-slate-200/60 dark:border-slate-800">
                        <div className="text-[10px] text-slate-500 uppercase font-semibold">Chars</div>
                        <div className="text-sm font-bold text-slate-900 dark:text-white mt-0.5">
                          {result.stats.char_count}
                        </div>
                      </div>
                      <div className="p-2 rounded-xl bg-white/60 dark:bg-slate-950/40 border border-slate-200/60 dark:border-slate-800">
                        <div className="text-[10px] text-slate-500 uppercase font-semibold">URLs</div>
                        <div className="text-sm font-bold text-slate-900 dark:text-white mt-0.5">
                          {result.stats.url_count}
                        </div>
                      </div>
                      <div className="p-2 rounded-xl bg-white/60 dark:bg-slate-950/40 border border-slate-200/60 dark:border-slate-800">
                        <div className="text-[10px] text-slate-500 uppercase font-semibold">Suspicious</div>
                        <div
                          className={`text-sm font-bold mt-0.5 ${
                            result.stats.suspicious_url_count > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'
                          }`}
                        >
                          {result.stats.suspicious_url_count}
                        </div>
                      </div>
                    </div>
                  </div>
                )
              })()}

              {/* Indicators */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-5 sm:p-6 space-y-3.5 shadow-md">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 flex items-center justify-between">
                  <span>Detected Indicators ({result.indicators.length})</span>
                </h4>

                {result.indicators.length === 0 ? (
                  <div className="p-4 rounded-2xl bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-800/50 text-xs text-emerald-800 dark:text-emerald-300 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                    <span>No malicious patterns or phishing markers were detected in this email.</span>
                  </div>
                ) : (
                  <div className="space-y-2.5">
                    {result.indicators.map((ind) => (
                      <div
                        key={ind.id}
                        className="bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-2xl p-3.5 space-y-1.5"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-bold text-slate-900 dark:text-slate-200">
                            {ind.title}
                          </span>
                          <span
                            className={`text-[10px] px-2.5 py-0.5 rounded-full font-bold border uppercase shrink-0 ${getSeverityBadge(
                              ind.severity
                            )}`}
                          >
                            {ind.severity} (+{ind.score_delta})
                          </span>
                        </div>
                        <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                          {ind.explanation}
                        </p>
                        {ind.matched_terms.length > 0 && (
                          <div className="flex flex-wrap gap-1.5 pt-1">
                            {ind.matched_terms.map((term, i) => (
                              <span
                                key={i}
                                className="text-[10px] px-2 py-0.5 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
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
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-5 sm:p-6 space-y-3.5 shadow-md">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                    Extracted Hyperlinks ({result.extracted_urls.length})
                  </h4>
                  <div className="space-y-2.5">
                    {result.extracted_urls.map((u, i) => (
                      <div
                        key={i}
                        className={`text-xs p-3.5 rounded-2xl border transition ${
                          u.is_suspicious
                            ? 'bg-rose-50/70 dark:bg-rose-950/30 border-rose-200 dark:border-rose-800/60 text-rose-900 dark:text-rose-200'
                            : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-300'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-3">
                          <span className="font-mono break-all font-medium text-[11px] sm:text-xs flex items-center gap-1.5">
                            <ExternalLink className="w-3.5 h-3.5 shrink-0 opacity-60" />
                            {u.url}
                          </span>
                          <span
                            className={`text-[10px] px-2.5 py-0.5 rounded-full uppercase font-bold shrink-0 border ${
                              u.is_suspicious
                                ? 'bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-900 dark:text-rose-200 dark:border-rose-800'
                                : 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800'
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
                                className="text-[10px] bg-rose-100 dark:bg-rose-900/40 text-rose-800 dark:text-rose-300 px-2 py-0.5 rounded-md font-semibold"
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
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-5 sm:p-6 space-y-3.5 shadow-md">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                    Actionable Guidance & Next Steps
                  </h4>
                  <ul className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
                    {result.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2.5">
                        <CheckCircle2 className="w-4 h-4 text-indigo-500 mt-0.5 flex-shrink-0" />
                        <span className="leading-relaxed">{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <p className="text-[11px] text-slate-400 dark:text-slate-500 italic text-center px-4 leading-relaxed">
                {result.disclaimer}
              </p>
            </div>
          )}
        </section>
      </main>
    </div>
  )
}
