import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import App from './App'

describe('App', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/samples')) {
        return Promise.resolve({ ok: true, json: async () => [] })
      }
      return Promise.resolve({
        ok: true,
        json: async () => ({ status: 'healthy', version: '1.0.0', service: 'phishguard-ai-backend' }),
      })
    }))
  })

  it('renders the header title', () => {
    render(<App />)
    expect(screen.getByText(/PhishGuard AI/i)).toBeInTheDocument()
  })
})
