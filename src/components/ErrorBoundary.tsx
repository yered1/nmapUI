import React from 'react';

interface ErrorBoundaryProps {
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('NmapUI Error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          height: '100vh',
          background: 'var(--bg-primary, #0a0e1a)',
          color: 'var(--text-primary, #e2e8f0)',
          padding: 40,
          textAlign: 'center',
        }}>
          <div style={{ fontSize: 48, marginBottom: 16, opacity: 0.4 }}>{'\u26A0'}</div>
          <h2 style={{ fontSize: 20, marginBottom: 8 }}>Something went wrong</h2>
          <p style={{ color: 'var(--text-muted, #64748b)', fontSize: 13, marginBottom: 16, maxWidth: 500 }}>
            An unexpected error occurred. You can try reloading the application.
          </p>
          {this.state.error && (
            <pre style={{
              background: 'var(--bg-tertiary, #1e293b)',
              padding: 12,
              borderRadius: 6,
              fontSize: 11,
              maxWidth: 600,
              overflow: 'auto',
              textAlign: 'left',
              marginBottom: 16,
              color: 'var(--red, #f87171)',
            }}>
              {this.state.error.message}
            </pre>
          )}
          <button
            onClick={() => {
              this.setState({ hasError: false, error: null });
              window.location.reload();
            }}
            style={{
              padding: '8px 20px',
              borderRadius: 6,
              border: 'none',
              background: 'var(--accent, #38bdf8)',
              color: '#0a0e1a',
              fontWeight: 600,
              cursor: 'pointer',
              fontSize: 13,
            }}
          >
            Reload Application
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
