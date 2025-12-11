import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';
import { Link } from 'react-router-dom';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    // Update state so the next render will show the fallback UI
    return {
      hasError: true,
      error,
      errorInfo: null,
    };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log error details
    console.error('ErrorBoundary caught an error:', error, errorInfo);

    this.setState({
      error,
      errorInfo,
    });
  }

  private handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center p-4">
          <div className="max-w-2xl w-full bg-slate-800/50 backdrop-blur-sm rounded-2xl border border-red-500/20 p-8">
            <div className="flex items-center gap-4 mb-6">
              <div className="p-3 bg-red-500/10 rounded-full">
                <AlertTriangle className="w-8 h-8 text-red-500" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">Something went wrong</h1>
                <p className="text-slate-400 mt-1">
                  An unexpected error occurred in the application
                </p>
              </div>
            </div>

            {this.state.error && (
              <div className="mb-6 p-4 bg-slate-900/50 rounded-lg border border-slate-700">
                <h2 className="text-sm font-semibold text-red-400 mb-2">Error Details</h2>
                <p className="text-sm text-slate-300 font-mono break-all">
                  {this.state.error.toString()}
                </p>

                {import.meta.env.MODE === 'development' && this.state.errorInfo && (
                  <details className="mt-4">
                    <summary className="text-sm text-slate-400 cursor-pointer hover:text-white">
                      Stack Trace (Development Only)
                    </summary>
                    <pre className="mt-2 text-xs text-slate-400 overflow-x-auto p-2 bg-slate-950 rounded">
                      {this.state.errorInfo.componentStack}
                    </pre>
                  </details>
                )}
              </div>
            )}

            <div className="flex flex-col sm:flex-row gap-3">
              <button
                onClick={this.handleReset}
                className="flex-1 flex items-center justify-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
              >
                <RefreshCw className="w-5 h-5" />
                Try Again
              </button>

              <Link
                to="/"
                className="flex-1 flex items-center justify-center gap-2 px-6 py-3 bg-slate-700 hover:bg-slate-600 text-white rounded-lg font-medium transition-colors"
                onClick={this.handleReset}
              >
                <Home className="w-5 h-5" />
                Go Home
              </Link>
            </div>

            <div className="mt-6 p-4 bg-slate-900/30 rounded-lg border border-slate-700">
              <h3 className="text-sm font-semibold text-slate-300 mb-2">What you can do:</h3>
              <ul className="text-sm text-slate-400 space-y-1">
                <li>• Click "Try Again" to attempt to recover</li>
                <li>• Go back to the homepage and start over</li>
                <li>• Refresh the page (Ctrl/Cmd + R)</li>
                <li>• Clear your browser cache if the issue persists</li>
              </ul>
            </div>

            {import.meta.env.MODE === 'production' && (
              <p className="mt-6 text-center text-sm text-slate-500">
                If this error persists, please report it via GitHub issues
              </p>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
