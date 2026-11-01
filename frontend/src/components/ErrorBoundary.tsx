import React from 'react';

interface Props {
  children: React.ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-black text-white p-8 font-mono border-4 border-red-500 m-4">
          <div className="bg-red-500 text-black px-4 py-2 font-black text-sm uppercase inline-block mb-4">
            RENDER ERROR CAUGHT BY SENTINEL ERROR BOUNDARY
          </div>
          <h2 className="text-xl font-bold text-red-400 mb-2">
            {this.state.error?.name}: {this.state.error?.message}
          </h2>
          <pre className="bg-zinc-900 p-4 border border-zinc-700 text-xs text-zinc-300 overflow-x-auto whitespace-pre-wrap">
            {this.state.error?.stack}
          </pre>
          <button
            onClick={() => window.location.reload()}
            className="mt-4 px-4 py-2 bg-lime-400 text-black font-bold uppercase border-2 border-black"
          >
            Reload Page
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
