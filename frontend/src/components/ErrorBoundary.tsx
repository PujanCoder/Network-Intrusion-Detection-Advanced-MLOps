import { Component } from "react";
import type { ErrorInfo, ReactNode } from "react";

interface State {
  error: Error | null;
}

/**
 * Last-resort guard: a render error must show a message, not a blank terminal.
 * The message stays generic so internal state is not leaked to the operator UI.
 */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("dashboard render error", error, info.componentStack);
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <div className="auth-screen">
          <div className="auth-card">
            <h1>The dashboard hit a rendering error</h1>
            <p className="small muted">
              Reload the page. If it keeps happening, check <span className="mono">/api/v1/system/status</span> for
              deployment state.
            </p>
            <button type="button" className="button primary block" onClick={() => window.location.reload()}>
              Reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
