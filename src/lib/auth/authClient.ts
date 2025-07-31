// File: lib/auth/authClient.ts
// Updated version using token-based authentication instead of cookies

export interface AuthUser {
  id: string;
  role: string;
  email: string | null;
  name: string | null;
  provider?: string | null;
  providerId?: string | null;
  image?: string | null;
}

export interface AuthResponse {
  authenticated: boolean;
  user?: AuthUser;
  sessionId?: string;
  token?: string;
  message?: string;
  requiresRedirect?: boolean;
  loginUrl?: string;
}

class AuthClient {
  private authServiceUrl: string;
  private user: AuthUser | null = null;
  private checkInterval: NodeJS.Timeout | null = null;
  private token: string | null = null;

  constructor(authServiceUrl: string) {
    this.authServiceUrl = authServiceUrl;
    // Load token from localStorage on initialization
    if (typeof window !== 'undefined') {
      this.token = localStorage.getItem('auth_token');
    }
  }

  /**
   * Set authentication token (call this after successful login)
   */
  setToken(token: string): void {
    this.token = token;
    if (typeof window !== 'undefined') {
      localStorage.setItem('auth_token', token);
    }
  }

  /**
   * Get stored token
   */
  getToken(): string | null {
    return this.token;
  }

  /**
   * Clear authentication token
   */
  clearToken(): void {
    this.token = null;
    if (typeof window !== 'undefined') {
      localStorage.removeItem('auth_token');
    }
  }

  /**
   * Check if user is authenticated by calling the auth service
   */
  async checkAuthentication(): Promise<AuthResponse> {
    try {
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };

      // Include token in Authorization header if available
      if (this.token) {
        headers['Authorization'] = `Bearer ${this.token}`;
      }

      const response = await fetch(`${this.authServiceUrl}/api/auth/verify-session`, {
        method: 'GET',
        credentials: 'include', // Still include for fallback
        headers,
      });

      const data: AuthResponse = await response.json();

      if (response.ok && data.authenticated && data.user) {
        this.user = data.user;
        
        // Store token if provided
        if (data.token) {
          this.setToken(data.token);
        }

        return {
          authenticated: true,
          user: data.user,
          sessionId: data.sessionId,
          token: data.token
        };
      }

      // Handle cross-domain authentication requirement
      if (response.status === 401 && data.requiresRedirect) {
        // This is a cross-domain request that needs authentication
        this.user = null;
        this.clearToken();
        
        return {
          authenticated: false,
          message: data.message || 'Authentication required',
          requiresRedirect: true,
          loginUrl: data.loginUrl
        };
      }

      // Clear stored data on authentication failure
      this.user = null;
      if (response.status === 401) {
        this.clearToken();
      }

      return {
        authenticated: false,
        message: data.message || 'Not authenticated'
      };

    } catch (error) {
      console.error('Authentication check failed:', error);
      this.user = null;
      return {
        authenticated: false,
        message: 'Network error during authentication check'
      };
    }
  }

  /**
   * Initialize authentication from URL parameters (for OAuth callbacks)
   */
  initializeFromUrl(): boolean {
    if (typeof window === 'undefined') return false;

    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    // const sessionId = urlParams.get('sessionId');

    if (token) {
      this.setToken(token);
      
      // Clean up URL
      const url = new URL(window.location.href);
      url.searchParams.delete('token');
      url.searchParams.delete('sessionId');
      window.history.replaceState({}, document.title, url.toString());
      
      return true;
    }

    return false;
  }

  /**
   * Get current user (cached)
   */
  getCurrentUser(): AuthUser | null {
    return this.user;
  }

  /**
   * Redirect to login page with return URL
   */
  redirectToLogin(callbackUrl?: string): void {
    const currentUrl = callbackUrl || (typeof window !== 'undefined' ? window.location.href : '');
    const loginUrl = `${this.authServiceUrl}/auth/user/login`;
    const url = currentUrl 
      ? `${loginUrl}?callbackUrl=${encodeURIComponent(currentUrl)}`
      : loginUrl;
    
    if (typeof window !== 'undefined') {
      window.location.href = url;
    }
  }

  /**
   * Logout by calling the auth service API endpoint
   */
  async logout(): Promise<void> {
    try {
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };

      if (this.token) {
        headers['Authorization'] = `Bearer ${this.token}`;
      }

      const response = await fetch(`${this.authServiceUrl}/api/auth/logout`, {
        method: 'POST',
        credentials: 'include',
        headers,
      });

      if (!response.ok) {
        throw new Error('Logout request failed');
      }

    } catch (error) {
      console.error('Logout request failed:', error);
    } finally {
      this.user = null;
      this.clearToken();
      this.stopPeriodicCheck();
      
      // Redirect to auth service login page
      if (typeof window !== 'undefined') {
        window.location.href = `${this.authServiceUrl}/auth/user/login`;
      }
    }
  }

  /**
   * Start periodic authentication checking
   */
  startPeriodicCheck(intervalMs: number = 300000): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
    }

    this.checkInterval = setInterval(async () => {
      const result = await this.checkAuthentication();
      if (!result.authenticated) {
        console.log('Session expired, redirecting to login...');
        this.redirectToLogin();
      }
    }, intervalMs);
  }

  /**
   * Stop periodic checking
   */
  stopPeriodicCheck(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
  }

  /**
   * Check if user has specific role
   */
  hasRole(role: string): boolean {
    return this.user?.role === role;
  }

  /**
   * Check if user has any of the specified roles
   */
  hasAnyRole(roles: string[]): boolean {
    return this.user ? roles.includes(this.user.role) : false;
  }

  /**
   * Check if user is admin or super_admin
   */
  isAdmin(): boolean {
    return this.hasAnyRole(['admin', 'super_admin']);
  }
}

// Create singleton instance
const authClient = new AuthClient(
  process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'https://access-management-xi.vercel.app'
);

export default authClient;