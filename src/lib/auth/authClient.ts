// File: lib/auth/authClient.ts
// Updated version for profile service to work with your auth service structure

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
  message?: string;
}

class AuthClient {
  private authServiceUrl: string;
  private user: AuthUser | null = null;
  private checkInterval: NodeJS.Timeout | null = null;

  constructor(authServiceUrl: string) {
    this.authServiceUrl = authServiceUrl;
  }

  /**
   * Check if user is authenticated by calling the auth service
   */
  async checkAuthentication(): Promise<AuthResponse> {
    try {
      const response = await fetch(
        `${this.authServiceUrl}/api/auth/verify-session`,
        {
          method: "GET",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
        }
      );

      const data: AuthResponse = await response.json();

      if (response.ok && data.authenticated && data.user) {
        this.user = data.user;
        return {
          authenticated: true,
          user: data.user,
        };
      }

      this.user = null;
      return {
        authenticated: false,
        message: data.message || "Not authenticated",
      };
    } catch (error) {
      console.error("Authentication check failed:", error);
      this.user = null;
      return {
        authenticated: false,
        message: "Network error during authentication check",
      };
    }
  }

  /**
   * Get current user (cached)
   */
  getCurrentUser(): AuthUser | null {
    return this.user;
  }

  /**
   * Redirect to login page
   */
  redirectToLogin(callbackUrl?: string): void {
    const loginUrl = `${this.authServiceUrl}/auth/users/login`;
    const url = callbackUrl
      ? `${loginUrl}?callbackUrl=${encodeURIComponent(callbackUrl)}`
      : loginUrl;

    window.location.href = url;
  }

  /**
   * Logout by calling the auth service API endpoint
   */
  async logout(): Promise<void> {
    try {
      const response = await fetch(`${this.authServiceUrl}/api/auth/logout`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        throw new Error("Logout request failed");
      }
    } catch (error) {
      console.error("Logout request failed:", error);
      // Even if the API call fails, we should still clean up locally
    } finally {
      this.user = null;
      this.stopPeriodicCheck();
      // Redirect to auth service login page
      window.location.href = `${this.authServiceUrl}/auth/users/login`;
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
        console.log("Session expired, redirecting to login...");
        this.redirectToLogin(window.location.pathname);
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
    return this.hasAnyRole(["admin", "super_admin"]);
  }
}

// Create singleton instance
const authClient = new AuthClient(
  process.env.NEXT_PUBLIC_AUTH_ACCESS_URL ||
    "https://access-management-xi.vercel.app"
);

export default authClient;
