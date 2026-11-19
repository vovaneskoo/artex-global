const TOKEN_KEY = "artex_token";
// Session-presence cookie for the Next.js middleware route guard (proxy.ts).
// NEVER carries the JWT: cookies are shared by every port on the same host
// (localhost:5173 and localhost:9999 are one "site"), so a cookie that held the
// real token authenticated forged cross-origin mutations (CSRF). API calls use
// Authorization: Bearer from localStorage; the middleware only needs to know a
// session exists to decide login redirects.
const SESSION_COOKIE = "artex_auth";
const LEGACY_COOKIE = "artex_token";
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60; // 7 天（秒）

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export const auth = {
  getToken(): string | null {
    if (typeof window === "undefined") return null;
    // Mock demo：无真实登录，返回一个假 token 让路由守卫放行、直接进主界面。
    return localStorage.getItem(TOKEN_KEY) ?? (process.env.NEXT_PUBLIC_MOCK === "1" ? "mock-demo" : null);
  },

  setToken(token: string): void {
    localStorage.setItem(TOKEN_KEY, token);
    // 写"已登录"标记 cookie（不含 token 本体），供 Next.js middleware 服务端读取。
    // 同时清掉旧版本写入的携带 JWT 的 artex_token cookie（迁移：老 cookie 立即失效）。
    // biome-ignore lint/suspicious/noDocumentCookie: middleware 需要服务端可读的标记 cookie，这里不能换成 Cookie Store API。
    document.cookie = `${SESSION_COOKIE}=1; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax`;
    // biome-ignore lint/suspicious/noDocumentCookie: 清理旧版 JWT cookie（迁移）。
    document.cookie = `${LEGACY_COOKIE}=; path=/; max-age=0`;
  },

  clearToken(): void {
    localStorage.removeItem(TOKEN_KEY);
    // biome-ignore lint/suspicious/noDocumentCookie: 见 setToken。
    document.cookie = `${SESSION_COOKIE}=; path=/; max-age=0`;
    // biome-ignore lint/suspicious/noDocumentCookie: 见 setToken。
    document.cookie = `${LEGACY_COOKIE}=; path=/; max-age=0`;
  },

  // 从 JWT payload 的 sub 字段解析当前用户，仅用于展示，不做签名验证。
  getCurrentUser(): CurrentUser | null {
    const token = this.getToken();
    if (!token) return null;
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      // base64url → base64
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      const username: string = payload.sub ?? "ARTEX";
      return { id: "1", name: username, username, email: "", avatar: "", role: "operator" };
    } catch {
      return null;
    }
  },
};
