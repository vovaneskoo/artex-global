import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

const AUTH_PAGES = ["/login", "/setup"];

export function proxy(request: NextRequest) {
  // Mock demo：无真实登录，放行所有页面（客户端 auth 守卫也会放行）。
  if (process.env.NEXT_PUBLIC_MOCK === "1") return NextResponse.next();

  const { pathname } = request.nextUrl;
  // Session presence only — never a credential. The new marker cookie (artex_auth)
  // says "logged in"; the legacy artex_token cookie (which used to carry the JWT)
  // is still honored for routing so sessions created before the upgrade are not
  // bounced to /login. API auth is always the Authorization header, so a stale
  // legacy cookie grants no API access — the backend rejects cookie auth.
  const sessionCookie = request.cookies.get("artex_auth")?.value;
  const legacyCookie = request.cookies.get("artex_token")?.value;
  const token = sessionCookie === "1" || legacyCookie;
  const isAuthPage = AUTH_PAGES.some((p) => pathname === p || pathname.startsWith(`${p}/`));

  // 未登录 → 跳转登录页
  if (!token && !isAuthPage) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  // 已登录时访问登录/初始化页 → 跳转主界面
  if (token && isAuthPage) {
    return NextResponse.redirect(new URL("/function/tasks", request.url));
  }

  return NextResponse.next();
}

export const config = {
  // 跳过 Next.js 内部路由、API 路由、favicon 及 public/ 下的静态文件（含图片、字体等）
  matcher: [
    "/((?!_next/static|_next/image|favicon\\.ico|api/|.*\\.(?:png|jpg|jpeg|gif|webp|svg|ico|woff2?|ttf|otf)$).*)",
  ],
};
