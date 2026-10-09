import { appendFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const messages = {
  CONFIG_INVALID: "ACCOUNTS 必须是非空 JSON 数组，且每项包含非空 cookie。",
  HOST_INVALID: "HOST 必须是域名（可带端口），不能包含协议、路径或认证信息。",
  REQUEST_FAILED: "签到请求失败；请检查站点可用性与网络。",
  RESPONSE_READ_FAILED: "无法读取签到响应。",
  AUTH_REQUIRED: "接口要求登录；请在网站确认登录状态，必要时更新认证配置。",
  HOST_REDIRECT: "接口重定向到其他站点；未跟随跳转，请核对 HOST 与当前站点地址。",
  REDIRECT: "接口发生重定向；未跟随跳转，请核对站点地址与登录状态。",
  CHALLENGE: "接口返回验证挑战页；自动签到尚未完成，请在网站检查验证要求。",
  ENDPOINT_NOT_FOUND: "签到接口不存在；请核对 HOST 与接口路径。",
  HTTP_ERROR: "签到接口返回 HTTP 错误。",
  NON_JSON: "接口返回非 JSON 内容；请核对站点地址、登录状态或验证要求。",
  INVALID_RESPONSE: "接口返回的 JSON 结构不符合预期。",
  REJECTED: "网站拒绝签到请求；请在网站查看原因。",
  UNEXPECTED_FAILURE: "签到处理失败；未输出可能含敏感信息的原始错误。",
};

export class CheckInError extends Error {
  constructor(code, status) {
    const suffix = Number.isInteger(status) && status >= 100 && status <= 599
      ? `（HTTP ${status}）` : "";
    // Keep summaries compatible with the existing Telegram Markdown format.
    super(`${code.replaceAll("_", "-")}: ${messages[code]}${suffix}`);
    this.name = "CheckInError";
    this.code = code;
  }
}

export function createCheckInUrl(host) {
  try {
    if (typeof host !== "string" || !host.trim() || /[\s/\\?#@]/.test(host)) {
      throw new Error();
    }
    const url = new URL(`https://${host}/user/checkin`);
    if (url.username || url.password || url.pathname !== "/user/checkin") {
      throw new Error();
    }
    return url.href;
  } catch {
    throw new CheckInError("HOST_INVALID");
  }
}

const isLoginPath = (pathname) => /\/(?:login|signin|sign-in)(?:\/|$)/i.test(pathname);

export async function checkIn(account, { url, request = fetch }) {
  let response;
  try {
    response = await request(url, {
      method: "POST",
      headers: { Cookie: account.cookie },
      redirect: "manual",
    });
  } catch {
    throw new CheckInError("REQUEST_FAILED");
  }

  const status = response.status;
  if ([301, 302, 303, 307, 308].includes(status)) {
    let target;
    try {
      const location = response.headers.get("location");
      if (location) target = new URL(location, url);
    } catch {
      // Never expose a malformed or sensitive redirect URL.
    }
    if (target && target.origin !== new URL(url).origin) {
      throw new CheckInError("HOST_REDIRECT", status);
    }
    if (target && isLoginPath(target.pathname)) {
      throw new CheckInError("AUTH_REQUIRED", status);
    }
    throw new CheckInError("REDIRECT", status);
  }

  if (response.headers.get("cf-mitigated")?.toLowerCase() === "challenge") {
    throw new CheckInError("CHALLENGE", status);
  }
  if (status === 401) throw new CheckInError("AUTH_REQUIRED", status);
  if (status === 404) throw new CheckInError("ENDPOINT_NOT_FOUND", status);

  let body;
  try {
    body = await response.text();
  } catch {
    throw new CheckInError("RESPONSE_READ_FAILED", status);
  }

  // Inspect only a small prefix for classification. Never log response content.
  const prefix = body.slice(0, 8192);
  const contentType = response.headers.get("content-type") || "";
  const isHtml = /\btext\/html\b/i.test(contentType)
    || /^\s*(?:<!doctype\s+html|<html\b)/i.test(prefix);
  if (isHtml) {
    if (/\/cdn-cgi\/challenge-platform\/|\bcf-chl-/i.test(prefix)) {
      throw new CheckInError("CHALLENGE", status);
    }
    if (/<input\b[^>]*\btype\s*=\s*["']?password\b/i.test(prefix)
      && /<form\b[^>]*\baction\s*=\s*["'][^"']*\/(?:login|signin|sign-in)(?:[/?#"'])/i.test(prefix)) {
      throw new CheckInError("AUTH_REQUIRED", status);
    }
    throw new CheckInError("NON_JSON", status);
  }
  if (!response.ok) throw new CheckInError("HTTP_ERROR", status);

  let data;
  try {
    data = JSON.parse(body);
  } catch {
    // JSON parser errors can contain response fragments, so discard them.
    throw new CheckInError("NON_JSON", status);
  }
  if (!data || typeof data !== "object" || Array.isArray(data) || typeof data.msg !== "string") {
    throw new CheckInError("INVALID_RESPONSE", status);
  }
  if (data.ret === 0) {
    const needsLogin = /未登录|请.{0,12}登录|登录.{0,12}(?:失效|过期)|not\s+logged\s+in|unauthenticated|session\s+(?:expired|invalid)/i.test(data.msg);
    throw new CheckInError(needsLogin ? "AUTH_REQUIRED" : "REJECTED", status);
  }
  return data.ret === 1
    ? "网站返回签到成功（ret=1）。"
    : "接口返回有效 JSON；请以网站签到记录为准。";
}

function safeError(error) {
  return error instanceof CheckInError
    ? error.message : new CheckInError("UNEXPECTED_FAILURE").message;
}

function setGitHubOutput(name, value) {
  appendFileSync(process.env.GITHUB_OUTPUT, `${name}<<EOF\n${value}\nEOF\n`);
}

export async function main({
  accountsConfig = process.env.ACCOUNTS,
  host = process.env.HOST || "ikuuu.win",
  request = fetch,
  output = setGitHubOutput,
  logger = console,
} = {}) {
  let accounts;
  let url;
  try {
    try {
      accounts = JSON.parse(accountsConfig);
      if (!Array.isArray(accounts) || accounts.length === 0
        || !accounts.every((account) => account && typeof account.cookie === "string" && account.cookie.trim())) {
        throw new Error();
      }
    } catch {
      throw new CheckInError("CONFIG_INVALID");
    }
    url = createCheckInUrl(host);
  } catch (error) {
    const message = safeError(error);
    logger.error(message);
    output("result", message);
    return 1;
  }

  const results = await Promise.allSettled(accounts.map((account) => checkIn(account, { url, request })));
  logger.log("\n======== 签到结果 ========\n");
  let hasError = false;
  const resultLines = results.map((result, index) => {
    const isSuccess = result.status === "fulfilled";
    if (!isSuccess) hasError = true;
    const message = isSuccess ? result.value : safeError(result.reason);
    // Number accounts locally; never include names, cookies or server messages.
    const line = `账户 #${index + 1}: ${isSuccess ? "✅" : "❌"} ${message}`;
    isSuccess ? logger.log(line) : logger.error(line);
    return line;
  });
  output("result", resultLines.join("\n"));
  return hasError ? 1 : 0;
}

// Importing this file for mock tests must never send a real check-in request.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => { process.exitCode = code; }).catch(() => {
    console.error(new CheckInError("UNEXPECTED_FAILURE").message);
    process.exitCode = 1;
  });
}
