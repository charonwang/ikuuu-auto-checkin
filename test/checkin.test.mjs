import assert from "node:assert/strict";
import { mock, test } from "node:test";

// The workflow injects real Secrets into this process. Remove them without
// reading or retaining their values; never let a mock test fall back to them.
const secretNames = ["ACCOUNTS", "HOST", "TELEGRAM_TOKEN", "TELEGRAM_TO"];
for (const name of secretNames) delete process.env[name];

// Every request below is injected. Fail closed if a test accidentally uses fetch.
mock.method(globalThis, "fetch", () => { throw new Error("Real network is forbidden in mock tests"); });
const { checkIn, CheckInError, createCheckInUrl, main } = await import("../main.js");

const url = "https://example.test/user/checkin";
const account = { name: "PRIVATE_ACCOUNT", cookie: "PRIVATE_COOKIE" };
const response = (body, options = {}) => new Response(body, options);
const runResponse = (body, options) => checkIn(account, { url, request: async () => response(body, options) });

test("workflow Secrets are unavailable to mock tests", () => {
  for (const name of secretNames) assert.equal(process.env[name], undefined);
});

async function expectCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof CheckInError);
    assert.equal(error.code, code);
    assert.doesNotMatch(error.message, /PRIVATE_|example\.test|DOCTYPE|secret-query/);
    return true;
  });
}

test("successful JSON uses a fixed summary without the server's private message", async () => {
  let calls = 0;
  const result = await checkIn(account, {
    url,
    request: async (requestUrl, options) => {
      calls++;
      assert.equal(requestUrl, url);
      assert.equal(options.method, "POST");
      assert.equal(options.redirect, "manual");
      assert.equal(options.headers.Cookie, account.cookie);
      return response(JSON.stringify({ ret: 1, msg: "PRIVATE_SERVER_MESSAGE" }), { headers: { "content-type": "application/json" } });
    },
  });
  assert.equal(calls, 1);
  assert.match(result, /ret=1/);
  assert.doesNotMatch(result, /PRIVATE_/);
});

test("valid legacy JSON with a text/plain content type remains supported", async () => {
  const result = await runResponse('{"msg":"PRIVATE_SERVER_MESSAGE"}', { headers: { "content-type": "text/plain" } });
  assert.match(result, /有效 JSON/);
  assert.doesNotMatch(result, /PRIVATE_/);
});

for (const [label, location, code] of [
  ["login redirect", "/auth/login?token=secret-query", "AUTH_REQUIRED"],
  ["cross-origin redirect", "https://other.test/auth/login?token=secret-query", "HOST_REDIRECT"],
  ["other redirect", "/maintenance?token=secret-query", "REDIRECT"],
  ["malformed redirect", "https://[invalid/?token=secret-query", "REDIRECT"],
]) {
  test(`${label} is classified without following or exposing the URL`, async () => {
    let calls = 0;
    await expectCode(checkIn(account, { url, request: async () => {
      calls++;
      return response(null, { status: 302, headers: { location } });
    } }), code);
    assert.equal(calls, 1);
  });
}

test("missing redirect Location remains an unclassified redirect", async () => {
  await expectCode(runResponse(null, { status: 307 }), "REDIRECT");
});

for (const [label, body, options, code] of [
  ["HTTP 401", "PRIVATE_BODY", { status: 401 }, "AUTH_REQUIRED"],
  ["HTTP 404", "PRIVATE_BODY", { status: 404 }, "ENDPOINT_NOT_FOUND"],
  ["HTTP 500 JSON", '{"msg":"PRIVATE_BODY"}', { status: 500, headers: { "content-type": "application/json" } }, "HTTP_ERROR"],
  ["challenge header", "PRIVATE_BODY", { status: 403, headers: { "cf-mitigated": "challenge" } }, "CHALLENGE"],
  ["challenge HTML", '<!DOCTYPE html><script src="/cdn-cgi/challenge-platform/PRIVATE_TOKEN"></script>', { headers: { "content-type": "text/html" } }, "CHALLENGE"],
  ["login HTML", '<!DOCTYPE html><form action="/auth/login"><input type="password" value="PRIVATE_VALUE"></form>', { headers: { "content-type": "text/html" } }, "AUTH_REQUIRED"],
  ["generic HTML", "<!DOCTYPE html><html>PRIVATE_BODY</html>", { headers: { "content-type": "text/html" } }, "NON_JSON"],
  ["HTML mislabeled as JSON", "<!DOCTYPE html><html>PRIVATE_BODY</html>", { headers: { "content-type": "application/json" } }, "NON_JSON"],
  ["unknown HTTP 403", "PRIVATE_BODY", { status: 403 }, "HTTP_ERROR"],
  ["malformed JSON", '{"msg":"PRIVATE_BODY",}', { headers: { "content-type": "application/json" } }, "NON_JSON"],
  ["unexpected JSON shape", '{"PRIVATE_FIELD":"PRIVATE_BODY"}', { headers: { "content-type": "application/json" } }, "INVALID_RESPONSE"],
  ["JSON null", "null", {}, "INVALID_RESPONSE"],
  ["JSON login requirement", '{"ret":0,"msg":"未登录 PRIVATE_BODY"}', {}, "AUTH_REQUIRED"],
  ["JSON business rejection", '{"ret":0,"msg":"PRIVATE_BODY"}', {}, "REJECTED"],
]) {
  test(`${label} gives a safe diagnostic`, async () => {
    await expectCode(runResponse(body, options), code);
  });
}

test("network exceptions never expose their original error", async () => {
  await expectCode(checkIn(account, { url, request: async () => {
    throw new Error("PRIVATE_COOKIE https://example.test/?token=secret-query");
  } }), "REQUEST_FAILED");
});

test("response read exceptions never expose their original error", async () => {
  await expectCode(checkIn(account, { url, request: async () => ({
    status: 200, ok: true, headers: new Headers(),
    text: async () => { throw new Error("PRIVATE_COOKIE secret-query"); },
  }) }), "RESPONSE_READ_FAILED");
});

test("HOST validation rejects sensitive URL components without echoing them", () => {
  assert.equal(createCheckInUrl("example.test:443"), url);
  for (const host of ["https://example.test", "example.test/path", "PRIVATE_USER:PRIVATE_PASSWORD@example.test", "example.test?token=secret-query", ""]) {
    assert.throws(() => createCheckInUrl(host), (error) => {
      assert.equal(error.code, "HOST_INVALID");
      assert.doesNotMatch(error.message, /PRIVATE_|example\.test|secret-query/);
      return true;
    });
  }
});

test("mixed account results keep failure status and redact logs and GitHub output", async () => {
  const logs = [];
  const outputs = [];
  let calls = 0;
  const exitCode = await main({
    accountsConfig: JSON.stringify([account, { name: "PRIVATE_SECOND_ACCOUNT", cookie: "PRIVATE_SECOND_COOKIE" }]),
    host: "example.test",
    request: async () => ++calls === 1
      ? response('{"ret":1,"msg":"PRIVATE_SERVER_MESSAGE"}')
      : response("<!DOCTYPE html><html>PRIVATE_BODY</html>"),
    logger: { log: (message) => logs.push(message), error: (message) => logs.push(message) },
    output: (name, value) => outputs.push({ name, value }),
  });
  assert.equal(exitCode, 1);
  assert.equal(calls, 2);
  assert.equal(outputs.length, 1);
  assert.equal(outputs[0].name, "result");
  assert.match(outputs[0].value, /账户 #1: ✅/);
  assert.match(outputs[0].value, /账户 #2: ❌.*NON-JSON/);
  assert.doesNotMatch(JSON.stringify({ logs, outputs }), /PRIVATE_|example\.test|DOCTYPE/);
});

test("invalid ACCOUNTS produce safe output and never send requests", async () => {
  for (const accountsConfig of [undefined, "PRIVATE_INVALID_JSON", "{}", "[]", '[{"cookie":""}]']) {
    const logs = [];
    let calls = 0;
    const exitCode = await main({
      accountsConfig,
      host: "example.test",
      request: async () => { calls++; throw new Error("Request must not happen"); },
      logger: { error: (message) => logs.push(message) },
      output: (_name, message) => logs.push(message),
    });
    assert.equal(exitCode, 1);
    assert.equal(calls, 0);
    assert.match(logs[0], /CONFIG-INVALID/);
    assert.doesNotMatch(logs.join("\n"), /PRIVATE_/);
  }
});

test("undefined configuration falls back only to an isolated fake environment", async () => {
  process.env.ACCOUNTS = JSON.stringify([account]);
  process.env.HOST = "example.test";
  const logs = [];
  let calls = 0;
  const options = {
    request: async (requestUrl, requestOptions) => {
      calls++;
      assert.equal(requestUrl, url);
      assert.equal(requestOptions.headers.Cookie, account.cookie);
      assert.equal(requestOptions.redirect, "manual");
      return response('{"ret":1,"msg":"PRIVATE_ENV_MESSAGE"}');
    },
    logger: { log: (message) => logs.push(message), error: (message) => logs.push(message) },
    output: (_name, message) => logs.push(message),
  };
  try {
    // Reproduce the CI default-parameter branch using fake values exclusively.
    assert.equal(await main({ ...options, accountsConfig: undefined }), 0);
    assert.equal(calls, 1);
    assert.doesNotMatch(logs.join("\n"), /PRIVATE_|example\.test/);

    // An explicit invalid configuration must not fall back to the environment.
    logs.length = 0;
    assert.equal(await main({ ...options, accountsConfig: "PRIVATE_INVALID_JSON" }), 1);
    assert.equal(calls, 1);
    assert.match(logs[0], /CONFIG-INVALID/);
    assert.doesNotMatch(logs.join("\n"), /PRIVATE_/);
  } finally {
    for (const name of secretNames) delete process.env[name];
  }
});
