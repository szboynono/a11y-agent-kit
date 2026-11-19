import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/client/stdio';

// StdioClientTransport hands its child only the SDK's default env whitelist (HOME, PATH, ...) unless `env` is
// given. Forward just the browser location on top of that default, so tests find Chromium when the parent uses
// a custom PLAYWRIGHT_BROWSERS_PATH, without leaking the rest of the environment.
export function mcpTransport(params) {
  const forwarded = process.env.PLAYWRIGHT_BROWSERS_PATH === undefined ? {} : { PLAYWRIGHT_BROWSERS_PATH: process.env.PLAYWRIGHT_BROWSERS_PATH };
  return new StdioClientTransport({ ...params, env: { ...getDefaultEnvironment(), ...forwarded, ...params.env } });
}
