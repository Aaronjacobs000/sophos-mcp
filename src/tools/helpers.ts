/**
 * Shared utilities for tool implementations.
 */

import { CHARACTER_LIMIT } from "../config/config.js";

export type ToolResult = {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
};

/**
 * Creates a successful tool response with JSON content.
 */
export function jsonResult(data: unknown): ToolResult {
  const text = JSON.stringify(data, null, 2);
  if (text.length > CHARACTER_LIMIT) {
    return {
      content: [
        {
          type: "text",
          text:
            text.slice(0, CHARACTER_LIMIT) +
            "\n\n... [TRUNCATED] Response exceeded size limit. Use filters or pagination to narrow results.",
        },
      ],
    };
  }
  return { content: [{ type: "text", text }] };
}

/**
 * Creates an error tool response.
 */
export function errorResult(error: unknown): ToolResult {
  const message =
    error instanceof Error ? error.message : String(error);
  return {
    content: [{ type: "text", text: `Error: ${message}` }],
    isError: true,
  };
}

/**
 * Wraps an async tool handler with standard error handling.
 */
export function withErrorHandling<TArgs>(
  handler: (args: TArgs) => Promise<ToolResult>
): (args: TArgs) => Promise<ToolResult> {
  return async (args: TArgs) => {
    try {
      return await handler(args);
    } catch (error) {
      return errorResult(error);
    }
  };
}

/**
 * Attaches non-empty warnings to a result object. Tools surface partial
 * response and migration warnings this way rather than dropping them.
 */
export function withWarnings<T extends object>(
  result: T,
  warnings: string[]
): T | (T & { warnings: string[] }) {
  return warnings.length > 0 ? { ...result, warnings } : result;
}
