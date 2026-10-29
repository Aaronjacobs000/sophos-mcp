/**
 * Tools: sophos_search_quarantine, sophos_preview_quarantine_message,
 *        sophos_get_quarantine_urls, sophos_get_quarantine_attachments,
 *        sophos_release_quarantine_message, sophos_delete_quarantine_message,
 *        sophos_strip_quarantine_attachments, sophos_reattach_quarantine_attachments,
 *        sophos_download_quarantine_attachment,
 *        sophos_search_post_delivery_quarantine, sophos_preview_post_delivery_message,
 *        sophos_get_post_delivery_attachments, sophos_release_post_delivery_message,
 *        sophos_delete_post_delivery_message, sophos_download_post_delivery_attachment,
 *        sophos_clawback_message, sophos_get_clawback_status,
 *        sophos_list_mailboxes, sophos_create_mailbox, sophos_bulk_create_mailboxes,
 *        sophos_get_mailbox, sophos_update_mailbox, sophos_delete_mailbox,
 *        sophos_list_mailbox_aliases, sophos_add_mailbox_alias, sophos_delete_mailbox_alias,
 *        sophos_list_mailbox_delegates, sophos_add_mailbox_delegate, sophos_delete_mailbox_delegate
 * Interact with the Sophos Email API /email/v1/, shaped by its published spec
 * (email-v1 1.4.0) and checked against the live API on 13/10/2026.
 *
 * Message IDs are the X-Sophos-Email-ID header value (a UUID). Release and
 * delete take batches of up to 50 messages. Attachment downloads are jobs: the
 * tool starts one and polls its status for the download URL.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";

const tenantIdSchema = z
  .string()
  .guid()
  .optional()
  .describe("Tenant ID. Required for partner/org callers.");

const messageIdSchema = z.string().guid().describe("Message ID (the X-Sophos-Email-ID header value)");
const messageIdsSchema = z.array(z.string().guid()).min(1).max(50).describe("Message IDs (X-Sophos-Email-ID), up to 50");
const recipientsSchema = z.array(z.string().email()).optional().describe("Only for these recipients; all when omitted");
const pageSizeSchema = z.number().int().min(1).max(100).optional().default(50).describe("Results per page (1-100, default 50)");
const mailboxTypeSchema = z.enum(["user", "distributionList", "publicFolder", "sharedMailbox"]);
const mailboxIdSchema = z.string().guid().describe("Mailbox ID");

const QUARANTINE_REASONS = [
  "bulk", "dataControl", "dkim", "dmarc", "headerAnomaly", "domainAnomaly", "imageAnalysis",
  "impersonation", "intelixMalicious", "intelixSuspicious", "intelixUnscannable", "maliciousUrl",
  "malware", "s/mime", "spam", "spf", "suspectedSpam", "unscannable", "countrySpam",
  "languageSpam", "batvSpam", "nrdSpam",
] as const;

const READ = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };

/** The filter object both quarantine searches share. */
function searchFilter(a: {
  message_id?: string;
  from_contains?: string;
  to_contains?: string;
  subject_contains?: string;
  attachment_name_contains?: string;
  size_mb_greater_than?: number;
  size_mb_lower_than?: number;
  product_type?: string;
  reason?: string[];
  has_any_attachment?: boolean;
  direction?: string;
}): Record<string, unknown> | undefined {
  const f: Record<string, unknown> = {};
  if (a.message_id) f.id = a.message_id;
  if (a.from_contains) f.fromContains = a.from_contains;
  if (a.to_contains) f.toContains = a.to_contains;
  if (a.subject_contains) f.subjectContains = a.subject_contains;
  if (a.attachment_name_contains) f.attachmentNameContains = a.attachment_name_contains;
  if (a.size_mb_greater_than !== undefined) f.sizeInMBGreaterThan = a.size_mb_greater_than;
  if (a.size_mb_lower_than !== undefined) f.sizeInMBLowerThan = a.size_mb_lower_than;
  if (a.product_type) f.productType = a.product_type;
  if (a.reason?.length) f.reason = a.reason;
  if (a.has_any_attachment !== undefined) f.hasAnyAttachment = a.has_any_attachment;
  if (a.direction) f.direction = a.direction;
  return Object.keys(f).length ? f : undefined;
}

const sharedSearchFields = {
  begin_date: z.string().describe("Quarantined on or after this time (ISO 8601)"),
  end_date: z.string().describe("Quarantined before this time (ISO 8601)"),
  message_id: z.string().guid().optional().describe("One message by X-Sophos-Email-ID"),
  from_contains: z.string().optional().describe("Sender contains"),
  to_contains: z.string().optional().describe("Recipient contains"),
  subject_contains: z.string().optional().describe("Subject contains"),
  attachment_name_contains: z.string().optional().describe("An attachment name contains"),
  size_mb_greater_than: z.number().optional().describe("Larger than this many MB"),
  size_mb_lower_than: z.number().optional().describe("Smaller than this many MB"),
  product_type: z.enum(["mailflow", "gateway", "ems"]).optional().describe("Email product"),
  has_any_attachment: z.boolean().optional().describe("Only messages with at least one attachment"),
  sort: z.array(z.string()).optional().describe('Sort fields, for example "quarantinedAt:desc"'),
  page_size: pageSizeSchema,
  tenant_id: tenantIdSchema,
};

/** Starts an attachment download job and polls its status until it has a URL or an error. */
async function downloadAttachments(
  client: SophosClient,
  tenantId: string,
  area: "quarantine" | "post-delivery-quarantine",
  messageId: string,
  attachments: string[] | undefined
): Promise<Record<string, unknown>> {
  type Job = { id?: string; status?: string; url?: string; error?: string };
  let job = await client.tenantRequest<Job>(tenantId, `/email/v1/${area}/messages/${messageId}/attachments/download`, {
    method: "POST",
    body: attachments?.length ? { attachments } : {},
  });
  for (let i = 0; i < 6 && job.id && !job.url && !job.error; i++) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    job = await client.tenantRequest<Job>(tenantId, `/email/v1/${area}/downloads/${job.id}/status`);
  }
  return {
    ...job,
    ...(job.url ? {} : { note: "The download is not ready yet. Call this tool again later for its URL." }),
  };
}

export function registerEmailTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // =========================================================================
  // Quarantine (9 tools)
  // =========================================================================

  // --- Search Quarantine ---
  server.registerTool(
    "sophos_search_quarantine",
    {
      title: "Search Quarantined Emails",
      description: `Search messages held in Sophos Email quarantine.

begin_date and end_date are required. Results page by key: pass the previous
result's pages.nextKey as page_from_key.

Args:
  - begin_date, end_date (string): Quarantine time window (ISO 8601).
  - from_contains, to_contains, subject_contains, attachment_name_contains (string, optional).
  - reason (array, optional): Quarantine reasons, for example "spam", "malware", "maliciousUrl".
  - direction (string, optional): "inbound" or "outbound".
  - message_id, size_mb_greater_than, size_mb_lower_than, product_type, has_any_attachment (optional).
  - sort (array, optional): For example "quarantinedAt:desc"; fields from, forRecipient, quarantinedAt.
  - page_size (number, optional), page_from_key (string, optional).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        ...sharedSearchFields,
        reason: z.array(z.enum(QUARANTINE_REASONS)).optional().describe("Quarantine reasons"),
        direction: z.enum(["inbound", "outbound"]).optional().describe("Mail direction"),
        page_from_key: z.string().optional().describe("pages.nextKey from the previous page"),
      },
      annotations: READ,
    },
    withErrorHandling(async ({ begin_date, end_date, sort, page_size, page_from_key, tenant_id, ...f }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { beginDate: begin_date, endDate: end_date, pageSize: page_size };
      const filter = searchFilter(f);
      if (filter) body.filter = filter;
      if (sort) body.sort = sort;
      if (page_from_key) body.pageFromKey = page_from_key;
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, "/email/v1/quarantine/messages/search", {
        method: "POST",
        body,
      });
      return jsonResult(data);
    })
  );

  // --- Preview Quarantine Message ---
  server.registerTool(
    "sophos_preview_quarantine_message",
    {
      title: "Preview Quarantined Email",
      description: `Preview a quarantined message.

Args:
  - message_id (string): X-Sophos-Email-ID of the message.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { message_id: messageIdSchema, tenant_id: tenantIdSchema },
      annotations: READ,
    },
    withErrorHandling(async ({ message_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      return jsonResult(
        await client.tenantRequest<Record<string, unknown>>(tenantId, `/email/v1/quarantine/messages/${message_id}/preview`)
      );
    })
  );

  // --- Get Quarantine URLs ---
  server.registerTool(
    "sophos_get_quarantine_urls",
    {
      title: "Get Quarantined Email URLs",
      description: `List the URLs found in the body of a quarantined message.

Args:
  - message_id (string): X-Sophos-Email-ID of the message.
  - page (number, optional), page_size (number, optional).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        message_id: messageIdSchema,
        page: z.number().int().min(1).optional().default(1).describe("Page number (default 1)"),
        page_size: pageSizeSchema,
        tenant_id: tenantIdSchema,
      },
      annotations: READ,
    },
    withErrorHandling(async ({ message_id, page, page_size, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      return jsonResult(
        await client.tenantRequest<Record<string, unknown>>(tenantId, `/email/v1/quarantine/messages/${message_id}/urls`, {
          params: { page: String(page), pageSize: String(page_size) },
        })
      );
    })
  );

  // --- Get Quarantine Attachments ---
  server.registerTool(
    "sophos_get_quarantine_attachments",
    {
      title: "Get Quarantined Email Attachments",
      description: `List the attachments of a quarantined message.

Args:
  - message_id (string): X-Sophos-Email-ID of the message.
  - page (number, optional), page_size (number, optional).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        message_id: messageIdSchema,
        page: z.number().int().min(1).optional().default(1).describe("Page number (default 1)"),
        page_size: pageSizeSchema,
        tenant_id: tenantIdSchema,
      },
      annotations: READ,
    },
    withErrorHandling(async ({ message_id, page, page_size, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      return jsonResult(
        await client.tenantRequest<Record<string, unknown>>(tenantId, `/email/v1/quarantine/messages/${message_id}/attachments`, {
          params: { page: String(page), pageSize: String(page_size) },
        })
      );
    })
  );

  // --- Release Quarantine Message ---
  server.registerTool(
    "sophos_release_quarantine_message",
    {
      title: "Release Quarantined Email",
      description: `Queue quarantined messages for release (up to 50 per call).

Args:
  - message_ids (array): X-Sophos-Email-ID values.
  - for_recipients (array, optional): Release only to these recipients.
  - strip_attachments (array, optional): Attachment names to strip on release.
  - allow_sender (boolean, optional): Add the sender to the allow list.
  - enforce_sender_authentication (boolean, optional): Keep authentication checks for that allowed sender.
  - submit_to_labs (boolean, optional): Report the messages to SophosLabs as false positives (spam and virus).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        message_ids: messageIdsSchema,
        for_recipients: recipientsSchema,
        strip_attachments: z.array(z.string()).optional().describe("Attachment names to strip on release"),
        allow_sender: z.boolean().optional().describe("Add the sender to the allow list"),
        enforce_sender_authentication: z.boolean().optional().describe("Keep authentication checks for the allowed sender"),
        submit_to_labs: z.boolean().optional().describe("Report to SophosLabs as false positives"),
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    withErrorHandling(async (a) => {
      const tenantId = tenantResolver.resolveTenantId(a.tenant_id);
      const items = a.message_ids.map((id) => ({
        id,
        ...(a.for_recipients ? { forRecipients: a.for_recipients } : {}),
        ...(a.strip_attachments ? { stripAttachments: a.strip_attachments } : {}),
      }));
      const body: Record<string, unknown> = { items };
      if (a.allow_sender !== undefined) body.allowSender = a.allow_sender;
      if (a.enforce_sender_authentication !== undefined) body.enforceSenderAuthentication = a.enforce_sender_authentication;
      if (a.submit_to_labs !== undefined) body.submitMessageToLabs = a.submit_to_labs;
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, "/email/v1/quarantine/messages/release", {
        method: "POST",
        body,
      });
      return jsonResult({ status: "release_queued", result: data });
    })
  );

  // --- Delete Quarantine Message ---
  server.registerTool(
    "sophos_delete_quarantine_message",
    {
      title: "Delete Quarantined Email",
      description: `Delete messages from quarantine (up to 50 per call).

Args:
  - message_ids (array): X-Sophos-Email-ID values.
  - for_recipients (array, optional): Delete only for these recipients.
  - block_sender (boolean, optional): Add the sender to the block list.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        message_ids: messageIdsSchema,
        for_recipients: recipientsSchema,
        block_sender: z.boolean().optional().describe("Add the sender to the block list"),
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ message_ids, for_recipients, block_sender, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = {
        items: message_ids.map((id) => ({ id, ...(for_recipients ? { forRecipients: for_recipients } : {}) })),
      };
      if (block_sender !== undefined) body.blockSender = block_sender;
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, "/email/v1/quarantine/messages/delete", {
        method: "POST",
        body,
      });
      return jsonResult({ status: "deleted", result: data });
    })
  );

  // --- Strip Quarantine Attachments ---
  server.registerTool(
    "sophos_strip_quarantine_attachments",
    {
      title: "Strip Quarantined Email Attachments",
      description: `Strip attachments from a quarantined message.

Args:
  - message_id (string): X-Sophos-Email-ID of the message.
  - attachments (array, optional): Attachment names to strip; all when omitted.
  - for_recipients (array, optional): Only for these recipients.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        message_id: messageIdSchema,
        attachments: z.array(z.string()).optional().describe("Attachment names; all when omitted"),
        for_recipients: recipientsSchema,
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    withErrorHandling(async ({ message_id, attachments, for_recipients, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = {};
      if (attachments) body.attachments = attachments;
      if (for_recipients) body.forRecipients = for_recipients;
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/email/v1/quarantine/messages/${message_id}/attachments/strip`,
        { method: "POST", body }
      );
      return jsonResult({ status: "stripped", result: data });
    })
  );

  // --- Reattach Quarantine Attachments ---
  server.registerTool(
    "sophos_reattach_quarantine_attachments",
    {
      title: "Reattach Quarantine Attachments",
      description: `Reattach stripped attachments to a quarantined message.

Args:
  - message_id (string): X-Sophos-Email-ID of the message.
  - attachments (array, optional): Attachment names to reattach; all when omitted.
  - for_recipients (array, optional): Only for these recipients.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        message_id: messageIdSchema,
        attachments: z.array(z.string()).optional().describe("Attachment names; all when omitted"),
        for_recipients: recipientsSchema,
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    withErrorHandling(async ({ message_id, attachments, for_recipients, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = {};
      if (attachments) body.attachments = attachments;
      if (for_recipients) body.forRecipients = for_recipients;
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/email/v1/quarantine/messages/${message_id}/attachments/reattach`,
        { method: "POST", body }
      );
      return jsonResult({ status: "reattached", result: data });
    })
  );

  // --- Download Quarantine Attachment ---
  server.registerTool(
    "sophos_download_quarantine_attachment",
    {
      title: "Download Quarantine Attachment",
      description: `Get a download link for attachments of a quarantined message.

Starts a download job and checks its status for up to about 12 seconds. The
result has the job's url and the ZIP password when ready.

Args:
  - message_id (string): X-Sophos-Email-ID of the message.
  - attachments (array, optional): Attachment names; all when omitted.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        message_id: messageIdSchema,
        attachments: z.array(z.string()).optional().describe("Attachment names; all when omitted"),
        tenant_id: tenantIdSchema,
      },
      annotations: READ,
    },
    withErrorHandling(async ({ message_id, attachments, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      return jsonResult(await downloadAttachments(client, tenantId, "quarantine", message_id, attachments));
    })
  );

  // =========================================================================
  // Post-Delivery Quarantine (6 tools)
  // =========================================================================

  // --- Search Post-Delivery Quarantine ---
  server.registerTool(
    "sophos_search_post_delivery_quarantine",
    {
      title: "Search Post-Delivery Quarantined Emails",
      description: `Search messages pulled into post-delivery quarantine after delivery.

begin_date and end_date are required. Results page by number.

Args:
  - begin_date, end_date (string): Quarantine time window (ISO 8601).
  - from_contains, to_contains, subject_contains, attachment_name_contains (string, optional).
  - reason (array, optional): "malware", "maliciousUrl" or "onDemand".
  - message_id, size_mb_greater_than, size_mb_lower_than, product_type, has_any_attachment (optional).
  - sort (array, optional): Fields from, quarantinedAt, forRecipient, reason.
  - page (number, optional), page_size (number, optional).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        ...sharedSearchFields,
        reason: z.array(z.enum(["malware", "maliciousUrl", "onDemand"])).optional().describe("Reasons"),
        page: z.number().int().min(1).optional().default(1).describe("Page number (default 1)"),
      },
      annotations: READ,
    },
    withErrorHandling(async ({ begin_date, end_date, sort, page, page_size, tenant_id, ...f }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { beginDate: begin_date, endDate: end_date, page, pageSize: page_size };
      const filter = searchFilter(f);
      if (filter) body.filter = filter;
      if (sort) body.sort = sort;
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/email/v1/post-delivery-quarantine/messages/search",
        { method: "POST", body }
      );
      return jsonResult(data);
    })
  );

  // --- Preview Post-Delivery Message ---
  server.registerTool(
    "sophos_preview_post_delivery_message",
    {
      title: "Preview Post-Delivery Quarantined Email",
      description: `Preview a message in post-delivery quarantine.

Args:
  - message_id (string): X-Sophos-Email-ID of the message.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { message_id: messageIdSchema, tenant_id: tenantIdSchema },
      annotations: READ,
    },
    withErrorHandling(async ({ message_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      return jsonResult(
        await client.tenantRequest<Record<string, unknown>>(
          tenantId,
          `/email/v1/post-delivery-quarantine/messages/${message_id}/preview`
        )
      );
    })
  );

  // --- Get Post-Delivery Attachments ---
  server.registerTool(
    "sophos_get_post_delivery_attachments",
    {
      title: "Get Post-Delivery Quarantine Attachments",
      description: `List the attachments of a message in post-delivery quarantine.

Args:
  - message_id (string): X-Sophos-Email-ID of the message.
  - page (number, optional), page_size (number, optional).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        message_id: messageIdSchema,
        page: z.number().int().min(1).optional().default(1).describe("Page number (default 1)"),
        page_size: pageSizeSchema,
        tenant_id: tenantIdSchema,
      },
      annotations: READ,
    },
    withErrorHandling(async ({ message_id, page, page_size, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      return jsonResult(
        await client.tenantRequest<Record<string, unknown>>(
          tenantId,
          `/email/v1/post-delivery-quarantine/messages/${message_id}/attachments`,
          { params: { page: String(page), pageSize: String(page_size) } }
        )
      );
    })
  );

  // --- Release Post-Delivery Message ---
  server.registerTool(
    "sophos_release_post_delivery_message",
    {
      title: "Release Post-Delivery Quarantined Email",
      description: `Queue messages in post-delivery quarantine for release (up to 50 per call).

Args:
  - message_ids (array): X-Sophos-Email-ID values.
  - for_recipients (array, optional): Release only to these recipients.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { message_ids: messageIdsSchema, for_recipients: recipientsSchema, tenant_id: tenantIdSchema },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    withErrorHandling(async ({ message_ids, for_recipients, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const items = message_ids.map((id) => ({ id, ...(for_recipients ? { forRecipients: for_recipients } : {}) }));
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/email/v1/post-delivery-quarantine/messages/release",
        { method: "POST", body: { items } }
      );
      return jsonResult({ status: "release_queued", result: data });
    })
  );

  // --- Delete Post-Delivery Message ---
  server.registerTool(
    "sophos_delete_post_delivery_message",
    {
      title: "Delete Post-Delivery Quarantined Email",
      description: `Delete messages from post-delivery quarantine (up to 50 per call).

Args:
  - message_ids (array): X-Sophos-Email-ID values.
  - for_recipients (array, optional): Delete only for these recipients.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { message_ids: messageIdsSchema, for_recipients: recipientsSchema, tenant_id: tenantIdSchema },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ message_ids, for_recipients, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const items = message_ids.map((id) => ({ id, ...(for_recipients ? { forRecipients: for_recipients } : {}) }));
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/email/v1/post-delivery-quarantine/messages/delete",
        { method: "POST", body: { items } }
      );
      return jsonResult({ status: "deleted", result: data });
    })
  );

  // --- Download Post-Delivery Attachment ---
  server.registerTool(
    "sophos_download_post_delivery_attachment",
    {
      title: "Download Post-Delivery Quarantine Attachment",
      description: `Get a download link for attachments of a message in post-delivery quarantine.

Starts a download job and checks its status for up to about 12 seconds. The
result has the job's url and the ZIP password when ready.

Args:
  - message_id (string): X-Sophos-Email-ID of the message.
  - attachments (array, optional): Attachment names; all when omitted.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        message_id: messageIdSchema,
        attachments: z.array(z.string()).optional().describe("Attachment names; all when omitted"),
        tenant_id: tenantIdSchema,
      },
      annotations: READ,
    },
    withErrorHandling(async ({ message_id, attachments, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      return jsonResult(await downloadAttachments(client, tenantId, "post-delivery-quarantine", message_id, attachments));
    })
  );

  // =========================================================================
  // Message Actions (2 tools)
  // =========================================================================

  // --- Clawback Message ---
  server.registerTool(
    "sophos_clawback_message",
    {
      title: "Clawback Delivered Email",
      description: `Claw back a delivered message from recipients' mailboxes.

Check progress with sophos_get_clawback_status.

Args:
  - message_id (string): X-Sophos-Email-ID of the message.
  - recipients (array, optional): Up to 500 recipient addresses; all recipients when omitted.
  - reason (string, optional): "malware", "phishing", "spam" or "unwanted".
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        message_id: z.string().describe("Message ID (the X-Sophos-Email-ID header value)"),
        recipients: z.array(z.string().email()).max(500).optional().describe("Recipients; all when omitted"),
        reason: z.enum(["malware", "phishing", "spam", "unwanted"]).optional().describe("Clawback reason"),
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    withErrorHandling(async ({ message_id, recipients, reason, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = {};
      if (recipients) body.recipients = recipients;
      if (reason) body.reason = reason;
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `/email/v1/messages/${message_id}/clawback`, {
        method: "POST",
        body,
      });
      return jsonResult({ status: "clawback_requested", result: data });
    })
  );

  // --- Get Clawback Status ---
  server.registerTool(
    "sophos_get_clawback_status",
    {
      title: "Get Clawback Action Status",
      description: `Get the per-recipient status of a message, for example after a clawback.

Args:
  - message_id (string): X-Sophos-Email-ID of the message that was clawed back.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        message_id: z.string().describe("Message ID (the X-Sophos-Email-ID header value)"),
        tenant_id: tenantIdSchema,
      },
      annotations: READ,
    },
    withErrorHandling(async ({ message_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      return jsonResult(
        await client.tenantRequest<Record<string, unknown>>(tenantId, `/email/v1/messages/${message_id}/status`)
      );
    })
  );

  // =========================================================================
  // Mailboxes (12 tools)
  // =========================================================================

  // --- List Mailboxes ---
  server.registerTool(
    "sophos_list_mailboxes",
    {
      title: "List Sophos Email Mailboxes",
      description: `List Sophos Email mailboxes, optionally filtered.

Results page by key: pass the previous result's pages.nextKey as page_from_key.

Args:
  - name, name_starts_with, email, email_starts_with (string, optional).
  - type (string, optional): "user", "distributionList", "publicFolder" or "sharedMailbox".
  - alias (string, optional): The mailbox with this alias.
  - delegate (string, optional): Mailboxes delegated to this address.
  - page_size (number, optional), page_from_key (string, optional).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        name: z.string().optional().describe("Exact mailbox name"),
        name_starts_with: z.string().optional().describe("Name starts with"),
        email: z.string().email().optional().describe("Exact email address"),
        email_starts_with: z.string().optional().describe("Email address starts with"),
        type: mailboxTypeSchema.optional().describe("Mailbox type"),
        alias: z.string().email().optional().describe("Mailbox with this alias"),
        delegate: z.string().email().optional().describe("Mailboxes delegated to this address"),
        page_size: pageSizeSchema,
        page_from_key: z.string().optional().describe("pages.nextKey from the previous page"),
        tenant_id: tenantIdSchema,
      },
      annotations: READ,
    },
    withErrorHandling(async (a) => {
      const tenantId = tenantResolver.resolveTenantId(a.tenant_id);
      const params: Record<string, string> = { pageSize: String(a.page_size) };
      if (a.name) params.name = a.name;
      if (a.name_starts_with) params.nameStartsWith = a.name_starts_with;
      if (a.email) params.email = a.email;
      if (a.email_starts_with) params.emailStartsWith = a.email_starts_with;
      if (a.type) params.type = a.type;
      if (a.alias) params.alias = a.alias;
      if (a.delegate) params.delegate = a.delegate;
      if (a.page_from_key) params.pageFromKey = a.page_from_key;
      return jsonResult(await client.tenantRequest<Record<string, unknown>>(tenantId, "/email/v1/mailboxes", { params }));
    })
  );

  // --- Create Mailbox ---
  server.registerTool(
    "sophos_create_mailbox",
    {
      title: "Create Sophos Email Mailbox",
      description: `Add a mailbox to Sophos Email. The address must be in one of the tenant's email domains.

Args:
  - email (string): Email address.
  - name (string): Display name.
  - type (string): "user", "distributionList", "publicFolder" or "sharedMailbox".
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        email: z.string().email().max(320).describe("Email address"),
        name: z.string().max(256).describe("Display name"),
        type: mailboxTypeSchema.describe("Mailbox type"),
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    withErrorHandling(async ({ email, name, type, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, "/email/v1/mailboxes", {
        method: "POST",
        body: { type, email, name },
      });
      return jsonResult({ status: "created", mailbox: data });
    })
  );

  // --- Bulk Create Mailboxes ---
  server.registerTool(
    "sophos_bulk_create_mailboxes",
    {
      title: "Bulk Create Sophos Email Mailboxes",
      description: `Add up to 10 mailboxes in one request.

Args:
  - mailboxes (array): Each {email, name, type}.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        mailboxes: z
          .array(
            z.object({
              email: z.string().email().max(320).describe("Email address"),
              name: z.string().max(256).describe("Display name"),
              type: mailboxTypeSchema.describe("Mailbox type"),
            })
          )
          .min(1)
          .max(10)
          .describe("Mailboxes to add"),
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    withErrorHandling(async ({ mailboxes, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, "/email/v1/mailboxes/bulk", {
        method: "POST",
        body: { items: mailboxes.map((m) => ({ type: m.type, email: m.email, name: m.name })) },
      });
      return jsonResult({ status: "submitted", result: data });
    })
  );

  // --- Get Mailbox ---
  server.registerTool(
    "sophos_get_mailbox",
    {
      title: "Get Sophos Email Mailbox Detail",
      description: `Get a mailbox, including its aliases, delegates and policies.

Args:
  - mailbox_id (string): Mailbox ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { mailbox_id: mailboxIdSchema, tenant_id: tenantIdSchema },
      annotations: READ,
    },
    withErrorHandling(async ({ mailbox_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      return jsonResult(await client.tenantRequest<Record<string, unknown>>(tenantId, `/email/v1/mailboxes/${mailbox_id}`));
    })
  );

  // --- Update Mailbox ---
  server.registerTool(
    "sophos_update_mailbox",
    {
      title: "Update Sophos Email Mailbox",
      description: `Rename a mailbox. The name is the only field the API changes.

Args:
  - mailbox_id (string): Mailbox ID.
  - name (string): New display name.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        mailbox_id: mailboxIdSchema,
        name: z.string().max(256).describe("New display name"),
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ mailbox_id, name, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `/email/v1/mailboxes/${mailbox_id}`, {
        method: "PATCH",
        body: { name },
      });
      return jsonResult({ status: "updated", mailbox: data });
    })
  );

  // --- Delete Mailbox ---
  server.registerTool(
    "sophos_delete_mailbox",
    {
      title: "Delete Sophos Email Mailbox",
      description: `Delete a mailbox.

Args:
  - mailbox_id (string): Mailbox ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { mailbox_id: mailboxIdSchema, tenant_id: tenantIdSchema },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ mailbox_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(tenantId, `/email/v1/mailboxes/${mailbox_id}`, { method: "DELETE" });
      return jsonResult({ status: "deleted", mailbox_id });
    })
  );

  // --- Aliases and delegates: read from the mailbox, changed with add/remove lists ---
  const listField = (field: "aliases" | "delegates") =>
    withErrorHandling(async ({ mailbox_id, tenant_id }: { mailbox_id: string; tenant_id?: string }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const mailbox = await client.tenantRequest<Record<string, unknown>>(tenantId, `/email/v1/mailboxes/${mailbox_id}`);
      const items = Array.isArray(mailbox[field]) ? (mailbox[field] as unknown[]) : [];
      return jsonResult({ mailbox_id, email: mailbox.email ?? null, [field]: items, total: items.length });
    });
  const change = (field: "aliases" | "delegates", op: "add" | "remove") =>
    withErrorHandling(async ({ mailbox_id, addresses, tenant_id }: { mailbox_id: string; addresses: string[]; tenant_id?: string }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `/email/v1/mailboxes/${mailbox_id}/${field}`, {
        method: "POST",
        body: { [op]: addresses },
      });
      return jsonResult({ status: op === "add" ? "added" : "removed", mailbox_id, [field]: addresses, result: data });
    });

  // --- List Mailbox Aliases ---
  server.registerTool(
    "sophos_list_mailbox_aliases",
    {
      title: "List Mailbox Aliases",
      description: `List a mailbox's aliases (read from the mailbox record).

Args:
  - mailbox_id (string): Mailbox ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { mailbox_id: mailboxIdSchema, tenant_id: tenantIdSchema },
      annotations: READ,
    },
    listField("aliases")
  );

  // --- Add Mailbox Alias ---
  server.registerTool(
    "sophos_add_mailbox_alias",
    {
      title: "Add Mailbox Alias",
      description: `Add alias addresses to a mailbox (up to 100 per call).

Args:
  - mailbox_id (string): Mailbox ID.
  - addresses (array): Alias email addresses to add.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        mailbox_id: mailboxIdSchema,
        addresses: z.array(z.string().email()).min(1).max(100).describe("Alias addresses to add"),
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    change("aliases", "add")
  );

  // --- Delete Mailbox Alias ---
  server.registerTool(
    "sophos_delete_mailbox_alias",
    {
      title: "Delete Mailbox Alias",
      description: `Remove alias addresses from a mailbox (up to 100 per call).

Args:
  - mailbox_id (string): Mailbox ID.
  - addresses (array): Alias email addresses to remove.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        mailbox_id: mailboxIdSchema,
        addresses: z.array(z.string().email()).min(1).max(100).describe("Alias addresses to remove"),
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    change("aliases", "remove")
  );

  // --- List Mailbox Delegates ---
  server.registerTool(
    "sophos_list_mailbox_delegates",
    {
      title: "List Mailbox Delegates",
      description: `List a mailbox's delegates (read from the mailbox record).

Args:
  - mailbox_id (string): Mailbox ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { mailbox_id: mailboxIdSchema, tenant_id: tenantIdSchema },
      annotations: READ,
    },
    listField("delegates")
  );

  // --- Add Mailbox Delegate ---
  server.registerTool(
    "sophos_add_mailbox_delegate",
    {
      title: "Add Mailbox Delegate",
      description: `Give other mailboxes delegate access to a mailbox (up to 50 per call).

Args:
  - mailbox_id (string): Mailbox ID.
  - addresses (array): Email addresses of the delegates to add.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        mailbox_id: mailboxIdSchema,
        addresses: z.array(z.string().email()).min(1).max(50).describe("Delegate addresses to add"),
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    change("delegates", "add")
  );

  // --- Delete Mailbox Delegate ---
  server.registerTool(
    "sophos_delete_mailbox_delegate",
    {
      title: "Remove Mailbox Delegate",
      description: `Remove delegates from a mailbox (up to 50 per call).

Args:
  - mailbox_id (string): Mailbox ID.
  - addresses (array): Email addresses of the delegates to remove.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        mailbox_id: mailboxIdSchema,
        addresses: z.array(z.string().email()).min(1).max(50).describe("Delegate addresses to remove"),
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    change("delegates", "remove")
  );
}
