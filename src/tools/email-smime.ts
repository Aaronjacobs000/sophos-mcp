/**
 * Tools: sophos_get_smime_config, sophos_create_smime_config,
 *        sophos_update_smime_config, sophos_reset_smime_config,
 *        sophos_get_smime_internal_ca, sophos_create_smime_internal_ca,
 *        sophos_upload_smime_internal_ca, sophos_download_smime_internal_ca,
 *        sophos_list_smime_internal_users, sophos_create_smime_internal_user_cert,
 *        sophos_upload_smime_internal_user_cert, sophos_download_smime_internal_user_cert,
 *        sophos_delete_smime_internal_user_cert,
 *        sophos_list_smime_external_users, sophos_upload_smime_external_user_cert,
 *        sophos_download_smime_external_user_cert, sophos_delete_smime_external_user_cert,
 *        sophos_list_smime_external_cas, sophos_upload_smime_external_ca,
 *        sophos_download_smime_external_ca, sophos_delete_smime_external_ca
 * Interact with the S/MIME operations of the Sophos Email API /email/v1/smime
 * (email-v1 1.4.0, released 01/10/2026).
 *
 * Certificates are identified by their SHA-256 fingerprint. Private keys are
 * never returned; downloads give the PEM public certificate (with its chain
 * when one was uploaded). Errors carry their reason in errorDetails, which
 * the REST client adds to the message.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";

const tenantIdSchema = z
  .string()
  .uuid()
  .optional()
  .describe("Tenant ID. Required for partner/org callers.");

const fingerprintSchema = z
  .string()
  .regex(/^[a-fA-F0-9]{64}$/, "64 hexadecimal characters")
  .describe("SHA-256 certificate fingerprint (64 hex characters, any case)");
const dateSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "YYYY-MM-DD");
const emailSchema = z.string().email().min(3).max(255);
const pemSchema = z
  .string()
  .min(300)
  .max(32000)
  .describe("PEM certificate, including the BEGIN and END CERTIFICATE lines");
const pkcs12Schema = z
  .string()
  .min(1200)
  .max(24000)
  .describe("PKCS#12 certificate and private key bundle, Base64 encoded");
const pkcs12PasswordSchema = z.string().min(3).max(50).describe("Password that decrypts the PKCS#12 bundle");
const certExpiryDateSchema = dateSchema
  .optional()
  .describe("Certificate expiry date, YYYY-MM-DD, from tomorrow up to 20 years ahead. Default 20 years");
const certValidityPeriodSchema = z
  .number()
  .int()
  .min(1)
  .max(20)
  .optional()
  .describe("Validity in years from today (1 to 20). Default 20");

const READ = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };
const ADD = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true };
const REMOVE = { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true };

const BASE = "/email/v1/smime";

/** The certificate filters and key paging the three certificate lists share. */
const certFilterFields = {
  cert_valid_before: dateSchema.optional().describe("Certificates that activate on or before this date (YYYY-MM-DD)"),
  cert_valid_after: dateSchema.optional().describe("Certificates that activate on or after this date (YYYY-MM-DD)"),
  cert_expiry_before: dateSchema.optional().describe("Certificates that expire on or before this date (YYYY-MM-DD)"),
  cert_expiry_after: dateSchema.optional().describe("Certificates that expire on or after this date (YYYY-MM-DD)"),
  cert_fingerprint: fingerprintSchema.optional(),
  issuer_cn: z.string().min(3).max(255).optional().describe("Issuer common name contains this text"),
  page_from_key: z.string().optional().describe("pages.nextKey from the previous page"),
  page_size: z.number().int().min(1).max(200).optional().default(50).describe("Results per page (1-200, default 50)"),
  tenant_id: tenantIdSchema,
};

const CERT_FILTER_ARGS = `  - cert_valid_before, cert_valid_after, cert_expiry_before, cert_expiry_after
    (string, optional): Date filters, YYYY-MM-DD from 2000-01-01. An After
    value must not be later than its Before value.
  - cert_fingerprint (string, optional): One certificate by SHA-256 fingerprint.
  - issuer_cn (string, optional): Issuer common name contains this text.
  - page_size (number, optional): 1 to 200, default 50.
  - page_from_key (string, optional): pages.nextKey from the previous page.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`;

/** Query string for a certificate list: only the filters that were passed. */
function certListParams(a: Record<string, unknown>): Record<string, string> {
  const map: Record<string, string> = {
    user_name: "userName",
    email: "email",
    email_starts_with: "emailStartsWith",
    common_name: "commonName",
    cert_valid_before: "certValidBefore",
    cert_valid_after: "certValidAfter",
    cert_expiry_before: "certExpiryBefore",
    cert_expiry_after: "certExpiryAfter",
    cert_fingerprint: "certFingerprint",
    issuer_cn: "issuerCN",
    page_from_key: "pageFromKey",
  };
  const params: Record<string, string> = { pageSize: String(a.page_size ?? 50) };
  for (const [arg, param] of Object.entries(map)) {
    const value = a[arg];
    if (value !== undefined && value !== "") params[param] = String(value);
  }
  return params;
}

const isNotFound = (error: unknown) => error instanceof Error && /^Sophos API error 404:/.test(error.message);

export function registerEmailSmimeTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // =========================================================================
  // Configuration (4 tools)
  // =========================================================================

  // --- Get S/MIME Configuration ---
  server.registerTool(
    "sophos_get_smime_config",
    {
      title: "Get S/MIME Configuration",
      description: `Get a tenant's S/MIME configuration: whether S/MIME is on, whether certificates are extracted from incoming mail, the certificate expiry notification addresses, and the deleteToken that sophos_reset_smime_config needs.

A tenant with no configuration returns configured false rather than an error.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { tenant_id: tenantIdSchema },
      annotations: READ,
    },
    withErrorHandling(async ({ tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      try {
        const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/config`);
        return jsonResult({ configured: true, ...data });
      } catch (error) {
        if (!isNotFound(error)) throw error;
        return jsonResult({
          configured: false,
          message:
            "No S/MIME configuration exists for this tenant. Creating the internal CA (sophos_create_smime_internal_ca or sophos_upload_smime_internal_ca) also creates a disabled configuration; sophos_create_smime_config creates one on its own.",
        });
      }
    })
  );

  // --- Create S/MIME Configuration ---
  server.registerTool(
    "sophos_create_smime_config",
    {
      title: "Create S/MIME Configuration",
      description: `Create a tenant's S/MIME configuration. Only works once per tenant: after a configuration exists (from this call or from creating the internal CA), use sophos_update_smime_config.

smime_enabled true needs the internal CA to exist already, so the usual order is: create or upload the internal CA (which creates a disabled configuration), then turn S/MIME on with sophos_update_smime_config.

Args:
  - smime_enabled (boolean): Turn S/MIME on (needs the internal CA) or leave it off.
  - extract_certificate (boolean, optional): Extract certificates from incoming messages. Sophos defaults it to false.
  - cert_expiry_notification_emails (string[], optional): Up to 5 tenant mailboxes notified before certificates expire.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        smime_enabled: z.boolean().describe("Turn S/MIME on (needs the internal CA) or leave it off"),
        extract_certificate: z.boolean().optional().describe("Extract certificates from incoming messages"),
        cert_expiry_notification_emails: z
          .array(emailSchema)
          .max(5)
          .optional()
          .describe("Up to 5 tenant mailboxes notified before certificates expire"),
        tenant_id: tenantIdSchema,
      },
      annotations: ADD,
    },
    withErrorHandling(async ({ smime_enabled, extract_certificate, cert_expiry_notification_emails, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { smimeEnabled: smime_enabled };
      if (extract_certificate !== undefined) body.extractCertificate = extract_certificate;
      if (cert_expiry_notification_emails !== undefined) {
        body.certExpiryNotificationEmailAddresses = cert_expiry_notification_emails;
      }
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/config`, {
        method: "POST",
        body,
      });
      return jsonResult({ status: "created", config: data });
    })
  );

  // --- Update S/MIME Configuration ---
  server.registerTool(
    "sophos_update_smime_config",
    {
      title: "Update S/MIME Configuration",
      description: `Turn S/MIME on or off, or change its settings. Only the fields you pass change.

Turning S/MIME on needs the internal CA to exist (sophos_get_smime_internal_ca). Turning it off stops S/MIME signing and encryption for the tenant. Every notification address must be a mailbox on the tenant; pass an empty list to clear them all.

Args:
  - smime_enabled (boolean, optional): Turn S/MIME on or off.
  - extract_certificate (boolean, optional): Extract certificates from incoming messages.
  - cert_expiry_notification_emails (string[], optional): Up to 5 tenant mailboxes; [] clears them.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        smime_enabled: z.boolean().optional().describe("Turn S/MIME on or off"),
        extract_certificate: z.boolean().optional().describe("Extract certificates from incoming messages"),
        cert_expiry_notification_emails: z
          .array(emailSchema)
          .max(5)
          .optional()
          .describe("Up to 5 tenant mailboxes notified before certificates expire; [] clears them"),
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ smime_enabled, extract_certificate, cert_expiry_notification_emails, tenant_id }) => {
      const body: Record<string, unknown> = {};
      if (smime_enabled !== undefined) body.smimeEnabled = smime_enabled;
      if (extract_certificate !== undefined) body.extractCertificate = extract_certificate;
      if (cert_expiry_notification_emails !== undefined) {
        body.certExpiryNotificationEmailAddresses = cert_expiry_notification_emails;
      }
      if (Object.keys(body).length === 0) {
        throw new Error("Nothing to update: pass smime_enabled, extract_certificate or cert_expiry_notification_emails.");
      }
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/config`, {
        method: "PATCH",
        body,
      });
      return jsonResult({ status: "updated", config: data });
    })
  );

  // --- Reset S/MIME Configuration ---
  server.registerTool(
    "sophos_reset_smime_config",
    {
      title: "Reset S/MIME Configuration",
      description: `Reset S/MIME for a tenant: permanently delete every S/MIME certificate and private key (internal CA, internal users, external users and trusted external CAs) and turn S/MIME off.

WARNING: irreversible. The private keys cannot be recovered and every internal user needs a new certificate afterwards. Sophos guards this call with the configuration's deleteToken: read it with sophos_get_smime_config and pass it here.

The configuration record itself stays, with S/MIME off (measured 29/10/2026); no call removes it.

Args:
  - delete_token (string): The 8 character deleteToken from sophos_get_smime_config.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        delete_token: z.string().length(8).describe("deleteToken from sophos_get_smime_config"),
        tenant_id: tenantIdSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    withErrorHandling(async ({ delete_token, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `${BASE}/config/${encodeURIComponent(delete_token)}`,
        { method: "DELETE" }
      );
      return jsonResult({ status: data.deleted === true ? "reset" : "not_confirmed", result: data });
    })
  );

  // =========================================================================
  // Internal CA (4 tools)
  // =========================================================================

  // --- Get Internal CA ---
  server.registerTool(
    "sophos_get_smime_internal_ca",
    {
      title: "Get S/MIME Internal CA",
      description: `Get the tenant's internal CA certificate details (fingerprint, subject, issuer, validity, origin). The internal CA signs the certificates Sophos generates for internal users. A tenant has at most one.

A tenant with no internal CA returns exists false rather than an error.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { tenant_id: tenantIdSchema },
      annotations: READ,
    },
    withErrorHandling(async ({ tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      try {
        const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/ca/internal`);
        return jsonResult({ exists: true, ...data });
      } catch (error) {
        if (!isNotFound(error)) throw error;
        return jsonResult({
          exists: false,
          message:
            "This tenant has no S/MIME internal CA. Create one with sophos_create_smime_internal_ca or upload your own with sophos_upload_smime_internal_ca.",
        });
      }
    })
  );

  // --- Create Internal CA ---
  server.registerTool(
    "sophos_create_smime_internal_ca",
    {
      title: "Create S/MIME Internal CA",
      description: `Have Sophos generate the tenant's internal CA certificate (RSA 2048, SHA-512) from your organisation details. It signs the certificates Sophos generates for internal users.

A tenant can have only one internal CA (Sophos answers 409 if one exists). If the tenant has no S/MIME configuration, this also creates a disabled one; it does not turn S/MIME on.

Args:
  - organization_name (string): Organisation (O), 3 to 128 characters.
  - organization_unit (string, optional): Organisational unit (OU), 3 to 64 characters.
  - locality (string): Locality (L), 1 to 64 characters.
  - country (string): Two-letter ISO 3166-1 country code (C), upper case.
  - email (string): Contact email address for the CA.
  - cert_expiry_date (string, optional): YYYY-MM-DD, tomorrow to 20 years ahead.
  - cert_validity_period (number, optional): Years from today, 1 to 20. Default 20. With both, Sophos uses the shorter.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        organization_name: z.string().min(3).max(128).describe("Organisation (O)"),
        organization_unit: z.string().min(3).max(64).optional().describe("Organisational unit (OU)"),
        locality: z.string().min(1).max(64).describe("Locality (L)"),
        country: z.string().regex(/^[A-Z]{2}$/, "two upper-case letters").describe("ISO 3166-1 country code (C)"),
        email: emailSchema.describe("Contact email address"),
        cert_expiry_date: certExpiryDateSchema,
        cert_validity_period: certValidityPeriodSchema,
        tenant_id: tenantIdSchema,
      },
      annotations: ADD,
    },
    withErrorHandling(async (a) => {
      const tenantId = tenantResolver.resolveTenantId(a.tenant_id);
      const body: Record<string, unknown> = {
        organizationName: a.organization_name,
        locality: a.locality,
        country: a.country,
        email: a.email,
      };
      if (a.organization_unit !== undefined) body.organizationUnit = a.organization_unit;
      if (a.cert_expiry_date !== undefined) body.certExpiryDate = a.cert_expiry_date;
      if (a.cert_validity_period !== undefined) body.certValidityPeriod = a.cert_validity_period;
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/ca/internal`, {
        method: "POST",
        body,
      });
      return jsonResult({ status: "created", internal_ca: data });
    })
  );

  // --- Upload Internal CA ---
  server.registerTool(
    "sophos_upload_smime_internal_ca",
    {
      title: "Upload S/MIME Internal CA",
      description: `Upload your own CA as the tenant's internal CA: a Base64 PKCS#12 bundle holding the CA certificate and its private key (RSA, EC or DSA). The CA certificate comes first in the bundle; any chain certificates after it are added as trusted external CAs.

A tenant can have only one internal CA (Sophos answers 409 if one exists). If the tenant has no S/MIME configuration, this also creates a disabled one; it does not turn S/MIME on. The private key is never returned by any call.

Args:
  - pkcs12 (string): The PKCS#12 bundle, Base64 encoded (1200 to 24000 characters).
  - password (string): Password that decrypts the bundle.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { pkcs12: pkcs12Schema, password: pkcs12PasswordSchema, tenant_id: tenantIdSchema },
      annotations: ADD,
    },
    withErrorHandling(async ({ pkcs12, password, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/ca/internal/certificate`, {
        method: "POST",
        body: { password, pkcs12 },
      });
      return jsonResult({ status: "uploaded", internal_ca: data });
    })
  );

  // --- Download Internal CA ---
  server.registerTool(
    "sophos_download_smime_internal_ca",
    {
      title: "Download S/MIME Internal CA",
      description: `Download the tenant's internal CA certificate as PEM (public certificate only).

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { tenant_id: tenantIdSchema },
      annotations: READ,
    },
    withErrorHandling(async ({ tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const pem = await client.tenantRequest<string>(tenantId, `${BASE}/ca/internal/certificate`, {
        responseType: "text",
      });
      return jsonResult({ pem });
    })
  );

  // =========================================================================
  // Internal users (5 tools)
  // =========================================================================

  // --- List Internal Users ---
  server.registerTool(
    "sophos_list_smime_internal_users",
    {
      title: "List S/MIME Internal Users",
      description: `List or search the tenant's S/MIME internal users (its own mailboxes) and their certificates (up to 2 each). Text filters are case-insensitive.

Args:
  - user_name (string, optional): User name contains this text.
  - email (string, optional): Exact email address.
  - email_starts_with (string, optional): Email address prefix.
${CERT_FILTER_ARGS}`,
      inputSchema: {
        user_name: z.string().min(3).max(255).optional().describe("User name contains this text"),
        email: emailSchema.optional().describe("Exact email address"),
        email_starts_with: z.string().min(3).max(255).optional().describe("Email address prefix"),
        ...certFilterFields,
      },
      annotations: READ,
    },
    withErrorHandling(async (a) => {
      const tenantId = tenantResolver.resolveTenantId(a.tenant_id);
      return jsonResult(
        await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/users/internal`, {
          params: certListParams(a),
        })
      );
    })
  );

  // --- Create Internal User Certificate ---
  server.registerTool(
    "sophos_create_smime_internal_user_cert",
    {
      title: "Create S/MIME Internal User Certificate",
      description: `Have Sophos generate a certificate for one of the tenant's mailboxes, signed by the internal CA, and turn S/MIME on for that user.

Needs the internal CA (sophos_get_smime_internal_ca), and the address must be a mailbox on the tenant (sophos_list_mailboxes); otherwise Sophos answers 400. A user can hold at most 2 certificates (Sophos answers 422 beyond that), which lets you add a replacement before the old one expires.

Args:
  - email (string): The mailbox's email address.
  - cert_expiry_date (string, optional): YYYY-MM-DD, tomorrow to 20 years ahead.
  - cert_validity_period (number, optional): Years from today, 1 to 20. Default 20. With both, Sophos uses the shorter.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        email: emailSchema.describe("Mailbox email address"),
        cert_expiry_date: certExpiryDateSchema,
        cert_validity_period: certValidityPeriodSchema,
        tenant_id: tenantIdSchema,
      },
      annotations: ADD,
    },
    withErrorHandling(async ({ email, cert_expiry_date, cert_validity_period, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { email };
      if (cert_expiry_date !== undefined) body.certExpiryDate = cert_expiry_date;
      if (cert_validity_period !== undefined) body.certValidityPeriod = cert_validity_period;
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/users/internal`, {
        method: "POST",
        body,
      });
      return jsonResult({ status: "created", user: data });
    })
  );

  // --- Upload Internal User Certificate ---
  server.registerTool(
    "sophos_upload_smime_internal_user_cert",
    {
      title: "Upload S/MIME Internal User Certificate",
      description: `Upload your own certificate for one of the tenant's mailboxes: a Base64 PKCS#12 bundle holding the user's certificate and private key, and turn S/MIME on for that user. The user's (leaf) certificate comes first; any CA certificates in the bundle are added as trusted external CAs.

The address must be a mailbox on the tenant (400 otherwise). The same certificate already on file for that email gets 409; a user can hold at most 2 certificates (422). A DSA or EC key can only sign and verify, not encrypt, so Sophos needs confirm_signing_only_cert true for one.

Args:
  - email (string): The mailbox's email address.
  - pkcs12 (string): The PKCS#12 bundle, Base64 encoded (1200 to 24000 characters).
  - password (string): Password that decrypts the bundle.
  - confirm_signing_only_cert (boolean, optional): true to accept a signing-only (DSA or EC) certificate. Default false.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        email: emailSchema.describe("Mailbox email address"),
        pkcs12: pkcs12Schema,
        password: pkcs12PasswordSchema,
        confirm_signing_only_cert: z
          .boolean()
          .optional()
          .describe("true to accept a signing-only (DSA or EC) certificate"),
        tenant_id: tenantIdSchema,
      },
      annotations: ADD,
    },
    withErrorHandling(async ({ email, pkcs12, password, confirm_signing_only_cert, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { email, password, pkcs12 };
      if (confirm_signing_only_cert !== undefined) body.confirmSigningOnlyCert = confirm_signing_only_cert;
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/users/internal/certificate`, {
        method: "POST",
        body,
      });
      return jsonResult({ status: "uploaded", result: data });
    })
  );

  // --- Download Internal User Certificate ---
  server.registerTool(
    "sophos_download_smime_internal_user_cert",
    {
      title: "Download S/MIME Internal User Certificate",
      description: `Download an internal user's certificate as PEM by fingerprint. A certificate uploaded with its CA chain comes back with the chain. Private keys are never returned.

Args:
  - fingerprint (string): SHA-256 fingerprint from sophos_list_smime_internal_users.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { fingerprint: fingerprintSchema, tenant_id: tenantIdSchema },
      annotations: READ,
    },
    withErrorHandling(async ({ fingerprint, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const pem = await client.tenantRequest<string>(tenantId, `${BASE}/users/internal/certificate/${fingerprint}`, {
        responseType: "text",
      });
      return jsonResult({ fingerprint, pem });
    })
  );

  // --- Delete Internal User Certificate ---
  server.registerTool(
    "sophos_delete_smime_internal_user_cert",
    {
      title: "Delete S/MIME Internal User Certificate",
      description: `Delete one certificate (and its private key) from an internal user. If it was the user's last certificate, the user leaves the S/MIME list. Irreversible.

Args:
  - email (string): The user's exact email address.
  - cert_fingerprint (string): SHA-256 fingerprint of the certificate to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        email: emailSchema.describe("The user's exact email address"),
        cert_fingerprint: fingerprintSchema,
        tenant_id: tenantIdSchema,
      },
      annotations: REMOVE,
    },
    withErrorHandling(async ({ email, cert_fingerprint, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/users/internal`, {
        method: "DELETE",
        params: { email, certFingerprint: cert_fingerprint },
      });
      return jsonResult({ status: data.deleted === true ? "deleted" : "not_confirmed", email, cert_fingerprint, result: data });
    })
  );

  // =========================================================================
  // External users (4 tools)
  // =========================================================================

  // --- List External Users ---
  server.registerTool(
    "sophos_list_smime_external_users",
    {
      title: "List S/MIME External Users",
      description: `List or search the external users (people outside the organisation) whose certificates the tenant holds, with their certificates. Text filters are case-insensitive.

Args:
  - email (string, optional): Exact email address.
  - email_starts_with (string, optional): Email address prefix.
${CERT_FILTER_ARGS}`,
      inputSchema: {
        email: emailSchema.optional().describe("Exact email address"),
        email_starts_with: z.string().min(3).max(255).optional().describe("Email address prefix"),
        ...certFilterFields,
      },
      annotations: READ,
    },
    withErrorHandling(async (a) => {
      const tenantId = tenantResolver.resolveTenantId(a.tenant_id);
      return jsonResult(
        await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/users/external`, {
          params: certListParams(a),
        })
      );
    })
  );

  // --- Upload External User Certificate ---
  server.registerTool(
    "sophos_upload_smime_external_user_cert",
    {
      title: "Upload S/MIME External User Certificate",
      description: `Upload the public certificate of someone outside the organisation, so the tenant can send them encrypted mail and verify their signed mail. The email address is read from the certificate.

The same certificate already on file gets 409; a user can hold at most 2 certificates (422). A DSA or EC key can only verify, not encrypt, so Sophos needs confirm_verification_only_cert true for one.

Args:
  - certificate (string): PEM certificate including the BEGIN and END lines (300 to 32000 characters).
  - confirm_verification_only_cert (boolean, optional): true to accept a verification-only (DSA or EC) certificate. Default false.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        certificate: pemSchema,
        confirm_verification_only_cert: z
          .boolean()
          .optional()
          .describe("true to accept a verification-only (DSA or EC) certificate"),
        tenant_id: tenantIdSchema,
      },
      annotations: ADD,
    },
    withErrorHandling(async ({ certificate, confirm_verification_only_cert, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { certificate };
      if (confirm_verification_only_cert !== undefined) {
        body.confirmVerificationOnlyCert = confirm_verification_only_cert;
      }
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/users/external/certificate`, {
        method: "POST",
        body,
      });
      return jsonResult({ status: "uploaded", result: data });
    })
  );

  // --- Download External User Certificate ---
  server.registerTool(
    "sophos_download_smime_external_user_cert",
    {
      title: "Download S/MIME External User Certificate",
      description: `Download an external user's certificate as PEM by fingerprint.

Args:
  - fingerprint (string): SHA-256 fingerprint from sophos_list_smime_external_users.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { fingerprint: fingerprintSchema, tenant_id: tenantIdSchema },
      annotations: READ,
    },
    withErrorHandling(async ({ fingerprint, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const pem = await client.tenantRequest<string>(tenantId, `${BASE}/users/external/certificate/${fingerprint}`, {
        responseType: "text",
      });
      return jsonResult({ fingerprint, pem });
    })
  );

  // --- Delete External User Certificate ---
  server.registerTool(
    "sophos_delete_smime_external_user_cert",
    {
      title: "Delete S/MIME External User Certificate",
      description: `Delete one certificate from an external user. If it was the user's last certificate, the user leaves the S/MIME list.

Args:
  - email (string): The user's exact email address.
  - cert_fingerprint (string): SHA-256 fingerprint of the certificate to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        email: emailSchema.describe("The user's exact email address"),
        cert_fingerprint: fingerprintSchema,
        tenant_id: tenantIdSchema,
      },
      annotations: REMOVE,
    },
    withErrorHandling(async ({ email, cert_fingerprint, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/users/external`, {
        method: "DELETE",
        params: { email, certFingerprint: cert_fingerprint },
      });
      return jsonResult({ status: data.deleted === true ? "deleted" : "not_confirmed", email, cert_fingerprint, result: data });
    })
  );

  // =========================================================================
  // Trusted external CAs (4 tools)
  // =========================================================================

  // --- List External CAs ---
  server.registerTool(
    "sophos_list_smime_external_cas",
    {
      title: "List S/MIME Trusted CAs",
      description: `List or search the CA certificates the tenant trusts to verify signed mail from other organisations (up to 100). Text filters are case-insensitive.

To act on a group (for example every CA from one issuer), list with a filter to collect the fingerprints, then call the delete or download tool once per fingerprint.

Args:
  - common_name (string, optional): Certificate common name contains this text.
${CERT_FILTER_ARGS}`,
      inputSchema: {
        common_name: z.string().min(3).max(255).optional().describe("Certificate common name contains this text"),
        ...certFilterFields,
      },
      annotations: READ,
    },
    withErrorHandling(async (a) => {
      const tenantId = tenantResolver.resolveTenantId(a.tenant_id);
      return jsonResult(
        await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/cas/external`, {
          params: certListParams(a),
        })
      );
    })
  );

  // --- Upload External CA ---
  server.registerTool(
    "sophos_upload_smime_external_ca",
    {
      title: "Upload S/MIME Trusted CA",
      description: `Trust a CA certificate, so mail signed by certificates it issued is verified automatically. The same certificate already on file gets 409.

Args:
  - certificate (string): PEM CA certificate including the BEGIN and END lines (300 to 32000 characters).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { certificate: pemSchema, tenant_id: tenantIdSchema },
      annotations: ADD,
    },
    withErrorHandling(async ({ certificate, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/cas/external/certificate`, {
        method: "POST",
        body: { certificate },
      });
      return jsonResult({ status: "uploaded", external_ca: data });
    })
  );

  // --- Download External CA ---
  server.registerTool(
    "sophos_download_smime_external_ca",
    {
      title: "Download S/MIME Trusted CA",
      description: `Download a trusted external CA certificate as PEM by fingerprint.

Args:
  - fingerprint (string): SHA-256 fingerprint from sophos_list_smime_external_cas.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { fingerprint: fingerprintSchema, tenant_id: tenantIdSchema },
      annotations: READ,
    },
    withErrorHandling(async ({ fingerprint, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const pem = await client.tenantRequest<string>(tenantId, `${BASE}/cas/external/certificate/${fingerprint}`, {
        responseType: "text",
      });
      return jsonResult({ fingerprint, pem });
    })
  );

  // --- Delete External CA ---
  server.registerTool(
    "sophos_delete_smime_external_ca",
    {
      title: "Delete S/MIME Trusted CA",
      description: `Stop trusting an external CA certificate. Mail signed under it is no longer verified automatically.

Args:
  - cert_fingerprint (string): SHA-256 fingerprint of the CA certificate.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { cert_fingerprint: fingerprintSchema, tenant_id: tenantIdSchema },
      annotations: REMOVE,
    },
    withErrorHandling(async ({ cert_fingerprint, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, `${BASE}/cas/external`, {
        method: "DELETE",
        params: { certFingerprint: cert_fingerprint },
      });
      return jsonResult({ status: data.deleted === true ? "deleted" : "not_confirmed", cert_fingerprint, result: data });
    })
  );
}
