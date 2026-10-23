// Preloaded with --import by test/http-transport.test.mjs. Answers the Sophos
// token, whoami and REST calls, and the Fusion case file upload (the
// startCaseFileUpload mutation and the presigned PUT), in memory so the real
// entry point runs with no network. REST answers wait FAKE_SOPHOS_DELAY_MS so
// concurrent calls overlap.

const delayMs = Number(process.env.FAKE_SOPHOS_DELAY_MS ?? 0);
const json = (body) => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });

globalThis.fetch = async (input, init) => {
  const url = String(input);
  if (url === "https://api.taegis.sophos.com/graphql" && init?.body?.includes("startCaseFileUpload")) {
    const { input: upload } = JSON.parse(init.body).variables;
    const file = {
      id: "00000000-0000-4000-8000-00000000f001",
      caseId: upload.caseId,
      name: upload.name,
      size: upload.size,
      status: "UPLOADED",
      isEmbedded: upload.isEmbedded,
      createdAt: "2026-10-23T00:00:00Z",
      updatedAt: "2026-10-23T00:00:00Z",
      deletedAt: null,
      uploadedById: "fake-user",
      deletedById: null,
      metadata: { contentType: upload.contentType, contentMD5: null },
    };
    return json({ data: { startCaseFileUpload: { file, presignedUrl: "https://fake-upload.test/put" } } });
  }
  if (url === "https://fake-upload.test/put") {
    return new Response(null, { status: 200 });
  }
  if (url.startsWith("https://id.sophos.com/")) {
    return json({ access_token: "fake-token", expires_in: 3600, errorCode: "success" });
  }
  if (url.endsWith("/whoami/v1")) {
    return json({
      id: "00000000-0000-4000-8000-000000000001",
      idType: "tenant",
      apiHosts: { global: "https://api.central.sophos.com", dataRegion: "https://api-au01.central.sophos.com" },
    });
  }
  await new Promise((resolve) => setTimeout(resolve, delayMs));
  return json({ items: [], pages: {} });
};
