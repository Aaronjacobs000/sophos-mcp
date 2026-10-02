// Preloaded with --import by test/http-transport.test.mjs. Answers the Sophos
// token, whoami and REST calls in memory so the real entry point runs with no
// network. REST answers wait FAKE_SOPHOS_DELAY_MS so concurrent calls overlap.

const delayMs = Number(process.env.FAKE_SOPHOS_DELAY_MS ?? 0);
const json = (body) => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });

globalThis.fetch = async (input) => {
  const url = String(input);
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
