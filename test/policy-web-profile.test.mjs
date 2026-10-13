/**
 * Web profile settings on the policy write tools, against the in-memory
 * policy API (fake-policy-api.mjs), which ignores web-profile-id unless
 * filter-by-web-profile.enabled is true in the same write and defaults a new
 * web control policy to web-profile.enabled true, as Sophos did on 13/10/2026.
 * No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { policyHarness as harness, P_WEB, P_USER, PROFILE } from "./fake-policy-api.mjs";

const ID = "endpoint.web-control.web-profile-id";
const FILTER = "endpoint.web-control.filter-by-web-profile.enabled";
const MODE = "endpoint.web-control.web-profile.enabled";

test("setting a profile on update also sends filter-by and web profiles mode, and reads them back", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_update_policy", { policy_id: P_WEB, settings: { [ID]: { value: PROFILE } } });
    assert.equal(isError, false, JSON.stringify(json));
    assert.deepEqual(h.writes()[0].body.settings, {
      [ID]: { value: PROFILE },
      [FILTER]: { value: true },
      [MODE]: { value: true },
    });
    const expected = { "web-profile-id": PROFILE, "filter-by-web-profile.enabled": true, "web-profile.enabled": true };
    assert.deepEqual(json.web_profile_sent, expected);
    assert.deepEqual(json.web_profile_stored, expected);
    assert.equal(json.web_profile_matches, true);
  } finally {
    await h.close();
  }
});

test("an explicit web-profile.enabled is kept, and filter-by false with a profile is refused", async () => {
  const h = await harness();
  try {
    const kept = await h.call("sophos_update_policy", { policy_id: P_WEB, settings: { [ID]: { value: PROFILE }, [MODE]: { value: false } } });
    assert.equal(kept.isError, false);
    assert.deepEqual(h.writes()[0].body.settings[MODE], { value: false });

    const refused = await h.call("sophos_update_policy", { policy_id: P_WEB, settings: { [ID]: { value: PROFILE }, [FILTER]: { value: false } } });
    assert.equal(refused.isError, true);
    assert.match(refused.text, /only sticks when .*filter-by-web-profile\.enabled is true/);
    assert.equal(h.writes().length, 1, "the refused call wrote nothing");
  } finally {
    await h.close();
  }
});

test("clearing the profile sends filter-by false, which Sophos needs; filter-by true with an empty ID is refused", async () => {
  const h = await harness();
  try {
    await h.call("sophos_update_policy", { policy_id: P_WEB, settings: { [ID]: { value: PROFILE } } });
    const cleared = await h.call("sophos_update_policy", { policy_id: P_WEB, settings: { [ID]: { value: "" } } });
    assert.equal(cleared.isError, false, cleared.text);
    assert.deepEqual(h.writes()[1].body.settings, { [ID]: { value: "" }, [FILTER]: { value: false } });
    assert.deepEqual(cleared.json.web_profile_stored, { "web-profile-id": "", "filter-by-web-profile.enabled": false });
    assert.equal(cleared.json.web_profile_matches, true);

    const refused = await h.call("sophos_update_policy", { policy_id: P_WEB, settings: { [ID]: { value: "" }, [FILTER]: { value: true } } });
    assert.equal(refused.isError, true);
    assert.match(refused.text, /Clearing .*needs .*false in the same write/);
  } finally {
    await h.close();
  }
});

test("the read-back catches a profile ID Sophos did not keep", async () => {
  const h = await harness({ tamper: (p) => ({ ...p, settings: { ...p.settings, [ID]: { value: "" } } }) });
  try {
    const { json } = await h.call("sophos_update_policy", { policy_id: P_WEB, settings: { [ID]: { value: PROFILE } } });
    assert.equal(json.web_profile_matches, false);
    assert.equal(json.web_profile_stored["web-profile-id"], "");
    assert.match(json.warning, /web profile settings differ/);
  } finally {
    await h.close();
  }
});

test("a new web control policy with no profile gets web-profile.enabled false explicitly (Sophos would default it to true)", async () => {
  const h = await harness();
  try {
    for (const type of ["web-control", "server-web-control"]) {
      const { isError, json } = await h.call("sophos_create_policy", { name: `ZZ ${type}`, type, enabled: false });
      assert.equal(isError, false);
      assert.deepEqual(h.writes().at(-1).body.settings, { [MODE]: { value: false } });
      assert.deepEqual(json.web_profile_stored, { "web-profile.enabled": false });
      assert.equal(json.web_profile_matches, true);
    }
  } finally {
    await h.close();
  }
});

test("a new web control policy with a profile gets web profiles mode and filter-by, and keeps legacy settings sent beside them", async () => {
  const h = await harness();
  try {
    const legacy = { "endpoint.web-control.tags.settings": { value: [] } };
    const { isError, json } = await h.call("sophos_create_policy", {
      name: "ZZ profile",
      type: "web-control",
      enabled: false,
      settings: { ...legacy, [ID]: { value: PROFILE } },
    });
    assert.equal(isError, false);
    assert.deepEqual(h.writes()[0].body.settings, { ...legacy, [ID]: { value: PROFILE }, [FILTER]: { value: true }, [MODE]: { value: true } });
    assert.equal(json.web_profile_matches, true);
    assert.equal(json.web_profile_stored["web-profile-id"], PROFILE);
  } finally {
    await h.close();
  }
});

test("an explicit web-profile.enabled on create is kept; other policy types get no web settings", async () => {
  const h = await harness();
  try {
    await h.call("sophos_create_policy", { name: "ZZ mode on", type: "web-control", settings: { [MODE]: { value: true } } });
    assert.deepEqual(h.writes()[0].body.settings, { [MODE]: { value: true } });
    await h.call("sophos_create_policy", { name: "ZZ tp", type: "threat-protection", settings: { "endpoint.malware.enabled": { value: true } } });
    assert.deepEqual(h.writes()[1].body.settings, { "endpoint.malware.enabled": { value: true } });
  } finally {
    await h.close();
  }
});

test("update without web profile settings sends settings untouched and reads nothing back for them", async () => {
  const h = await harness();
  try {
    const { json } = await h.call("sophos_update_policy", { policy_id: P_USER, settings: { "endpoint.web-control.tags.settings": { value: [] } } });
    assert.deepEqual(h.writes()[0].body.settings, { "endpoint.web-control.tags.settings": { value: [] } });
    assert.equal("web_profile_sent" in json, false);
    assert.equal(h.calls.length, 1);
  } finally {
    await h.close();
  }
});
