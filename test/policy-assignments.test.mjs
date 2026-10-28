/**
 * Handler-level tests for policy assignment (appliesTo) writes through the
 * real SophosClient and the registered schemas, against the in-memory policy
 * API in fake-policy-api.mjs: body shapes, the user/device and server/computer
 * refusals, the target lookups, add/remove merging, clone with assignment and
 * the read-back. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  policyHarness as harness,
  U1, U2, UG1, E1, ES1, EV1, G1, G2, G3, MISSING,
  P_USER, P_DEVICE, P_SERVER, P_EMPTY,
} from "./fake-policy-api.mjs";

test("create with users sends plain IDs, reads the policy back by ID and reports what is stored", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_create_policy", {
      name: "ZZ create users",
      type: "threat-protection",
      enabled: false,
      users: [U1, U1],
    });
    assert.equal(isError, false);
    assert.deepEqual(h.calls.map((c) => c.method), ["POST", "GET"]);
    assert.deepEqual(h.calls[0].body, {
      name: "ZZ create users",
      type: "threat-protection",
      enabled: false,
      appliesTo: { users: [U1], userGroups: [] },
    });
    assert.equal(h.calls[1].path, `/endpoint/v1/policies/${json.policy.id}`);
    assert.deepEqual(json.assignment_sent, { kind: "user", users: [U1], user_groups: [] });
    assert.deepEqual(json.assignment_stored, { kind: "user", users: [U1], user_groups: [] });
    assert.equal(json.assignment_matches, true);
    assert.deepEqual(json.policy.applies_to, { kind: "user", users: 1, user_groups: 0 });
  } finally {
    await h.close();
  }
});

test("create with endpoint groups looks the group up and always carries the endpoints companion key", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_create_policy", {
      name: "ZZ create groups",
      type: "server-threat-protection",
      enabled: false,
      endpoint_groups: [G2],
    });
    assert.equal(isError, false);
    assert.deepEqual(h.lookups().map((c) => [c.path, c.params.ids]), [["/endpoint/v1/endpoint-groups", G2]]);
    assert.deepEqual(h.writes()[0].body.appliesTo, { endpoints: [], endpointGroups: [G2] });
    assert.deepEqual(json.assignment_stored, { kind: "device", endpoints: [], endpoint_groups: [G2] });
    assert.equal(json.assignment_matches, true);
  } finally {
    await h.close();
  }
});

test("create with no assignment sends no appliesTo and, outside web control, makes no read-back", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_create_policy", { name: "ZZ plain", type: "threat-protection" });
    assert.equal(isError, false);
    assert.equal(h.calls.length, 1);
    assert.equal("appliesTo" in h.calls[0].body, false);
    assert.equal("settings" in h.calls[0].body, false);
    assert.equal("assignment_sent" in json, false);
  } finally {
    await h.close();
  }
});

test("a user and device mix is refused before anything is sent", async () => {
  const h = await harness();
  try {
    for (const [name, args] of [
      ["sophos_create_policy", { name: "ZZ mix", type: "web-control", users: [U1], endpoints: [E1] }],
      ["sophos_update_policy", { policy_id: P_USER, user_groups: [UG1], endpoint_groups: [G1] }],
      ["sophos_set_policy_assignments", { policy_id: P_USER, mode: "add", users: [], endpoints: [E1] }],
      ["sophos_clone_policy", { source_policy_id: P_USER, name: "ZZ clone mix", users: [U1], endpoints: [E1] }],
    ]) {
      const { isError, text } = await h.call(name, args);
      assert.equal(isError, true, name);
      assert.match(text, /never both/, name);
      assert.match(text, /Nothing was sent/, name);
    }
    assert.equal(h.calls.length, 0, "no request was sent");
  } finally {
    await h.close();
  }
});

test("user keys on a server policy are refused before any write", async () => {
  const h = await harness();
  try {
    const create = await h.call("sophos_create_policy", { name: "ZZ srv", type: "server-web-control", user_groups: [UG1] });
    assert.equal(create.isError, true);
    assert.match(create.text, /server-web-control applies only to endpoints and endpoint groups/);
    assert.equal(h.calls.length, 0, "create sent nothing");

    const update = await h.call("sophos_update_policy", { policy_id: P_SERVER, users: [U1] });
    assert.equal(update.isError, true);
    assert.match(update.text, /applies only to endpoints and endpoint groups/);

    const set = await h.call("sophos_set_policy_assignments", { policy_id: P_SERVER, mode: "add", users: [U1] });
    assert.equal(set.isError, true);
    assert.deepEqual(h.writes(), [], "only reads were made");
  } finally {
    await h.close();
  }
});

test("a server endpoint or server group on a computer policy is refused, and so is the reverse", async () => {
  const h = await harness();
  try {
    const create = await h.call("sophos_create_policy", { name: "ZZ srv on computer", type: "web-control", endpoints: [ES1, E1] });
    assert.equal(create.isError, true);
    assert.match(create.text, /web-control applies to computers only: endpoint .*c2 \(DC01\) is a server\. Nothing was written\./);
    assert.deepEqual(h.lookups().map((c) => c.params.ids), [`${ES1},${E1}`], "one batched lookup");

    const update = await h.call("sophos_update_policy", { policy_id: P_DEVICE, endpoint_groups: [G2] });
    assert.equal(update.isError, true);
    assert.match(update.text, /endpoint group .*d2 \(ZZ servers\) is a server group/);

    const set = await h.call("sophos_set_policy_assignments", { policy_id: P_SERVER, mode: "add", endpoint_groups: [G1], endpoints: [E1] });
    assert.equal(set.isError, true);
    assert.match(set.text, /server-web-control applies to servers only/);
    assert.match(set.text, /\(victim\) is a computer;/);
    assert.match(set.text, /\(ZZ computers\) is a computer group/);
    assert.deepEqual(h.writes(), [], "nothing was written");
  } finally {
    await h.close();
  }
});

test("an ID the tenant does not have is refused; a group not listed yet is found by GET; a security VM passes", async () => {
  const h = await harness();
  try {
    const missing = await h.call("sophos_set_policy_assignments", { policy_id: P_DEVICE, mode: "add", endpoints: [MISSING] });
    assert.equal(missing.isError, true);
    assert.match(missing.text, /endpoint .*ff was not found in this tenant/);
    assert.deepEqual(h.writes(), []);

    const lagging = await h.call("sophos_set_policy_assignments", { policy_id: P_DEVICE, mode: "add", endpoint_groups: [G3] });
    assert.equal(lagging.isError, false, lagging.text);
    assert.ok(h.calls.some((c) => c.path === `/endpoint/v1/endpoint-groups/${G3}`), "fell back to GET by ID");
    assert.deepEqual(lagging.json.assignment_stored.endpoint_groups, [G1, G3]);

    const svm = await h.call("sophos_set_policy_assignments", { policy_id: P_SERVER, mode: "add", endpoints: [EV1] });
    assert.equal(svm.isError, false, svm.text);
  } finally {
    await h.close();
  }
});

test("an ID whose 404 has a non-JSON body is still reported as not found", async () => {
  const h = await harness({ plainNotFound: true });
  try {
    const missing = await h.call("sophos_set_policy_assignments", { policy_id: P_DEVICE, mode: "add", endpoint_groups: [MISSING] });
    assert.equal(missing.isError, true);
    assert.match(missing.text, /endpoint group .*ff was not found in this tenant/);
    assert.deepEqual(h.writes(), []);
  } finally {
    await h.close();
  }
});

test("remove does not look targets up", async () => {
  const h = await harness();
  try {
    const { isError } = await h.call("sophos_set_policy_assignments", { policy_id: P_DEVICE, mode: "remove", endpoints: [E1] });
    assert.equal(isError, false);
    assert.deepEqual(h.lookups(), []);
  } finally {
    await h.close();
  }
});

test("{id} objects are refused by the schema", async () => {
  const h = await harness();
  try {
    const { isError, text } = await h.call("sophos_create_policy", { name: "ZZ obj", type: "web-control", users: [{ id: U1 }] });
    assert.equal(isError, true);
    assert.match(text, /Input validation error/);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("update with an assignment replaces the whole assignment and reads it back", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_update_policy", { policy_id: P_USER, user_groups: [UG1] });
    assert.equal(isError, false);
    assert.deepEqual(h.calls.map((c) => c.method), ["GET", "PATCH", "GET"]);
    assert.deepEqual(h.calls[1].body, { appliesTo: { users: [], userGroups: [UG1] } });
    assert.deepEqual(json.assignment_stored, { kind: "user", users: [], user_groups: [UG1] });
    assert.equal(json.assignment_matches, true);
  } finally {
    await h.close();
  }
});

test("update with device keys flips a user policy to a device policy after checking the targets", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_update_policy", { policy_id: P_USER, endpoint_groups: [G1], name: "ZZ flipped" });
    assert.equal(isError, false);
    assert.deepEqual(h.calls.map((c) => `${c.method} ${c.path}`), [
      `GET /endpoint/v1/policies/${P_USER}`,
      "GET /endpoint/v1/endpoint-groups",
      `PATCH /endpoint/v1/policies/${P_USER}`,
      `GET /endpoint/v1/policies/${P_USER}`,
    ]);
    assert.deepEqual(h.writes()[0].body, { name: "ZZ flipped", appliesTo: { endpoints: [], endpointGroups: [G1] } });
    assert.deepEqual(json.assignment_stored, { kind: "device", endpoints: [], endpoint_groups: [G1] });
    assert.deepEqual(json.policy.applies_to, { kind: "device", endpoints: 0, endpoint_groups: 1 });
  } finally {
    await h.close();
  }
});

test("update with no fields names the assignment keys", async () => {
  const h = await harness();
  try {
    const { json } = await h.call("sophos_update_policy", { policy_id: P_USER });
    assert.match(json.error, /users, user_groups, endpoints, endpoint_groups/);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("set add merges with what the policy holds", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_set_policy_assignments", { policy_id: P_USER, mode: "add", users: [U2, U1] });
    assert.equal(isError, false);
    assert.deepEqual(h.writes()[0].body, { appliesTo: { users: [U1, U2], userGroups: [] } });
    assert.deepEqual(json.assignment_before, { kind: "user", users: [U1], user_groups: [] });
    assert.deepEqual(json.assignment_stored, { kind: "user", users: [U1, U2], user_groups: [] });
    assert.equal(json.assignment_matches, true);
    assert.equal(json.status, "updated");
  } finally {
    await h.close();
  }
});

test("set add refuses a kind change while the policy holds the other kind", async () => {
  const h = await harness();
  try {
    const { isError, text } = await h.call("sophos_set_policy_assignments", { policy_id: P_USER, mode: "add", endpoints: [E1] });
    assert.equal(isError, true);
    assert.match(text, /is a user policy with 1 assignment/);
    assert.match(text, /mode "replace"/);
    assert.deepEqual(h.writes(), []);
  } finally {
    await h.close();
  }
});

test("set add on an empty user policy makes it a device policy", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_set_policy_assignments", { policy_id: P_EMPTY, mode: "add", endpoint_groups: [G1] });
    assert.equal(isError, false);
    assert.deepEqual(h.writes()[0].body, { appliesTo: { endpoints: [], endpointGroups: [G1] } });
    assert.equal(json.assignment_stored.kind, "device");
  } finally {
    await h.close();
  }
});

test("set remove takes IDs out and lists the ones that were not assigned", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_set_policy_assignments", {
      policy_id: P_DEVICE,
      mode: "remove",
      endpoint_groups: [G1, G2],
    });
    assert.equal(isError, false);
    assert.deepEqual(h.writes()[0].body, { appliesTo: { endpoints: [E1], endpointGroups: [] } });
    assert.deepEqual(json.not_assigned, { kind: "device", endpoints: [], endpoint_groups: [G2] });
    assert.deepEqual(json.assignment_stored, { kind: "device", endpoints: [E1], endpoint_groups: [] });
  } finally {
    await h.close();
  }
});

test("set writes nothing when nothing would change", async () => {
  const h = await harness();
  try {
    const remove = await h.call("sophos_set_policy_assignments", { policy_id: P_USER, mode: "remove", endpoints: [E1] });
    assert.equal(remove.json.status, "unchanged");
    assert.deepEqual(remove.json.not_assigned, { kind: "device", endpoints: [E1], endpoint_groups: [] });
    const add = await h.call("sophos_set_policy_assignments", { policy_id: P_USER, mode: "add", users: [U1] });
    assert.equal(add.json.status, "unchanged");
    const replace = await h.call("sophos_set_policy_assignments", { policy_id: P_DEVICE, mode: "replace", endpoints: [E1], endpoint_groups: [G1] });
    assert.equal(replace.json.status, "unchanged");
    assert.deepEqual(h.writes(), []);
  } finally {
    await h.close();
  }
});

test("set needs at least one assignment key", async () => {
  const h = await harness();
  try {
    const { isError, text } = await h.call("sophos_set_policy_assignments", { policy_id: P_USER, mode: "replace" });
    assert.equal(isError, true);
    assert.match(text, /at least one of users, user_groups, endpoints or endpoint_groups/);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("set replace sends the whole family and can empty a device policy", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_set_policy_assignments", { policy_id: P_DEVICE, mode: "replace", endpoints: [] });
    assert.equal(isError, false);
    assert.deepEqual(h.writes()[0].body, { appliesTo: { endpoints: [], endpointGroups: [] } });
    assert.deepEqual(json.assignment_stored, { kind: "device", endpoints: [], endpoint_groups: [] });
  } finally {
    await h.close();
  }
});

test("the read-back reports what Sophos stored when it differs from what was sent", async () => {
  const h = await harness({
    tamper: (p) => ({ ...p, appliesTo: { users: p.appliesTo.users?.slice(0, 1) ?? [], userGroups: [] } }),
  });
  try {
    const { isError, json } = await h.call("sophos_set_policy_assignments", { policy_id: P_USER, mode: "add", users: [U2] });
    assert.equal(isError, false);
    assert.deepEqual(json.assignment_sent, { kind: "user", users: [U1, U2], user_groups: [] });
    assert.deepEqual(json.assignment_stored, { kind: "user", users: [U1], user_groups: [] });
    assert.equal(json.assignment_matches, false);
    assert.match(json.warning, /differs from what was sent/);
  } finally {
    await h.close();
  }
});

test("clone with an assignment checks it against the source type, clones, then replaces the clone's assignment", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_clone_policy", { source_policy_id: P_DEVICE, name: "ZZ clone", endpoint_groups: [G3] });
    assert.equal(isError, false, JSON.stringify(json));
    assert.deepEqual(
      h.calls.filter((c) => !/endpoint-groups/.test(c.path)).map((c) => `${c.method} ${c.path.replace(json.policy.id, "<clone>")}`),
      [
        `GET /endpoint/v1/policies/${P_DEVICE}`,
        `POST /endpoint/v1/policies/${P_DEVICE}/clone`,
        "GET /endpoint/v1/policies/<clone>",
        "PATCH /endpoint/v1/policies/<clone>",
        "GET /endpoint/v1/policies/<clone>",
      ]
    );
    assert.equal(h.lookups().length, 2, "one list lookup plus the GET fallback, run once before the clone");
    assert.equal(json.status, "cloned");
    assert.deepEqual(json.assignment.assignment_before, { kind: "device", endpoints: [E1], endpoint_groups: [G1] });
    assert.deepEqual(json.assignment.assignment_stored, { kind: "device", endpoints: [], endpoint_groups: [G3] });
    assert.equal(json.assignment.assignment_matches, true);
  } finally {
    await h.close();
  }
});

test("clone refuses a bad assignment before cloning, and without one makes a single call", async () => {
  const h = await harness();
  try {
    const bad = await h.call("sophos_clone_policy", { source_policy_id: P_DEVICE, name: "ZZ clone", endpoints: [ES1] });
    assert.equal(bad.isError, true);
    assert.match(bad.text, /is a server/);
    assert.deepEqual(h.writes(), [], "no clone was made");

    h.calls.length = 0;
    const plain = await h.call("sophos_clone_policy", { source_policy_id: P_DEVICE, name: "ZZ plain clone" });
    assert.equal(plain.isError, false);
    assert.deepEqual(h.calls.map((c) => c.method), ["POST"]);
    assert.equal("assignment" in plain.json, false);
  } finally {
    await h.close();
  }
});

test("clone reports the clone's ID when the assignment write fails after the clone", async () => {
  const h = await harness({ failPatch: true });
  try {
    const { isError, json } = await h.call("sophos_clone_policy", { source_policy_id: P_USER, name: "ZZ clone", users: [U2] });
    assert.equal(isError, false);
    assert.equal(json.status, "cloned");
    assert.match(json.assignment_error, /Rejected by the test/);
    assert.match(json.assignment_error, new RegExp(`The clone ${json.policy.id} exists without the requested assignment`));
  } finally {
    await h.close();
  }
});

test("list and get report the stored plain ID arrays and the kind", async () => {
  const h = await harness();
  try {
    const list = await h.call("sophos_list_policies", {});
    const byId = new Map(list.json.policies.map((p) => [p.id, p]));
    assert.deepEqual(byId.get(P_USER).applies_to, { kind: "user", users: 1, user_groups: 0 });
    assert.deepEqual(byId.get(P_DEVICE).applies_to, { kind: "device", endpoints: 1, endpoint_groups: 1 });
    assert.deepEqual(byId.get(P_SERVER).applies_to, { kind: "device", endpoints: 0, endpoint_groups: 0 });

    const get = await h.call("sophos_get_policy", { policy_id: P_DEVICE });
    assert.deepEqual(get.json.applies_to_detail, { kind: "device", endpoints: [E1], endpoint_groups: [G1] });
  } finally {
    await h.close();
  }
});
