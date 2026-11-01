import assert from "node:assert/strict";
import test from "node:test";
import { applyDashboardMode } from "../src/routingMode.ts";

function state(mode = "auto", trafficMode = "selective") {
  return { ok: true, authenticated: true, authConfigured: true,
    csrf: "csrf-0", trafficMode,
    control: { mode, failurePolicy: "killswitch", pinName: "Pinned node" } };
}

function fakeAPI(initial) {
  const persisted = structuredClone(initial);
  const calls = [];
  async function request(action, payload, options) {
    assert.equal(options.csrf, persisted.csrf, "every step uses the latest CSRF token");
    calls.push([action, payload]);
    if (action === "traffic_mode") {
      assert.ok(["selective", "full-vpn"].includes(payload.trafficMode));
      if (payload.trafficMode === "full-vpn") {
        assert.ok(["auto", "pinned"].includes(persisted.control.mode));
      }
      persisted.trafficMode = payload.trafficMode;
    } else {
      assert.ok(["auto", "direct"].includes(action));
      assert.notEqual(persisted.trafficMode, "full-vpn");
      persisted.control.mode = action;
    }
    persisted.csrf = `csrf-${calls.length}`;
    return structuredClone(persisted);
  }
  return { request, calls };
}

for (const [from, scope, to, expected] of [
  ["auto", "selective", "full-vpn", [["traffic_mode", { trafficMode: "full-vpn" }]]],
  ["direct", "selective", "full-vpn", [["auto", {}], ["traffic_mode", { trafficMode: "full-vpn" }]]],
  ["auto", "full-vpn", "auto", [["traffic_mode", { trafficMode: "selective" }]]],
  ["auto", "full-vpn", "direct", [["traffic_mode", { trafficMode: "selective" }], ["direct", {}]]],
  ["auto", "selective", "direct", [["direct", {}]]],
  ["direct", "selective", "auto", [["auto", {}]]],
  ["pinned", "selective", "full-vpn", [["traffic_mode", { trafficMode: "full-vpn" }]]],
  ["pinned", "full-vpn", "auto", [["traffic_mode", { trafficMode: "selective" }], ["auto", {}]]],
  ["pinned", "selective", "auto", [["auto", {}]]],
]) {
  test(`${from}/${scope} -> ${to}: ordered API steps`, async () => {
    const initial = state(from, scope);
    const untouched = structuredClone(initial);
    const api = fakeAPI(initial);
    const confirmed = [];
    const result = await applyDashboardMode(initial, to, api.request, value => confirmed.push(value));
    assert.deepEqual(api.calls, expected);
    assert.equal(confirmed.length, expected.length);
    assert.equal(result.trafficMode, to === "full-vpn" ? "full-vpn" : "selective");
    if (to !== "full-vpn") assert.equal(result.control.mode, to);
    assert.deepEqual(initial, untouched, "previous control response must not be mutated");
  });
}

for (const [mode, scope, target] of [
  ["auto", "selective", "auto"], ["direct", "selective", "direct"],
  ["auto", "full-vpn", "full-vpn"], ["pinned", "full-vpn", "full-vpn"],
]) {
  test(`${mode}/${scope}: selecting the current mode is a no-op`, async () => {
    const initial = state(mode, scope);
    const api = fakeAPI(initial);
    const confirmed = [];
    assert.equal(await applyDashboardMode(initial, target, api.request, value => confirmed.push(value)), initial);
    assert.deepEqual(api.calls, []);
    assert.deepEqual(confirmed, []);
  });
}

test("failed second step keeps the last confirmed state and reports failure", async () => {
  const initial = state("direct");
  const api = fakeAPI(initial);
  const confirmed = [];
  await assert.rejects(applyDashboardMode(initial, "full-vpn", async (...args) => {
    if (args[0] === "traffic_mode") throw new Error("nft validation failed");
    return api.request(...args);
  }, value => confirmed.push(value)), /nft validation failed/);
  assert.equal(confirmed.length, 1);
  assert.equal(confirmed[0].control.mode, "auto");
  assert.equal(confirmed[0].trafficMode, "selective");
});

test("failure leaving Full VPN must not trigger Direct", async () => {
  const calls = [], confirmed = [];
  await assert.rejects(applyDashboardMode(state("auto", "full-vpn"), "direct", async action => {
    calls.push(action);
    throw new Error("failed to restore selective routing");
  }, value => confirmed.push(value)), /selective routing/);
  assert.deepEqual(calls, ["traffic_mode"]);
  assert.deepEqual(confirmed, []);
});

test("non-success response is never published as the active mode", async () => {
  const confirmed = [];
  await assert.rejects(applyDashboardMode(state(), "full-vpn", async () => ({
    ...state(), ok: false, error: "service unavailable",
  }), value => confirmed.push(value)), /service unavailable/);
  assert.deepEqual(confirmed, []);
});
