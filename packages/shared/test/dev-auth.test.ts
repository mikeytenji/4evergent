import { test } from "node:test";
import assert from "node:assert/strict";
import { DevAuthProvider } from "../src/dev-auth.js";

test("DevAuthProvider: no Authorization header returns default owner", async () => {
  const provider = new DevAuthProvider({ defaultOwnerId: "owner-dev" });

  const result = await provider.authenticate({ headers: {} });

  assert.ok(result);
  assert.equal(result!.ownerId, "owner-dev");
  assert.equal(result!.subject, "dev-user");
});

test("DevAuthProvider: known API key returns mapped owner and apikey subject", async () => {
  const provider = new DevAuthProvider({
    defaultOwnerId: "owner-dev",
    apiKeys: { "test-key-123": "owner-a" },
  });

  const result = await provider.authenticate({
    headers: { authorization: "Bearer test-key-123" },
  });

  assert.ok(result);
  assert.equal(result!.ownerId, "owner-a");
  // subject is "apikey:" + first 8 characters of the key
  assert.equal(result!.subject, "apikey:test-key");
});

test("DevAuthProvider: multiple keys map to different owners", async () => {
  const provider = new DevAuthProvider({
    defaultOwnerId: "owner-dev",
    apiKeys: { "key-alpha-1": "owner-a", "key-beta-22": "owner-b" },
  });

  const resultA = await provider.authenticate({
    headers: { authorization: "Bearer key-alpha-1" },
  });
  const resultB = await provider.authenticate({
    headers: { authorization: "Bearer key-beta-22" },
  });

  assert.equal(resultA!.ownerId, "owner-a");
  assert.equal(resultA!.subject, "apikey:key-alph");
  assert.equal(resultB!.ownerId, "owner-b");
  assert.equal(resultB!.subject, "apikey:key-beta");
});

test("DevAuthProvider: unknown API key falls through to default owner", async () => {
  const provider = new DevAuthProvider({
    defaultOwnerId: "owner-dev",
    apiKeys: { "test-key-123": "owner-a" },
  });

  // Documented permissive dev behaviour: unknown keys are NOT rejected,
  // they fall through to the configured default identity.
  const result = await provider.authenticate({
    headers: { authorization: "Bearer no-such-key" },
  });

  assert.ok(result);
  assert.equal(result!.ownerId, "owner-dev");
  assert.equal(result!.subject, "dev-user");
});

test("DevAuthProvider: non-Bearer Authorization header returns default owner", async () => {
  const provider = new DevAuthProvider({
    defaultOwnerId: "owner-dev",
    apiKeys: { "test-key-123": "owner-a" },
  });

  const result = await provider.authenticate({
    headers: { authorization: "Basic dXNlcjpwYXNz" },
  });

  assert.ok(result);
  assert.equal(result!.ownerId, "owner-dev");
  assert.equal(result!.subject, "dev-user");
});

test("DevAuthProvider: array-valued Authorization header uses the first value", async () => {
  const provider = new DevAuthProvider({
    defaultOwnerId: "owner-dev",
    apiKeys: { "test-key-123": "owner-a" },
  });

  const result = await provider.authenticate({
    headers: { authorization: ["Bearer test-key-123", "Bearer ignored-key"] },
  });

  assert.ok(result);
  assert.equal(result!.ownerId, "owner-a");
  assert.equal(result!.subject, "apikey:test-key");
});

test("DevAuthProvider: empty apiKeys config returns default owner for any key", async () => {
  const provider = new DevAuthProvider({ defaultOwnerId: "owner-dev", apiKeys: {} });

  const result = await provider.authenticate({
    headers: { authorization: "Bearer any-key" },
  });

  assert.ok(result);
  assert.equal(result!.ownerId, "owner-dev");
  assert.equal(result!.subject, "dev-user");
});

test("DevAuthProvider: omitted apiKeys config returns default owner", async () => {
  const provider = new DevAuthProvider({ defaultOwnerId: "owner-dev" });

  const result = await provider.authenticate({
    headers: { authorization: "Bearer any-key" },
  });

  assert.ok(result);
  assert.equal(result!.ownerId, "owner-dev");
  assert.equal(result!.subject, "dev-user");
});

test("DevAuthProvider: client-provided owner headers are never trusted", async () => {
  const provider = new DevAuthProvider({
    defaultOwnerId: "owner-dev",
    apiKeys: { "test-key-123": "owner-a" },
  });

  const result = await provider.authenticate({
    headers: {
      authorization: "Bearer test-key-123",
      "x-owner-id": "fake-owner",
      "x-subject": "fake-subject",
    },
  });

  assert.equal(result!.ownerId, "owner-a");
  assert.equal(result!.subject, "apikey:test-key");
});
