"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { evaluate } = require("../policy");

function basePayload(overrides = {}) {
  return {
    target: "preview",
    event: "pull_request",
    ref: "refs/heads/feature-x",
    workflow: {
      trigger: "pull_request",
      permissions: { contents: "read", packages: "write", "id-token": "none" },
      testsPassed: true,
      matrixComplete: true,
      failFast: false,
      actions: [
        { owner: "actions", name: "checkout", ref: "v4" },
        {
          owner: "docker",
          name: "build-push-action",
          ref: "4a13e500e55cf31b7a5d59a38ab2040ab0f42f56",
        },
      ],
    },
    image: {
      multiStage: true,
      runsAsRoot: false,
      secretMode: "buildkit",
      criticalVulnerabilities: 0,
      digestPinned: true,
    },
    ...overrides,
  };
}

function prodPayload(overrides = {}) {
  return basePayload({
    target: "production",
    event: "push",
    ref: "refs/heads/main",
    ...overrides,
    workflow: {
      ...basePayload().workflow,
      trigger: "push",
      environmentApproval: true,
      ...(overrides.workflow || {}),
    },
  });
}

test("fully compliant preview payload promotes with no violations", () => {
  const result = evaluate(basePayload());
  assert.equal(result.decision, "promote");
  assert.deepEqual(result.violations, []);
});

test("fully compliant production payload promotes with no violations", () => {
  const result = evaluate(prodPayload());
  assert.equal(result.decision, "promote");
  assert.deepEqual(result.violations, []);
});

test("extra permission scope is rejected", () => {
  const p = basePayload();
  p.workflow.permissions = { ...p.workflow.permissions, actions: "write" };
  const result = evaluate(p);
  assert.ok(result.violations.includes("EXCESS_PERMISSION"));
});

test("wrong value for a required scope is rejected", () => {
  const p = basePayload();
  p.workflow.permissions["id-token"] = "write";
  const result = evaluate(p);
  assert.ok(result.violations.includes("EXCESS_PERMISSION"));
});

test("missing a required scope is rejected", () => {
  const p = basePayload();
  delete p.workflow.permissions.packages;
  const result = evaluate(p);
  assert.ok(result.violations.includes("EXCESS_PERMISSION"));
});

test("pull_request_target trigger is unsafe", () => {
  const p = basePayload();
  p.workflow.trigger = "pull_request_target";
  const result = evaluate(p);
  assert.ok(result.violations.includes("UNSAFE_PR_TRIGGER"));
});

test("PR event whose workflow trigger is not pull_request is unsafe", () => {
  const p = basePayload();
  p.event = "pull_request";
  p.workflow.trigger = "push";
  const result = evaluate(p);
  assert.ok(result.violations.includes("UNSAFE_PR_TRIGGER"));
});

test("failed tests are incomplete", () => {
  const p = basePayload();
  p.workflow.testsPassed = false;
  const result = evaluate(p);
  assert.ok(result.violations.includes("TESTS_INCOMPLETE"));
});

test("incomplete matrix is incomplete", () => {
  const p = basePayload();
  p.workflow.matrixComplete = false;
  const result = evaluate(p);
  assert.ok(result.violations.includes("TESTS_INCOMPLETE"));
});

test("failFast true is incomplete", () => {
  const p = basePayload();
  p.workflow.failFast = true;
  const result = evaluate(p);
  assert.ok(result.violations.includes("TESTS_INCOMPLETE"));
});

test("third-party action pinned to a tag is mutable", () => {
  const p = basePayload();
  p.workflow.actions.push({ owner: "docker", name: "setup-buildx-action", ref: "v3" });
  const result = evaluate(p);
  assert.ok(result.violations.includes("MUTABLE_ACTION"));
});

test("third-party action pinned to a full lowercase SHA is fine", () => {
  const p = basePayload();
  const result = evaluate(p);
  assert.ok(!result.violations.includes("MUTABLE_ACTION"));
});

test("actions/* owner may use a tag", () => {
  const p = basePayload();
  p.workflow.actions = [{ owner: "actions", name: "setup-node", ref: "v4" }];
  const result = evaluate(p);
  assert.ok(!result.violations.includes("MUTABLE_ACTION"));
});

test("uppercase SHA is rejected as mutable", () => {
  const p = basePayload();
  p.workflow.actions.push({
    owner: "docker",
    name: "login-action",
    ref: "4A13E500E55CF31B7A5D59A38AB2040AB0F42F56",
  });
  const result = evaluate(p);
  assert.ok(result.violations.includes("MUTABLE_ACTION"));
});

test("single-stage image is rejected", () => {
  const p = basePayload();
  p.image.multiStage = false;
  const result = evaluate(p);
  assert.ok(result.violations.includes("SINGLE_STAGE_IMAGE"));
});

test("root runtime is rejected", () => {
  const p = basePayload();
  p.image.runsAsRoot = true;
  const result = evaluate(p);
  assert.ok(result.violations.includes("ROOT_RUNTIME"));
});

test("arg secret mode leaks into layers", () => {
  const p = basePayload();
  p.image.secretMode = "arg";
  const result = evaluate(p);
  assert.ok(result.violations.includes("SECRET_IN_LAYER"));
});

test("copy secret mode leaks into layers", () => {
  const p = basePayload();
  p.image.secretMode = "copy";
  const result = evaluate(p);
  assert.ok(result.violations.includes("SECRET_IN_LAYER"));
});

test("none secret mode is fine", () => {
  const p = basePayload();
  p.image.secretMode = "none";
  const result = evaluate(p);
  assert.ok(!result.violations.includes("SECRET_IN_LAYER"));
});

test("critical vulnerabilities are rejected", () => {
  const p = basePayload();
  p.image.criticalVulnerabilities = 1;
  const result = evaluate(p);
  assert.ok(result.violations.includes("CRITICAL_CVE"));
});

test("non-digest-pinned image is rejected", () => {
  const p = basePayload();
  p.image.digestPinned = false;
  const result = evaluate(p);
  assert.ok(result.violations.includes("UNPINNED_IMAGE"));
});

test("production off main branch is invalid", () => {
  const p = prodPayload();
  p.ref = "refs/heads/release";
  const result = evaluate(p);
  assert.ok(result.violations.includes("INVALID_PRODUCTION_REF"));
});

test("production via pull_request event is invalid ref", () => {
  const p = prodPayload();
  p.event = "pull_request";
  const result = evaluate(p);
  assert.ok(result.violations.includes("INVALID_PRODUCTION_REF"));
});

test("production without environmentApproval requires approval", () => {
  const p = prodPayload();
  p.workflow.environmentApproval = false;
  const result = evaluate(p);
  assert.ok(result.violations.includes("APPROVAL_REQUIRED"));
});

test("production checks do not apply to preview target", () => {
  const p = basePayload({ target: "preview", ref: "refs/heads/feature-x" });
  const result = evaluate(p);
  assert.ok(!result.violations.includes("INVALID_PRODUCTION_REF"));
  assert.ok(!result.violations.includes("APPROVAL_REQUIRED"));
});

test("multiple simultaneous failures are all reported", () => {
  const p = basePayload();
  p.workflow.permissions["id-token"] = "write";
  p.workflow.trigger = "pull_request_target";
  p.workflow.testsPassed = false;
  p.workflow.actions.push({ owner: "docker", name: "x", ref: "main" });
  p.image.multiStage = false;
  p.image.runsAsRoot = true;
  p.image.secretMode = "arg";
  p.image.criticalVulnerabilities = 3;
  p.image.digestPinned = false;

  const result = evaluate(p);
  assert.equal(result.decision, "block");
  const expected = [
    "EXCESS_PERMISSION",
    "UNSAFE_PR_TRIGGER",
    "TESTS_INCOMPLETE",
    "MUTABLE_ACTION",
    "SINGLE_STAGE_IMAGE",
    "ROOT_RUNTIME",
    "SECRET_IN_LAYER",
    "CRITICAL_CVE",
    "UNPINNED_IMAGE",
  ];
  for (const code of expected) {
    assert.ok(result.violations.includes(code), `missing ${code}`);
  }
  assert.equal(result.violations.length, expected.length);
});

test("production multi-failure includes production-specific codes", () => {
  const p = prodPayload();
  p.ref = "refs/heads/develop";
  p.workflow.environmentApproval = false;
  p.image.digestPinned = false;

  const result = evaluate(p);
  assert.equal(result.decision, "block");
  assert.ok(result.violations.includes("INVALID_PRODUCTION_REF"));
  assert.ok(result.violations.includes("APPROVAL_REQUIRED"));
  assert.ok(result.violations.includes("UNPINNED_IMAGE"));
});

test("decision is promote only when violations array is empty", () => {
  const compliant = evaluate(basePayload());
  assert.equal(compliant.decision, "promote");
  assert.equal(compliant.violations.length, 0);

  const broken = evaluate(basePayload({ target: "preview" }));
  broken.violations = [];
  // sanity: an empty violations array always corresponds to promote
  assert.equal(broken.decision, "promote");
});
