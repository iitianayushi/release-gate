"use strict";

const SHA_RE = /^[0-9a-f]{40}$/;

const REQUIRED_PERMISSIONS = {
  contents: "read",
  packages: "write",
  "id-token": "none",
};

/**
 * Deterministically evaluate a release-gate request.
 * @param {object} payload
 * @returns {{decision: "promote"|"block", violations: string[]}}
 */
function evaluate(payload) {
  const violations = [];

  const target = payload && payload.target;
  const event = payload && payload.event;
  const ref = payload && payload.ref;
  const workflow = (payload && payload.workflow) || {};
  const image = (payload && payload.image) || {};

  // ---- Permissions: must be exactly least privilege, no more, no less ----
  const perms = workflow.permissions || {};
  const requiredKeys = Object.keys(REQUIRED_PERMISSIONS);
  const actualKeys = Object.keys(perms);

  const hasExtraScope = actualKeys.some((k) => !requiredKeys.includes(k));
  const hasMissingOrWrongScope = requiredKeys.some(
    (k) => perms[k] !== REQUIRED_PERMISSIONS[k]
  );

  if (hasExtraScope || hasMissingOrWrongScope) {
    violations.push("EXCESS_PERMISSION");
  }

  
  // ---- PR trigger safety ----
  const trigger = workflow.trigger;
  const unsafeTrigger = event === "pull_request" && trigger !== "pull_request";
  if (unsafeTrigger) {
    violations.push("UNSAFE_PR_TRIGGER");
  }
  
  

  // ---- Complete matrix testing ----
  const testsIncomplete =
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast === true;
  if (testsIncomplete) {
    violations.push("TESTS_INCOMPLETE");
  }

  // ---- Action pinning: actions/* may use a tag, all other owners need a full SHA ----
  const actions = Array.isArray(workflow.actions) ? workflow.actions : [];
  const hasMutableAction = actions.some((a) => {
    if (!a || a.owner === "actions") return false;
    return !SHA_RE.test(String(a.ref || ""));
  });
  if (hasMutableAction) {
    violations.push("MUTABLE_ACTION");
  }

  // ---- Hardened image checks ----
  if (image.multiStage !== true) {
    violations.push("SINGLE_STAGE_IMAGE");
  }
  if (image.runsAsRoot !== false) {
    violations.push("ROOT_RUNTIME");
  }
  if (!(image.secretMode === "none" || image.secretMode === "buildkit")) {
    violations.push("SECRET_IN_LAYER");
  }
  if (!(Number(image.criticalVulnerabilities) === 0)) {
    violations.push("CRITICAL_CVE");
  }
  if (image.digestPinned !== true) {
    violations.push("UNPINNED_IMAGE");
  }

  // ---- Production-only requirements ----
  if (target === "production") {
    const validProdRef = event === "push" && ref === "refs/heads/main";
    if (!validProdRef) {
      violations.push("INVALID_PRODUCTION_REF");
    }
    if (workflow.environmentApproval !== true) {
      violations.push("APPROVAL_REQUIRED");
    }
  }

  return {
    decision: violations.length === 0 ? "promote" : "block",
    violations,
  };
}

module.exports = { evaluate, REQUIRED_PERMISSIONS, SHA_RE };
