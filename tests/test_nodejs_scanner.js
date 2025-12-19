#!/usr/bin/env node
/**
 * Node.js Scanner Test Suite
 * Tests for shai_hulud_scanner.js covering both original and Shai-Hulud 2.0 detection.
 */

const fs = require("fs");
const path = require("path");
const { test } = require("node:test");
const assert = require("node:assert");
const {
  scanForIocs,
  loadAffectedPackagesFromYaml,
  scanPackage,
} = require("../shai_hulud_scanner.js");

// Test utilities
function createTempDir() {
  const tempDir = path.join(__dirname, "temp_test_" + Date.now());
  fs.mkdirSync(tempDir, { recursive: true });
  return tempDir;
}

function cleanupTempDir(dir) {
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function writeFile(dir, filename, content) {
  const filePath = path.join(dir, filename);
  const dirPath = path.dirname(filePath);
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
  fs.writeFileSync(filePath, content);
}

// Test Suite
console.log("🧪 Running Node.js Scanner Tests\n");

// Test IoC Detection
test("Original postinstall detection", () => {
  const testDir = createTempDir();
  try {
    writeFile(
      testDir,
      "package.json",
      JSON.stringify({
        scripts: {
          postinstall: "node bundle.js",
        },
      })
    );

    const iocs = scanForIocs(testDir);
    const postinstallIocs = iocs.filter(
      (ioc) => ioc.type === "malicious_postinstall"
    );

    assert.ok(postinstallIocs.length > 0, "Should detect postinstall hook");
    assert.strictEqual(
      postinstallIocs[0].variant,
      "original",
      "Should be original variant"
    );
  } finally {
    cleanupTempDir(testDir);
  }
});

test("Shai-Hulud 2.0 preinstall detection", () => {
  const testDir = createTempDir();
  try {
    writeFile(
      testDir,
      "package.json",
      JSON.stringify({
        scripts: {
          preinstall: "node setup_bun.js",
        },
      })
    );

    const iocs = scanForIocs(testDir);
    const preinstallIocs = iocs.filter(
      (ioc) => ioc.type === "malicious_preinstall"
    );

    assert.ok(preinstallIocs.length > 0, "Should detect preinstall hook");
    assert.strictEqual(
      preinstallIocs[0].variant,
      "2.0",
      "Should be 2.0 variant"
    );
  } finally {
    cleanupTempDir(testDir);
  }
});

test("setup_bun.js payload file detection", () => {
  const testDir = createTempDir();
  try {
    writeFile(testDir, "setup_bun.js", "// malicious payload");

    const iocs = scanForIocs(testDir);
    const payloadIocs = iocs.filter(
      (ioc) => ioc.type === "malicious_payload_file"
    );

    assert.ok(payloadIocs.length > 0, "Should detect setup_bun.js");
    assert.strictEqual(payloadIocs[0].filename, "setup_bun.js");
    assert.strictEqual(payloadIocs[0].variant, "2.0");
  } finally {
    cleanupTempDir(testDir);
  }
});

test("bun_environment.js payload file detection", () => {
  const testDir = createTempDir();
  try {
    writeFile(testDir, "bun_environment.js", "// malicious payload");

    const iocs = scanForIocs(testDir);
    const payloadIocs = iocs.filter(
      (ioc) => ioc.type === "malicious_payload_file"
    );

    assert.ok(payloadIocs.length > 0, "Should detect bun_environment.js");
    assert.strictEqual(payloadIocs[0].filename, "bun_environment.js");
  } finally {
    cleanupTempDir(testDir);
  }
});

test("Data files detection", () => {
  const testDir = createTempDir();
  try {
    const dataFiles = [
      "cloud.json",
      "contents.json",
      "environment.json",
      "truffleSecrets.json",
    ];

    dataFiles.forEach((file) => {
      writeFile(testDir, file, "{}");
    });

    const iocs = scanForIocs(testDir);
    const dataFileIocs = iocs.filter(
      (ioc) => ioc.type === "shai_hulud_data_file"
    );

    assert.strictEqual(
      dataFileIocs.length,
      dataFiles.length,
      "Should detect all data files"
    );
    dataFileIocs.forEach((ioc) => {
      assert.strictEqual(ioc.variant, "2.0");
      assert.ok(
        dataFiles.includes(ioc.filename),
        `Expected array to contain ${ioc.filename}`
      );
    });
  } finally {
    cleanupTempDir(testDir);
  }
});

test("actionsSecrets.json detection (GitHub Actions secrets exfiltration)", () => {
  const testDir = createTempDir();
  try {
    writeFile(
      testDir,
      "actionsSecrets.json",
      '{"GITHUB_TOKEN": "ghp_fake_token"}'
    );

    const iocs = scanForIocs(testDir);
    const dataFileIocs = iocs.filter(
      (ioc) => ioc.type === "shai_hulud_data_file"
    );
    const actionsSecretsIocs = dataFileIocs.filter(
      (ioc) => ioc.filename === "actionsSecrets.json"
    );

    assert.ok(
      actionsSecretsIocs.length > 0,
      "Should detect actionsSecrets.json"
    );
    assert.strictEqual(actionsSecretsIocs[0].variant, "2.0");
    assert.strictEqual(actionsSecretsIocs[0].severity, "HIGH");
  } finally {
    cleanupTempDir(testDir);
  }
});

test("Webhook.site reference detection", () => {
  const testDir = createTempDir();
  try {
    writeFile(
      testDir,
      "test.js",
      'const url = "https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7";'
    );

    const iocs = scanForIocs(testDir);
    const webhookIocs = iocs.filter(
      (ioc) => ioc.type === "webhook_site_reference"
    );

    assert.ok(webhookIocs.length > 0, "Should detect webhook.site reference");
  } finally {
    cleanupTempDir(testDir);
  }
});

test("discussion.yaml workflow detection", () => {
  const testDir = createTempDir();
  try {
    const workflowContent = `name: Discussion Create
on:
  discussion:
jobs:
  process:
    env:
      RUNNER_TRACKING_ID: 0
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v5
`;
    writeFile(testDir, ".github/workflows/discussion.yaml", workflowContent);

    const iocs = scanForIocs(testDir);
    const workflowIocs = iocs.filter(
      (ioc) => ioc.type === "malicious_github_workflow"
    );

    assert.ok(
      workflowIocs.length > 0,
      "Should detect discussion.yaml workflow"
    );

    const discussionIocs = workflowIocs.filter(
      (ioc) => ioc.pattern && ioc.pattern.includes("discussion.yaml")
    );
    assert.ok(discussionIocs.length > 0, "Should identify as discussion.yaml");
    assert.strictEqual(discussionIocs[0].variant, "2.0");
  } finally {
    cleanupTempDir(testDir);
  }
});

test("formatter workflow detection", () => {
  const testDir = createTempDir();
  try {
    writeFile(
      testDir,
      ".github/workflows/formatter_123456789.yml",
      "name: Code Formatter\n"
    );

    const iocs = scanForIocs(testDir);
    const workflowIocs = iocs.filter(
      (ioc) => ioc.type === "malicious_github_workflow"
    );
    const formatterIocs = workflowIocs.filter(
      (ioc) => ioc.pattern && ioc.pattern.includes("formatter")
    );

    assert.ok(formatterIocs.length > 0, "Should detect formatter workflow");
    assert.strictEqual(formatterIocs[0].variant, "2.0");
  } finally {
    cleanupTempDir(testDir);
  }
});

test("SHA1HULUD runner detection", () => {
  const testDir = createTempDir();
  try {
    writeFile(testDir, ".github/workflows/test.yml", "runs-on: SHA1HULUD\n");

    const iocs = scanForIocs(testDir);
    const runnerIocs = iocs.filter((ioc) => ioc.type === "sha1hulud_runner");

    assert.ok(runnerIocs.length > 0, "Should detect SHA1HULUD runner");
    assert.strictEqual(runnerIocs[0].variant, "2.0");
  } finally {
    cleanupTempDir(testDir);
  }
});

test("Docker privilege escalation detection", () => {
  const testDir = createTempDir();
  try {
    writeFile(
      testDir,
      "malicious.sh",
      "docker run --rm --privileged -v /:/host ubuntu bash\n"
    );

    const iocs = scanForIocs(testDir);
    const dockerIocs = iocs.filter(
      (ioc) => ioc.type === "docker_privilege_escalation"
    );

    assert.ok(
      dockerIocs.length > 0,
      "Should detect Docker privilege escalation"
    );
    assert.strictEqual(dockerIocs[0].variant, "2.0");
  } finally {
    cleanupTempDir(testDir);
  }
});

test("RUNNER_TRACKING_ID detection", () => {
  const testDir = createTempDir();
  try {
    writeFile(
      testDir,
      ".github/workflows/test.yml",
      "env:\n  RUNNER_TRACKING_ID: 0\n"
    );

    const iocs = scanForIocs(testDir);
    const trackingIocs = iocs.filter(
      (ioc) => ioc.type === "suspicious_runner_config"
    );

    assert.ok(trackingIocs.length > 0, "Should detect RUNNER_TRACKING_ID: 0");
    assert.strictEqual(trackingIocs[0].variant, "2.0");
  } finally {
    cleanupTempDir(testDir);
  }
});

test("Original workflow detection", () => {
  const testDir = createTempDir();
  try {
    writeFile(
      testDir,
      ".github/workflows/shai-hulud-workflow.yml",
      "name: Shai-Hulud\n"
    );

    const iocs = scanForIocs(testDir);
    const workflowIocs = iocs.filter(
      (ioc) => ioc.type === "malicious_github_workflow"
    );
    const originalIocs = workflowIocs.filter(
      (ioc) => ioc.variant === "original"
    );

    assert.ok(originalIocs.length > 0, "Should detect original workflow");
  } finally {
    cleanupTempDir(testDir);
  }
});

test("Both variants detected simultaneously", () => {
  const testDir = createTempDir();
  try {
    writeFile(
      testDir,
      "package.json",
      JSON.stringify({
        scripts: {
          postinstall: "node bundle.js", // Original
          preinstall: "node setup_bun.js", // 2.0
        },
      })
    );

    writeFile(testDir, "setup_bun.js", "// payload");

    const iocs = scanForIocs(testDir);

    const postinstallIocs = iocs.filter(
      (ioc) => ioc.type === "malicious_postinstall"
    );
    const preinstallIocs = iocs.filter(
      (ioc) => ioc.type === "malicious_preinstall"
    );
    const payloadIocs = iocs.filter(
      (ioc) => ioc.type === "malicious_payload_file"
    );

    assert.ok(postinstallIocs.length > 0, "Should detect original postinstall");
    assert.ok(preinstallIocs.length > 0, "Should detect 2.0 preinstall");
    assert.ok(payloadIocs.length > 0, "Should detect 2.0 payload file");
  } finally {
    cleanupTempDir(testDir);
  }
});

test("zapier-platform-legacy-scripting-runner package detection", async (t) => {
  const testDir = createTempDir();
  try {
    // First check if the package is in the database
    const affectedDb = await loadAffectedPackagesFromYaml();
    if (!affectedDb.has("zapier-platform-legacy-scripting-runner")) {
      t.skip(
        "zapier-platform-legacy-scripting-runner package detection (skipped - not yet in remote database)"
      );
      return;
    }

    writeFile(
      testDir,
      "package.json",
      JSON.stringify({
        dependencies: {
          "zapier-platform-legacy-scripting-runner": "4.0.3",
        },
      })
    );

    const packagePath = path.join(testDir, "package.json");
    const { foundPackages, potentialMatches } = await scanPackage(packagePath);

    assert.ok(
      foundPackages.length > 0,
      "Should detect zapier-platform-legacy-scripting-runner"
    );
    assert.strictEqual(
      foundPackages[0].name,
      "zapier-platform-legacy-scripting-runner"
    );
    assert.strictEqual(foundPackages[0].installedVersion, "4.0.3");
  } finally {
    cleanupTempDir(testDir);
  }
});
