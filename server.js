"use strict";

const express = require("express");
const cors = require("cors");
const { evaluate } = require("./policy");

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) => {
  res.json({ status: "ok", service: "release-gate" });
});

app.post("/release-gate", (req, res) => {
  try {
    const result = evaluate(req.body || {});
    res.status(200).json(result);
  } catch (err) {
    // Fail closed: any malformed input blocks the promotion.
    res.status(400).json({
      decision: "block",
      violations: [],
      error: "malformed_request",
    });
  }
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`release-gate listening on port ${PORT}`);
  });
}

module.exports = app;
