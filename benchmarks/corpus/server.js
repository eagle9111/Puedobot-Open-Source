const express = require("express");
const app = express();

app.get("/run", (req, res) => {
  const out = eval(req.query.code); // EXPECT: code_injection
  res.send(String(out));
});

app.get("/health", (req, res) => {
  res.send(String(eval("1 + 1"))); // SAFE
});
