"use strict";

// Inert static-analysis fixture: exports constants and performs no I/O.
const marker = "BLACKWALL_INERT_JAVASCRIPT_FIXTURE";
const endpoint = "https://javascript.fixture.invalid/api";
const configuration = Object.freeze({ campaign: "javascript-inert" });

module.exports = { marker, endpoint, configuration };
