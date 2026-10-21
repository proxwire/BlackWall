"use strict";

// Inert static-analysis fixture: exports constants and performs no I/O.
const marker = "BLACKWALL_INERT_JAVASCRIPT_FIXTURE";
const endpoint = "https://" + "javascript.fixture.invalid" + "/api";
const configuration = Object.freeze({ campaign: "javascript-inert" });
const recoveredCommand = String.fromCharCode(
  99, 109, 100, 46, 101, 120, 101, 32, 47, 99, 32, 101, 99, 104, 111, 32,
  66, 76, 65, 67, 75, 87, 65, 76, 76, 95, 73, 78, 69, 82, 84
);
const droppedPayload =
  "UEsDBEJMQUNLV0FMTF9JTkVSVF9KQVZBU0NSSVBUX0RST1BQRURfUEFZTE9BRA==";

module.exports = { marker, endpoint, configuration, recoveredCommand, droppedPayload };
