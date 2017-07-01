"use strict";

const extend = require("extend");
const moduleTelemetryPolicy = require("module-telemetry-policy");
const pkg = require("../package.json");

const Cache = require("../index.js");

moduleTelemetryPolicy(
    {
        construct: () => new Cache(require("../test/config/valid.js")),
        package: pkg
    }
);
