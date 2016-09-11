"use strict";

const clone = require("clone");
const pkg = require("../package.json");

const Cache = require("../index.js");

const VALID_CONFIG = require("./config/valid.js");

const tests = module.exports = {};

tests["instantiates with valid config"] = test =>
{
    test.expect(2);
    let cache = new Cache(VALID_CONFIG);
    test.ok(cache instanceof Cache);
    cache = Cache.call({}, VALID_CONFIG);
    test.ok(cache instanceof Cache);
    test.done();
};

tests["exposes 'name' and 'version' properties"] = test =>
{
    test.expect(2);
    const cache = new Cache(VALID_CONFIG);
    test.equal(cache.name, pkg.name);
    test.equal(cache.version, pkg.version);
    test.done();
};

tests["initializes cache with provided Map"] = test =>
{
    test.expect(2);
    const config = clone(VALID_CONFIG);
    config.initialCache = new Map();
    config.initialCache.set("myKey", Buffer.from("myValue"));
    const cache = new Cache(config);
    cache.get("myKey", (error, value) =>
    {
        test.ok(!error);
        test.deepEqual(value, Buffer.from("myValue"));
        test.done();
    });
};
