"use strict";

const clone = require("clone");

const Cache = require("./index.js");

const validConfig = require("./test/config/valid.js");

it("instantiates with valid config", () =>
    {
        let cache = new Cache(validConfig);
        expect(cache instanceof Cache);
        cache = Cache.call({}, validConfig);
        expect(cache instanceof Cache);
    }
);

it("initializes cache with provided Map", done =>
    {
        const config = clone(validConfig);
        config.initialCache = new Map();
        config.initialCache.set("myKey", Buffer.from("myValue"));
        const cache = new Cache(config);
        cache.get("myKey", (error, value) =>
            {
                expect(error).toBeFalsy();
                expect(value).toEqual(Buffer.from("myValue"));
                done();
            }
        );
    }
);
