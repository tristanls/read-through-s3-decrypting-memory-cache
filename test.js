"use strict";

const AWS = require("aws-sdk");
const clone = require("clone");

const Cache = require("./index.js");

const validConfig = require("./test/config/valid.js");

it("instantiates with valid config", () =>
    {
        let cache = new Cache(validConfig);
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

it("initializes AWS SDK with provided credentials", () =>
    {
        const creds = new AWS.SharedIniFileCredentials();
        const cache = new Cache(Object.assign(clone(validConfig),
            {
                credentials: creds
            }
        ));
        expect(cache._s3.config.credentials).toBe(creds);
        expect(cache._kms.config.credentials).toBe(creds);
    }
);
