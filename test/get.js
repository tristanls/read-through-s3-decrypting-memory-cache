"use strict";

const clone = require("clone");
const proxyquire = require("proxyquire").noPreserveCache();

const Cache = require("../index.js");

const VALID_CONFIG = require("./config/valid.js");

const countdown = (done, count) =>
{
    let doneCount = 0;
    return () =>
    {
        doneCount++;
        if (doneCount == count)
        {
            done();
        }
    }
};

const tests = module.exports = {};

tests["if value present in cache"] = {
    setUp: function(callback)
    {
        const self = this;
        self.config = clone(VALID_CONFIG);
        self.config.initialCache = new Map();
        self.config.initialCache.set("myKey", Buffer.from("myValue"));
        callback();
    },
    "calls callback with no error, and with value": function(test)
    {
        const self = this;
        test.expect(2);
        const cache = new Cache(self.config);
        cache.get("myKey", (error, value) =>
        {
            test.ok(!error);
            test.ok(Buffer.from("myValue").equals(value));
            test.done();
        });
    },
    "does not call S3": function(test)
    {
        const self = this;
        test.expect(2);
        const Cache = proxyquire("../index.js",
        {
            "aws-sdk":
            {
                S3: function()
                {
                    return {
                        getObject: _ => test.ok(false, "unexpected invocation")
                    }
                }
            }
        });
        const cache = new Cache(self.config);
        cache.get("myKey", (error, value) =>
        {
            test.ok(!error);
            test.ok(Buffer.from("myValue").equals(value));
            test.done();
        });
    },
    "does not call KMS": function(test)
    {
        const self = this;
        test.expect(2);
        const Cache = proxyquire("../index.js",
        {
            "aws-sdk":
            {
                KMS: function()
                {
                    return {
                        decrypt: _ => test.ok(false, "unexpected invocation")
                    }
                }
            }
        });
        const cache = new Cache(self.config);
        cache.get("myKey", (error, value) =>
        {
            test.ok(!error);
            test.ok(Buffer.from("myValue").equals(value));
            test.done();
        });
    }
};

tests["if value not present in cache"] = {
    "calls S3 getObject, if error, calls callback with error": test =>
    {
        test.expect(3);
        const Cache = proxyquire("../index",
        {
            "aws-sdk":
            {
                S3: function()
                {
                    return {
                        getObject: (params, callback) =>
                        {
                            test.deepEqual(params,
                            {
                                Bucket: VALID_CONFIG.bucket,
                                Key: "myKey"
                            });
                            return callback(new Error("boom"));
                        }
                    }
                }
            }
        });
        const cache = new Cache(VALID_CONFIG);
        cache.get("myKey", (error, value) =>
        {
            test.ok(error instanceof Error);
            test.strictEqual(value, undefined);
            test.done();
        });
    },
    "calls S3 getObject, if object does not exist, calls callback with no error and no value": test =>
    {
        test.expect(Cache.S3_NOT_FOUND_CODES.length * 2);
        const done = countdown(test.done, Cache.S3_NOT_FOUND_CODES.length);
        Cache.S3_NOT_FOUND_CODES.map(notFound =>
        {
            const Cache = proxyquire("../index",
            {
                "aws-sdk":
                {
                    S3: function()
                    {
                        return {
                            getObject: (_, callback) =>
                            {
                                return callback(
                                {
                                    code: notFound
                                });
                            }
                        }
                    }
                }
            });
            const cache = new Cache(VALID_CONFIG);
            cache.get("myKey", (error, value) =>
            {
                test.ok(!error);
                test.strictEqual(value, undefined);
                done();
            });
        });
    },
    "calls S3 getObject, if object exists": {
        setUp: function(callback)
        {
            const self = this;
            self.called = false;
            self.stubs =
            {
                "aws-sdk":
                {
                    S3: function()
                    {
                        return {
                            getObject: (_, callback) =>
                            {
                                if (!self.called)
                                {
                                    self.called = true;
                                    return callback(undefined,
                                    {
                                        Body: Buffer.from("myValueInCiphertext")
                                    });
                                }
                                test.ok(false, "unexpected invocation");
                            }
                        }
                    }
                }
            };
            callback();
        },
        "calls KMS to decrypt, if error, calls callback with error": function(test)
        {
            const self = this;
            test.expect(3);
            self.stubs["aws-sdk"].KMS = function()
            {
                return {
                    decrypt: (params, callback) =>
                    {
                        test.deepEqual(params,
                        {
                            CiphertextBlob: Buffer.from("myValueInCiphertext"),
                            EncryptionContext: Object.assign(
                                clone(VALID_CONFIG.encryptionContext),
                                {
                                    keyId: "myKey"
                                }
                            )
                        });
                        return callback(new Error("boom"));
                    }
                }
            };
            const Cache = proxyquire("../index.js", self.stubs);
            const cache = new Cache(VALID_CONFIG);
            cache.get("myKey", (error, value) =>
            {
                test.ok(error instanceof Error);
                test.strictEqual(value, undefined);
                test.done();
            });
        },
        "calls KMS to decrypt, if decrypt failure, calls callback with no error and no value": function(test)
        {
            const self = this;
            test.expect(2);
            self.stubs["aws-sdk"].KMS = function()
            {
                return {
                    decrypt: (_, callback) =>
                    {
                        return callback(undefined,
                        {
                            KeyId: "customer-master-key-id"
                        });
                    }
                }
            };
            const Cache = proxyquire("../index.js", self.stubs);
            const cache = new Cache(VALID_CONFIG);
            cache.get("myKey", (error, value) =>
            {
                test.ok(!error);
                test.strictEqual(value, undefined);
                test.done();
            });
        },
        "calls KMS to decrypt, if success, calls callback with no error and value and caches the object": function(test)
        {
            const self = this;
            test.expect(4);
            self.stubs["aws-sdk"].KMS = function()
            {
                return {
                    decrypt: (_, callback) =>
                    {
                        return callback(undefined,
                        {
                            KeyId: "customer-master-key-id",
                            Plaintext: Buffer.from("myValue")
                        });
                    }
                }
            };
            const Cache = proxyquire("../index.js", self.stubs);
            const cache = new Cache(VALID_CONFIG);
            cache.get("myKey", (error, value) =>
            {
                test.ok(!error);
                test.ok(Buffer.from("myValue").equals(value));
                cache.get("myKey", (error, value) =>
                {
                    test.ok(!error);
                    test.ok(Buffer.from("myValue").equals(value));
                    test.done();
                });
            });
        }
    }
}
