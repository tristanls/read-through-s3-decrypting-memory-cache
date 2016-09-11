"use strict";

const AWS = require("aws-sdk");
const clone = require("clone");
const events = require("events");
const Joi = require("joi");
const LogTelemetryEvents = require("telemetry-events-log");
const markTime = require("mark-time");
const pkg = require("./package.json");
const QuantifyTelemetryEvents = require("telemetry-events-quantify");
const TelemetryEvents = require("telemetry-events");
const util = require("util");

const Cache = module.exports = function(config)
{
    if (!(this instanceof Cache))
    {
        return new Cache(config);
    }
    const self = this;

    self.name = pkg.name;
    self.version = pkg.version;

    const configValidationResult = Joi.validate(
        config, Cache.SCHEMA.config,
        {
            abortEarly: false,
            convert: false
        });
    if (configValidationResult.error)
    {
        throw configValidationResult.error;
    }

    Object.keys(config).map(property =>
    {
        self[`_${property}`] = config[property];
    });
    events.EventEmitter.call(self);

    self._cache = new Map();
    if (self._initialCache)
    {
        self._initialCache.forEach((value, key) => self._cache.set(key, value));
    }
    self._kms = new AWS.KMS();
    self._s3 = new AWS.S3();

    self._telemetry = new TelemetryEvents(
    {
        package: pkg,
        emitter: self
    });
    self._log = new LogTelemetryEvents(
        {
            telemetry: self._telemetry
        }
    ).log;
    self._metrics = new QuantifyTelemetryEvents(
    {
        telemetry: self._telemetry
    });

    // debugging
    // self.on("telemetry", event =>
    // {
    //     // clone handles circular dependencies
    //     console.log(JSON.stringify(clone(event)));
    // });
};

util.inherits(Cache, events.EventEmitter);

Cache.SCHEMA =
{
    config: Joi.object().keys(
        {
            bucket: Joi.string().required(),
            encryptionContext: Joi.object().required(),
            initialCache: Joi.object().type(Map)
        }
    )
};
Cache.S3_NOT_FOUND_CODES =
[
    "AccessDenied", "NoSuchKey"
];


Cache.prototype.get = function(key, callback)
{
    const self = this;
    if (self._cache.has(key))
    {
        return callback(undefined, self._cache.get(key));
    }
    const workflow = new events.EventEmitter();
    workflow.on("s3.getObject", dataBag =>
    {
        const _targetMetadata = {
            method: "get",
            target: {
                module: "aws-sdk",
                version: AWS.VERSION,
                export: "S3",
                method: "getObject"
            }
        };
        const params = {
            Bucket: self._bucket,
            Key: dataBag.key
        };
        self._log("info", "getting object from S3", _targetMetadata,
        {
            target: {
                args: [params]
            }
        });
        const startTime = markTime();
        self._s3.getObject(params, (error, data) =>
        {
            const elapsedTime = markTime() - startTime;
            self._metrics.gauge("latency",
            {
                unit: "ms",
                value: elapsedTime,
                metadata: clone(_targetMetadata)
            });
            if (error)
            {
                const notFound = Cache.S3_NOT_FOUND_CODES.indexOf(error.code) >= 0;
                if (notFound)
                {
                    self._cache.set(dataBag.key, undefined);
                    return callback();
                }
                self._log("error", "getting object from S3 failed", _targetMetadata,
                {
                    target: {
                        args: [params]
                    },
                    error,
                    stack: error.stack
                });
                return callback(error);
            }
            dataBag.ciphertext = data.Body;
            workflow.emit("kms.decrypt", dataBag)
        });
    });
    workflow.on("kms.decrypt", dataBag =>
    {
        const _targetMetadata = {
            method: "get",
            target: {
                module: "aws-sdk",
                version: AWS.VERSION,
                export: "KMS",
                method: "decrypt"
            }
        };
        const params = {
            CiphertextBlob: dataBag.ciphertext,
            EncryptionContext: Object.assign(
                clone(self._encryptionContext),
                {
                    keyId: dataBag.key
                }
            )
        };
        const redactedParams = {
            CiphertextBlob: params.CiphertextBlob.toString("base64"),
            EncryptionContext: params.EncryptionContext
        };
        self._log("info", "decrypting ciphertext via KMS", _targetMetadata,
        {
            target: {
                args: [redactedParams]
            }
        });
        const startTime = markTime();
        self._kms.decrypt(params, (error, data) =>
        {
            const elapsedTime = markTime() - startTime;
            self._metrics.gauge("latency",
            {
                unit: "ms",
                value: elapsedTime,
                metadata: clone(_targetMetadata)
            });
            if (error)
            {
                self._log(
                    "error",
                    "decrypting ciphertext via KMS failed",
                    _targetMetadata,
                    {
                        target: {
                            args: [redactedParams]
                        },
                        error,
                        stack: error.stack
                    }
                );
                return callback(error);
            }
            if (!data.Plaintext)
            {
                self._cache.set(dataBag.key, undefined);
                return callback();
            }
            self._cache.set(dataBag.key, data.Plaintext);
            return callback(undefined, data.Plaintext);
        })
    });
    workflow.emit("s3.getObject", {key});
};
