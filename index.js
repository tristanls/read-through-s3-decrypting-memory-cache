"use strict";

const AWS = require("aws-sdk");
const clone = require("clone");
const events = require("events");
const Joi = require("@hapi/joi");
const LogTelemetryEvents = require("telemetry-events-log");
const markTime = require("mark-time");
const pkg = require("./package.json");
const QuantifyTelemetryEvents = require("telemetry-events-quantify");
const TelemetryEvents = require("telemetry-events");
const TraceTelemetryEvents = require("telemetry-events-trace");

class Cache extends events.EventEmitter
{
    constructor(config)
    {
        super();
        const self = this;

        self.name = pkg.name;
        self.version = pkg.version;

        const configValidationResult = Cache.SCHEMA.config.validate(
            config,
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
        if (self._credentials)
        {
            AWS.config.credentials = self._credentials;
        }
        self._kms = new AWS.KMS(
            {
                region: self._region
            }
        );
        self._s3 = new AWS.S3();

        self._telemetry = new TelemetryEvents(
        {
            package: pkg,
            emitter: self
        });
        self._logs = new LogTelemetryEvents(
            {
                telemetry: self._telemetry
            }
        );
        self._log = self._logs.log;
        self._metrics = new QuantifyTelemetryEvents(
        {
            telemetry: self._telemetry
        });
        self._tracing = new TraceTelemetryEvents(
            {
                telemetry: self._telemetry
            }
        );

        if (self._stderrTelemetry)
        {
            self.on("telemetry", event =>
                {
                    // clone handles-ish circular dependencies
                    console.error(JSON.stringify(clone(event)));
                }
            );
        }
    }

    get(key, callback, context = {})
    {
        const self = this;
        if (self._cache.has(key))
        {
            return callback(undefined, self._cache.get(key));
        }
        const workflow = new events.EventEmitter();
        setImmediate(() => workflow.emit("s3.getObject", {key}));
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
            let traceSpan;
            if (context.parentSpan)
            {
                traceSpan = context.parentSpan.childSpan("AWS.S3.getObject");
            }
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
                        self._log("info", "not found", _targetMetadata,
                            {
                                target:
                                {
                                    args: [params]
                                },
                                error
                            }
                        );
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
                    if (traceSpan)
                    {
                        traceSpan.tag("error", true);
                        traceSpan.finish();
                    }
                    return callback(error);
                }
                if (traceSpan)
                {
                    traceSpan.finish();
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
            let traceSpan;
            if (context.parentSpan)
            {
                traceSpan = context.parentSpan.childSpan("AWS.KMS.decrypt");
            }
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
                    if (traceSpan)
                    {
                        traceSpan.tag("error", true);
                        traceSpan.finish();
                    }
                    return callback(error);
                }
                if (traceSpan)
                {
                    traceSpan.finish();
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
    }
}

Cache.SCHEMA =
{
    config: Joi.object().keys(
        {
            bucket: Joi.string().required(),
            credentials: Joi.object(),
            encryptionContext: Joi.object().required(),
            initialCache: Joi.object().instance(Map),
            region: Joi.string().required(),
            stderrTelemetry: Joi.bool()
        }
    ).required()
};
Cache.S3_NOT_FOUND_CODES =
[
    "AccessDenied", "NoSuchKey"
];

module.exports = Cache;
