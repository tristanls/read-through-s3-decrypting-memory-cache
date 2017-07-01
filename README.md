# read-through-s3-decrypting-memory-cache

_Stability: 1 - [Experimental](https://github.com/tristanls/stability-index#stability-1---experimental)_

[![NPM version](https://badge.fury.io/js/read-through-s3-decrypting-memory-cache.png)](http://npmjs.org/package/read-through-s3-decrypting-memory-cache)

Read-through in-memory cache for AWS S3 objects that are reasonable to cache in memory and need to be decrypted using AWS KMS.

## Contributors

[@tristanls](https://github.com/tristanls)

## Contents

  * [Overview](#overview)
  * [Installation](#installation)
  * [Tests](#tests)
  * [Usage](#usage)
  * [Documentation](#documentation)
  * [Releases](#releases)

## Overview

This module offers a read-through in-memory cache for small objects that are stored in S3 and need to be decrypted using KMS. It assumes it is running in an environment where [aws-sdk](https://github.com/aws/aws-sdk-js) has access to its standard credentials chain with `s3:GetObject` permission to the configured S3 Bucket, `kms:decrypt` permission. Further, this module assumes appropriate AWS KMS key policies or grants allow decryption invocations to succeed.

## Installation

    npm install read-through-s3-decrypting-memory-cache

## Tests

    npm test

## Usage

```javascript
const Cache = require("read-through-s3-decrypting-memory-cache");
const cache = new Cache(
{
    bucket: "name-of-my-s3-bucket",
    encryptionContext: {
        some: "encryption context"
    }
});
cache.get("myKey", (error, value) =>
{
    console.log(error, value);
});

const initialCache = new Map();
initialCache.set("myKey", Buffer.from("myValue"));
const cache2 = new Cache(
{
    bucket: "name-of-my-other-s3-bucket",
    encryptionContext: {
        some: "encryption context"
    },
    initialCache
});
cache2.get("myKey", (error, value) =>
{
    console.log(error, value);
});
```

## Documentation

### Cache

**Public API**
  * [Cache.S3_NOT_FOUND_CODES](#caches3_not_found_codes)
  * [new Cache(config)](#new-cacheconfig)
  * [cache.get(key, \[context\], callback)](#cachegetkey-context-callback)

#### Cache.S3_NOT_FOUND_CODES

  * `["AccessDenied", "NoSuchKey"]`

Default S3 error codes to treat as "not found" (`AccessDenied` can occur if the object does not exist but the caller has no `s3:ListBucket` permission).

#### new Cache(config)

  * `config`: _Object_ Cache configuration.
    * `bucket`: _String_ Name of S3 bucket to retrieve values from.
    * `encryptionContext`: _Object_ Encryption context to extend when attempting KMS decryption.
    * `initialCache`: _Map_ _(Default: undefined)_ Initial cached values to use.
    * `stdoutTelemetry`: _Boolean_ _(Default: false)_ If `true`, telemetry will be emitted to `stdout`.

Creates a new Cache.

#### cache.get(key, [context], callback)

  * `key`: _String_ S3 Key to retrieve from cache.
  * `context`: _Object_ Optional context.
    * `parentSpan`: _TraceTelemetryEvents.Span_ Parent span to use to trace execution.
  * `callback`: _Function_ `function(error, value){}`
    * `error`: _Error_ Error, if any.
    * `value`: _Buffer_ S3 Object, if it exists, `undefined` otherwise.

Retrieves the cached `value` from memory. If not found in memory, attempts to retrieve the `value` from S3. If not found in S3, caches `undefined` locally, otherwise, decrypts using KMS. If decryption fails, caches `undefined` locally, otherwise caches the platinext `value` locally.

The `EncryptionContext` used in `KMS.decrypt()` operation is the configured `encryptionContext` with addition of `keyId` field that equals the value of `key`. For example, `cache.get("foo", callback)` will add `keyId: "foo"` to the configured `encryptionContext` when attempting decryption.

## Releases

[Current releases](https://github.com/tristanls/read-through-s3-decrypting-memory-cache/releases).

### Policy

We follow the semantic versioning policy ([semver.org](http://semver.org/)) with a caveat:

> Given a version number MAJOR.MINOR.PATCH, increment the:
>
>MAJOR version when you make incompatible API changes,<br/>
>MINOR version when you add functionality in a backwards-compatible manner, and<br/>
>PATCH version when you make backwards-compatible bug fixes.

**caveat**: Major version zero is a special case indicating development version that may make incompatible API changes without incrementing MAJOR version.
