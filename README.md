# NKJWT

## Contents:

- Why NKJWT?
- User Guide
    - Verifying Token
        - Getting Payload from token
        - Creating token
        - Signing and getting signed token
        - Updating payload

## Why NKJWT?

JWT (JSON Web Token) is an amazing technology, which makes network / API integration extremely easy and fast. This library allows you to get all benefits of JWT with only a few lines of code.

## User Guide

### Verifying Token

```objective-c
NSString *token = @"xxxxxxxxxxxx";
NKJWT *jwt = [[NKJWT alloc] initWithJWT:token];
isValid = [jwt verifyWithKey:key];
```

or if you do not prefer stateless expressions:

```objective-c
NSString *token = @"xxxxxxxxxxxx";
NKJWT *jwt = [[NKJWT alloc] initWithJWT:token];
[jwt setKey:key];
isValid = [jwt verify];
```

### Getting Payload from token

```objective-c
NKJWT *jwt = [[NKJWT alloc] initWithJWT:token];
isValid = [jwt verifyWithKey:key];
NSDictionary *payload = jwt.payload;
```

### Creating token

```objective-c
NKJWT *jwt = [[NKJWT alloc] initWithPayload:payloadDictionary];
```

### Signing and getting signed token

```objective-c
NKJWT *jwt = [[NKJWT alloc] initWithPayload:payloadDictionary];
[jwt signWithKey:key];
NSString *token = [jwt token];
```

or without stateless expressions:

```objective-c
NKJWT *jwt = [[NKJWT alloc] initWithPayload:payloadDictionary];
[jwt setKey:key];
[jwt sign];
NSString *token = [jwt token];
```

### Updating payload

```objective-c
NKJWT *jwt = [[NKJWT alloc] initWithPayload:payloadDictionary];
[jwt signWithKey:key];
NSString *token = [jwt token];

[jwt setPayload:newPayloadDictionary];
[jwt signWithKey:key];
NSString *newToken = [jwt token];
```
