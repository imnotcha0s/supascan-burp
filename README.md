# SupaScan for Burp Suite

SupaScan is a [Burp Suite](https://portswigger.net/burp) extension (Montoya API, Java 17) that passively fingerprints Supabase backends in proxied traffic and runs safe checks for common Supabase misconfigurations.

## Overview

As you browse a target through Burp, SupaScan watches the proxied traffic, detects Supabase usage, extracts credentials, and surfaces Row Level Security, authentication, storage, RPC, and privilege escalation.

The extension is passive by default. No request is ever sent on your behalf until you explicitly run a check. 

## Features

Passive detection

* Fingerprints Supabase from host patterns, API paths, request headers, and JavaScript bundles
* Extracts the project URL, the anon key, and the anon role
* Detects any leaked service_role key in responses or bundles
* Captures observed tables, RPC functions, and storage buckets from traffic

Session manager

* Add authenticated users per instance by signing in with email and password, or by pasting an existing access token
* Switch the active identity from a dropdown beside the instance selector
* Users created through the Signup tab are added automatically
* Works with only a session and no anon key, since Supabase accepts any project token as the api key

Active checks (explicit, gated by instance)

* Read: tests each table with a single row request and a count only request, records the row count as impact, and keeps one sampled row as evidence
* Write: attempts an update guarded by a `tx=rollback` preference and a filter that matches no rows
* Auth: tests open signup, and provides a custom signup tab with optional user metadata
* RPC: enumerates functions from the OpenAPI schema, tests unauthenticated calls, and offers a name brute force
* Storage: enumerates objects inside buckets recursively to find exposed files, with copy url, download, and send to Repeater
* Databases: brute forces privileged PostgREST schemas (auth, vault, storage, and more) to find privilege escalation, tested as the active role
* IDOR and RLS: diffs what two or more users can read to catch broken policies, not just absent ones

## Requirements

* JDK 17

The Gradle wrapper (`./gradlew`, pinned to Gradle 8.14.1) is checked in, so no separate Gradle install is needed.

## Build

```bash
./gradlew shadowJar
```

The build produces an installable fat JAR at `build/libs/supascan-burp-0.1.0.jar`, with Gson shaded (under `com.supascan.shaded.gson`) and the Montoya API left out, since Burp provides it at runtime.

## Install in Burp

1. Open Burp Suite
2. Go to Extensions, then the Installed tab
3. Choose Add, and set Extension type to Java
4. Select `build/libs/supascan-burp-0.1.0.jar`

The SupaScan tab appears once loaded. Findings surface as native Scanner issues under Target, Issues (Burp Suite Professional).

## Usage

1. Browse the target application through Burp. SupaScan detects Supabase instances passively and lists them in the SupaScan tab
2. Optionally open the Sessions tab and add a user by sign in or by token, then pick the active identity from the dropdown beside the instance selector
3. Select an instance and run the checks you need: Read, Write, Auth, RPC, Databases, or IDOR and RLS
4. Review findings in Burp's Issues view, and inspect results in the SupaScan tabs

## Disclaimer

SupaScan is for authorized security testing only. Use it exclusively on systems you own or have explicit permission to test. This build does not restrict active checks to Burp's scope, and captured evidence — including tokens, emails, and secret values — is stored raw in the Burp project file, so treat that file as sensitive. You are responsible for how you use it.

Keep that in mind when performing your audits: https://supabase.com/docs/guides/security/security-testing
