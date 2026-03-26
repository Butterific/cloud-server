# cloud-server (Deno Deploy)

A cloud data server for Scratch-style cloud variables, compatible with existing forkphorus/TurboWarp projects.

This version is adapted to run on Deno Deploy using `deno.ts` as the runtime entrypoint.

## Compatibility

The WebSocket protocol is kept compatible with the original cloud-server behavior:

- same handshake + `set/create/delete/rename` message methods
- same newline-batched `set` forwarding behavior
- same important close codes (`4000`, `4002`, `4003`, `4005`)

So previous projects should work the same, with the main difference being deployment on Deno Deploy.

See `doc/protocol.md` for protocol details.

## Restrictions

- No long-term storage: all data is in memory only.
- No history logs.
- Rooms/variables reset when the deployment restarts.

## Deploy on Deno Deploy

Set your project entrypoint to:

`deno.ts`

You do not need to set any environment variables to start; defaults are already configured.

## Resource optimization defaults

The Deno runtime is tuned to reduce active CPU time and bandwidth usage:

- send buffering enabled by default (`BUFFER_SENDS=20`)
- lazy flush scheduling (flush timer only when buffered data exists)
- lazy maintenance scheduling (runs only when clients/rooms exist)
- handshake timeout cleanup
- idle client cleanup
- dormant room janitor cleanup
- message size cap

## Environment variables

- `TRUST_PROXY` (`true`/`false`)
- `ANONYMIZE_ADDRESSES` (`true`/`false`)
- `ANONYMIZE_GENERATED_USERNAMES` (`true`/`false`, default `true`)
- `ENABLE_RENAME` (`true`/`false`, default `false`)
- `ENABLE_DELETE` (`true`/`false`, default `false`)
- `BUFFER_SENDS` (messages/second, default `20`, set `0` to disable buffering)
- `MAX_ROOMS` (default `16384`)
- `JANITOR_INTERVAL_MS` (default `60000`)
- `JANITOR_THRESHOLD_MS` (default `3600000`)
- `HANDSHAKE_TIMEOUT_MS` (default `30000`)
- `CLIENT_IDLE_TIMEOUT_MS` (default `900000`)
- `MAX_MESSAGE_CHARS` (default `1000000`)
- `LOG_LEVEL` (`info` or `debug`, default `info`)

## Notes

- HTTP responses are served directly by `deno.ts`.
- The runtime does not depend on Node.js, npm, or `src/config.js`.
