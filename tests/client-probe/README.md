# Temporary application probe

Preparation only; no server or provider connection runs during fixture tests.
Live serving, phone setup and router operations require the exact reviewed batch approval.
No installation or external deployment is needed. Python and browser APIs are the only runtime dependencies.

After approval, the operator supplies an unused absolute **private log path** and explicit protected adult LAN bind address:

```sh
python3 tests/client-probe/helper.py --bind APPROVED_SINGLE_LAN_ADDRESS --port APPROVED_PORT --lifetime 90 --log /ABSOLUTE/PRIVATE/UNUSED_LOG
```

Default bind is loopback. Listener lifetime is 90–180 seconds. The printed URL contains a private capability in its fragment; open it on each approved browser and keep it private. The capability is sent only to the helper in a header. No query-token URLs, arbitrary files, CORS or application APIs are served. The helper creates the supplied log exclusively with mode 0600 and bounds requests/bodies/log bytes.

Each page creates one primary WebSocket, never reconnects, and sends only random run/socket identifiers, sequences and fresh 128-bit nonces. Each trial lasts at most 60 seconds/120 sends. Keep both browsers foreground and awake. Exact echoes older than 500 ms, duplicates and altered messages are rejected. LAN heartbeats and clock bounds support local attribution/timing; they do not prove Internet forwarding.

Endpoint candidate: [Postman's documented public echo](https://learning.postman.com/docs/reference/developer-resources/echo-api/). Browser-Origin acceptance, uptime, RTT and policy suitability remain untested. Baseline both clients before any router mutation; missing adult echoes, clock uncertainty, lifecycle gaps or provider failures make measurements unavailable. The provider receives ordinary source addresses; send no household identity or credentials.

Download browser observations before closing the page. Browser downloads are private evidence; move them to the approved private evidence directory and set mode 0600. Helper logs contain source addresses and must stay private. The output never declares packet acceptance. Root must correlate exact approved router dispatch/acceptance timestamps, source binding, family and accelerated-path evidence separately. Longer timed pauses require a distinct <=60-second observation window around expiry, not extending a primary trial.

Offline verification: `python3 tests/test-client-probe.py`. Fake WebSockets make no provider connections; helper tests bind only loopback. Stop/remove only exact owned artifacts according to the reviewed teardown, and do not publish raw logs or capability URLs.
