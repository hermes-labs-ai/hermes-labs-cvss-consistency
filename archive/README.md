# Historical scanner

`original-audit.py` is the byte-identical scanner recovered from the original fixed-snapshot audit. Its SHA-256 is `aeadfc3c91179efce6027956ecf0929aeb884083c04e9ca1be0c269f3374e82a`.

This archived script records historical scope: it couples CVSS, CWE, CPE, and SSVC checks to a Vulnrichment repository layout, a time window, and issue exclusions. It is not the reusable checker under `src/`, and the fixture replay does not reproduce its time-bounded full-corpus audit. Its broader dependencies are intentionally excluded from the package install.
