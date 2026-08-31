# Encrypted Geneva + Tour du Mont Blanc itinerary

The deployed page contains an unlock screen and an AES-256-GCM encrypted payload. The passphrase is stored as a protected GitHub Actions secret and is never committed or included in the deployed site.

The editable itinerary source is kept outside the public repository. `site/index.html` is ciphertext and may be published safely.
