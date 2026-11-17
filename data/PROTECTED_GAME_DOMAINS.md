# Protected game and top-up domains

`protected-game-domains.json` is a typo/homoglyph reference set. It is not an
allowlist, does not set `isKnownDomain`, and never proves that a page or payment
transaction is legitimate.

Only registrable domains are stored because `findSimilarDomain()` compares the
registrable label. Official subdomains such as `shop.vnggames.com`,
`pay.zing.vn`, and `napthe.vtcgame.vn` are represented by their registrable
domains. Every entry must retain a publisher-owned source URL and review date.

User reports alone are not enough to add a domain to this file or to the static
blacklist. Threat-shaped regression fixtures should use reserved `.example`
domains whenever the real domain is not required.
