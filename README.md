# 1.8 GDPS
Source code for Exenity's 1.8 GDPS, based on Cvolton's GMDprivateServer.
Intended only for use on 1.8, usage with other versions untested but most versions pre-1.9 should be usable.

See all documentation about this edition [here](Documentation.md).

### Basic Instructions
1) Upload the files inside 'src' folder on a webserver
2) Import database.sql into a MySQL/MariaDB database
3) Import sql_upgrade.sql over the database you've created
3) Edit the server endpoints inside your Geometry Dash client to point to your server

### Credits

- GMDprivateServer by Cvolton
- Some code used here is taken from Dashbox/GDOpenServer (now discontinued, public archive available [here](https://github.com/Stazzical/dashbox-old/)), by (mostly) me, ryzzica and Wyliemaster.

### GMDprivateServer Credits
Base for account settings and the private messaging system by someguy28

Using this for XOR encryption - https://github.com/sathoro/php-xor-cipher - (incl/lib/XORCipher.php)

Using this for cloud save encryption - https://github.com/defuse/php-encryption - (incl/lib/defuse-crypto.phar)

Most of the stuff in generateHash.php has been figured out by pavlukivan and Italian APK Downloader, so credits to them

## Security fixes

This fork hardened the endpoints below. Each entry lists the endpoint, why it was vulnerable in the base fork, and the fix applied.

### src/incl/levels/getGJLevels.php (level search)
- **Vulnerability:** pagination was unbounded (`page` was multiplied straight into a `LIMIT ... OFFSET` clause), so a single request with a huge page number forced MySQL to scan and discard an enormous result set. Combined with the level name search, this allowed trivial CPU/database-exhaustion denial of service.
- **Why it was vulnerable:** no upper bound existed on the client-supplied offset.
- **Fix:** page is clamped to a server-defined maximum (`$maxPage` in `src/config/security.php`, default 1000 → offset 10000). Search strings are escaped for `LIKE` wildcards and truncated to 64 characters.

### src/incl/levels/uploadGJLevel.php (level upload)
- **Vulnerability:** the level data string (`levelString`) had no length limit, so a custom client could upload multi-megabyte payloads that were stored verbatim on disk and served to every other player (disk exhaustion / bandwidth abuse).
- **Why it was vulnerable:** the request body was trusted without any size check.
- **Fix:** `levelString` is now rejected above `$maxLevelLength` (default 512000 characters) in `src/config/security.php`. Existing protections kept: the request must contain the shared upload secret (`Wmfd2893gb7`) and a one-time verification key that was generated on the account beforehand.

### src/incl/scores/updateGJUserScore.php (stats / leaderboard update)
- **Vulnerability:** an unauthenticated custom client could report arbitrary stats (stars, demons, coins, user coins, diamonds, moons), forging the leaderboards. There was also no rate limit, so a script could flood the `actions` table and the weekly leaderboard logic.
- **Why it was vulnerable:** the reported values were written to `users` and `actions` with no validation and no frequency limit.
- **Fix:** every stat is capped by `$maxStatValues` in `src/config/security.php` (e.g. stars ≤ 1,000,000), and an account may only submit at most 5 score updates per 10 seconds (tracked via `actions` type 9).

### src/incl/misc/likeGJItem.php (level/comment likes)
- **Vulnerability:** the `type` parameter was taken from the request and used to pick the `$table` and `$column` in an `UPDATE`. Values outside the expected 1-4 left those variables undefined, which under PHP 8 is a fatal error (request fails) and could otherwise reach the wrong table. Likes were also accepted from any anonymous request, so a bot could mass-like levels/comments without an account.
- **Why it was vulnerable:** the type was never whitelisted before being used in SQL, and no authentication was required.
- **Fix:** `type` must now be numeric and in the 1-4 range before any table/column is selected. Likebot prevention: every like/dislike now requires a linked account — either `accountID` + GJP/GJP2 (newer clients) or a `udid` mapped to an account in `userLinks` (1.8 clients). Anonymous requests get `-1`.

### src/incl/comments/uploadGJComment.php (level comments)
- **Vulnerability:** two issues. (1) The level-completion percent update reused a query prepared for a `SELECT` and executed it with write parameters, producing "HY093: number of bound variables does not match" under native prepared statements — the update silently failed. (2) `percent` was stored without validation, so a cheated client could post completion percentages outside 0-100.
- **Why it was vulnerable:** mismatched statement reuse, and an unvalidated client value.
- **Fix:** the `UPDATE levelscores` statement is now bound separately with its own parameters, and `percent` is clamped to 0-100 (`min(max(...))`).

### src/incl/lib/commands.php (in-game chat commands)
- **Vulnerability:** the `!rate` command (available to moderators) accepted stars, coins and featured values straight from chat without validation, and omitted arguments caused undefined-index warnings on PHP 8. A mod could therefore set impossible ratings (e.g. 99,999 stars) and confuse the difficulty filter logic.
- **Why it was vulnerable:** missing input validation and missing defaults for command arguments.
- **Fix:** `!rate` now validates stars 0-10, coins 0-3 and featured 0/1 and replies with a usage error on bad input; missing arguments default via `?? ""`. (`!setacc` / `!sharecp` were also given undefined-index guards.)

### src/incl/misc/captchaGen.php (registration captcha)
- **Vulnerability:** the captcha code came from `rand()`, a predictable PRNG. An attacker could reproduce the sequence and bypass registration captcha.
- **Why it was vulnerable:** `rand()` output is cryptographically guessable.
- **Fix:** switched to `random_int()`.

### src/incl/lib/mainLib.php (song reupload / link nexus)
- **Vulnerability:** `getFileInfo()` / `songReupload()` performed a cURL fetch to an attacker-supplied URL. Redirects were followed with no protocol restriction and no response size cap, so a request like `file:///etc/passwd` (or a redirect to it) could read local files, and huge responses could exhaust memory. `setLinkNexusLevel()` wrote its argument straight into the PHP config file `config/linking.php`, which was PHP code injection into server configuration if a non-numeric value ever reached it.
- **Why it was vulnerable:** unconstrained cURL options and unvalidated input written into a PHP file.
- **Fix:** cURL is now restricted to http/https for both the initial request and redirects (`CURLOPT_PROTOCOLS`, `CURLOPT_REDIR_PROTOCOLS`) with a 50 MB cap (`CURLOPT_MAXFILESIZE`); reuploads must be audio content between 0 and 50 MB; `setLinkNexusLevel()` refuses non-numeric level IDs.

### src/tools/bot/* (Discord bot helper endpoints)
- **Vulnerability:** the bot endpoints (`levelSearchBot.php`, `songSearchBot.php`, `userLevelSearchBot.php`, `dailyLevelBot.php`, `latestSongBot.php`, `leaderboardsBot.php`, `modActionsBot.php`, `playerStatsBot.php`, `songAddBot.php`, `songListBot.php`, `whoRatedBot.php`) were publicly reachable with no authentication, so anyone could query server data or trigger bot-side actions.
- **Why it was vulnerable:** no token check before running.
- **Fix:** every bot endpoint now requires `?token=...` matching `$botSecret` (checked via `src/incl/lib/botCheck.php`). While `$botSecret` is empty in `src/config/security.php`, the endpoints are blocked entirely — set a long random value and pass it from your bot.

### src/config/connection.php (database layer)
- **Hardening:** the PDO connection now uses `utf8mb4`, enables exception mode, and disables prepared-statement emulation (`PDO::ATTR_EMULATE_PREPARES => false`) so any leftover string-interpolated SQL fails loudly instead of half-parsing. Note: native prepares require the `mysqlnd` driver; if your host lacks it, revert that one line to `true`.

### src/config/security.php (new hardening settings)
- `$botSecret` — shared token for all bot endpoints (see above).
- `$maxPage`, `$maxLevelLength`, `$maxSongsPerSearch`, `$maxStatValues` — caps backing the fixes above.
- `$allowedTargetServers` — whitelist of hosts that `src/tools/linkAcc.php` and `src/tools/levelToGD.php` are allowed to target, preventing server-side request abuse through those tools.

### Proxy/VPN blocking (src/incl/lib/blockProxyVPN.php)
- **Vulnerability:** anyone could reach the server through a free proxy or a VPN, making IP-based rate limits and bans (login brute-force, like limits, report limits) trivially bypassable.
- **Fix:** when `$blockFreeProxies` or `$blockCommonVPNs` is enabled in `src/config/security.php`, the client IP (Cloudflare/X-Forwarded-For aware) is checked on every request against:
  - free proxy IP lists (`$proxies` — fhgdps.com http/https/socks4/socks5/unknown), exact IP match;
  - VPN and datacenter CIDR lists (`$vpns` — X4BNet `vpn` and `datacenter` IPv4 ranges), covering free and paid VPN providers as well as paid proxies running on hosting IPs.
- Blocked requests get HTTP 403. Lists are cached in `src/data/proxycache/` (12h refresh, per-IP result cached 10 min) so downloads happen rarely; a download failure falls back to the stale cache and never blocks everyone. Localhost/private/reserved IPs are always allowed.

### Operational notes
- The above fixes assume a PHP 7.4+/8.x runtime with `mysqlnd`. After deploying, set `$botSecret` and test a level upload/comment/rate flow.
- Ownership checks on level deletion (`deleteGJLevelUser.php`), comment deletion (`deleteGJComment.php`) and reporting (`reportGJLevel.php`) were reviewed and were already safe (owner/moderator checks with prepared statements); no change was needed there.
