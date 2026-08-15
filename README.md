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
- **Vulnerability:** the captcha code came from `rand()`, a predictable PRNG, and was a 4-digit number (only 10,000 combinations). An attacker could reproduce the sequence or simply brute-force all combinations to bypass registration captcha.
- **Why it was vulnerable:** `rand()` output is cryptographically guessable, and a 4-digit space is trivially small.
- **Fix:** the code is now a random 6-character string (no `0/O`, `1/I/L`) generated character-by-character with `random_int()` (~1 billion combinations), rendered with noise lines. Captcha comparisons in `registerAccount.php` / `generateKey.php` are case-insensitive.

### src/incl/lib/mainLib.php (verification keys)
- **Vulnerability:** `randomString()`, used by `generateVerificationKey()` for account verification keys, still used `rand()`, a predictable PRNG. An attacker who could reproduce the sequence could forge a verification key and hijack an account link.
- **Why it was vulnerable:** `rand()` output is cryptographically guessable.
- **Fix:** `randomString()` now draws each character with `random_int()`.

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

## Security fixes (second pass)

### src/incl/scores/updateGJUserScore.php (stat floor + oversized IN-list)
- **Vulnerability:** two issues. (1) Negative stats (e.g. `stars=-100`) were accepted, so an account could be pushed far below zero; combined with the stats cap this still let a cheated client wreck its own leaderboard row. (2) `dinfo`/`sinfo` (demo/secret info) were stored unbounded and later splatted into `IN (...)` lists in `getGJComments.php` / `getGJUserList.php`, so an oversized value caused a massive SQL list (CPU/DB exhaustion).
- **Fix:** any reported stat below 0 is rejected (`-1`); `dinfo`/`sinfo` are truncated to 1000 characters.

### src/config/security.php (`$sessionGrants`)
- **Vulnerability:** with `$sessionGrants = true` (upstream default), a login response granted a 1-hour `isAdmin`/grant session where account actions were performed without the account's GJP — an attacker could obtain it once (e.g. via a leaked login) and impersonate the account for an hour without ever knowing the password.
- **Fix:** `$sessionGrants` now defaults to `false`, so every account action re-verifies the password (GJP) exactly as 1.8 clients behave.

### src/tools/stats/songList.php, src/incl/lib/mainLib.php `getSongString`, src/tools/bot/songAddBot.php (song metadata XSS/sanitization)
- **Vulnerability:** the song author name and size were echoed raw into an HTML table (`songList.php`), and were re-served raw in the level-response song string (`getSongString`). A custom client could upload a song whose name/author contained `</td><script>...` and execute JavaScript in the admin panel of any viewer (stored XSS).
- **Fix:** `songList.php` escapes author/size with `htmlspecialchars(... ENT_QUOTES)`. `getSongString` strips the GD protocol delimiters `# ~ : |` from the name and author name. `songAddBot.php` strips `#~:|` and truncates name/author to 64 chars.

### src/incl/lib/commands.php (verification-key comparison)
- **Vulnerability:** the 7 verification-key checks in the commands used a loose `==` comparison. PHP's loose comparison converts a numeric string to an integer, so a key like `0e123...` could be coerced; more importantly, string-to-int juggling could make mismatched keys compare equal.
- **Fix:** all 7 checks now use `hash_equals()` (constant-time, strict string compare).

### src/tools/account/generateKey.php (account enumeration + captcha replay)
- **Vulnerability:** three issues. (1) "This username is already in use." vs "Incorrect username-password combination." revealed which usernames exist. (2) The captcha session code was not cleared after use, so the same captcha image could be reused to automate the endpoint. (3) A valid/invalid password produced measurably different response times, allowing timing-based password guessing.
- **Fix:** captcha is validated first and the session code is unset; both failure branches return the identical "Incorrect username-password combination." message; a dummy `password_verify()` equalizes timing regardless of the account's actual hash.

### src/incl/lib/generatePass.php, mainLib.php (LIKE auth lookups)
- **Vulnerability:** account lookups used `userName LIKE :usr` / `userName LIKE '%usr%'`, so the SQL wildcard `_` in a username matched more than one row (multi-account collision / auth confusion).
- **Fix:** lookups now use `userName = :userName LIMIT 1`; extID lookups use `extID = BINARY :extID`.

### src/incl/lib/mainLib.php (permission column whitelist)
- **Vulnerability:** the `$permission` argument was interpolated directly into `SELECT $permission FROM roles ...` (`checkPermission`, `getMaxValuePermission`, `getAccountsWithPermission`, `checkModIPPermission`, `getAccountCommentColor`). Any caller-controlled value became SQL column injection.
- **Fix:** `validatePermission()` whitelists the argument against the known permission columns; invalid values fail closed. `roleIDlist` values are `(int)`-cast before being joined into `IN (...)`.

### src/tools/account/changePassword.php (cloud save encryption)
- **Vulnerability:** after changing the account password, the cloud save was written back to disk **in plaintext**, leaving the entire savegame (incl. any sensitive progress) readable by anyone with file access.
- **Fix:** the save is now decrypted with the old password and re-encrypted with the new password (via the defuse `KeyProtectedByPassword` wrapper), and the new protected key is stored. Plaintext is never written.

### src/tools/account/registerAccount.php (captcha replay)
- **Vulnerability:** the captcha session code was never invalidated on success or failure, so a single captcha solve could be replayed for unlimited automated registrations.
- **Fix:** the session code is unset once validated (both in `registerAccount.php` and `generateKey.php`).

### src/incl/comments/deleteGJComment.php (response bug)
- **Vulnerability:** the response flow echoed `-11`/`11` then fell through and echoed the result string again, producing a corrupted response for the game client and leaking the success/failure path.
- **Fix:** the flow now uses explicit early `exit()` with a single response string.

### Remaining SQL `IN (...)` lists (intval hardening)
- **Vulnerability:** several queries joined DB-sourced values into `IN (...)` lists without integer casting (`modActions.php` accounts list, `modActionsBot.php` account list, `getGJLevels.php` gauntlet levels / friends list), so a crafted DB value could inject SQL into the list.
- **Fix:** all list values are now `array_map('intval', ...)`-cast; the level-name `LIKE` search is bound via `:searchstr` placeholder instead of string interpolation.

### Session cookies (registerAccount.php, generateKey.php, captchaGen.php, userlist.php)
- **Vulnerability:** session cookies were set without `HttpOnly`/`Secure`/`SameSite`, so they could be stolen via XSS or CSRF and sent over plain HTTP.
- **Fix:** `session_set_cookie_params()` now sets `httponly`, `secure` (when HTTPS), and `samesite` (`Lax`/`Strict`) before `session_start()` in every session-using page.

### Reflected XSS in admin tools (src/tools/stats/*, src/tools/linkAcc.php, src/tools/levelToGD.php)
- **Vulnerability:** multiple admin-facing pages echoed DB data or upstream-server responses raw into HTML (`top24h.php`, `noLogIn.php`, `unlisted.php`, `dailyTable.php`, `packTable.php`, `modActions.php`, and the error/debug output of `linkAcc.php`/`levelToGD.php`), enabling stored/reflected XSS in the admin panel.
- **Fix:** all echoed dynamic values are wrapped in `htmlspecialchars(... ENT_QUOTES)`.

### Operational notes
- The above fixes assume a PHP 7.4+/8.x runtime with `mysqlnd`. After deploying, set `$botSecret` and test a level upload/comment/rate flow.
- Ownership checks on level deletion (`deleteGJLevelUser.php`), comment deletion (`deleteGJComment.php`) and reporting (`reportGJLevel.php`) were reviewed and were already safe (owner/moderator checks with prepared statements); no change was needed there.
