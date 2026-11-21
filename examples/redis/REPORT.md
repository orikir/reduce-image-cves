# CVE reduction report: `redis:7-bookworm`

Date: 2026-11-20 · grype 0.122.0, vulnerability DB built 2026-11-20T06:21Z · docker 29.8.0

**Goal:** cut the CVEs in `redis:7-bookworm` as far as possible without breaking Redis.

**Result:** **113 → 4 unique CVEs (−109, −96 %)**, no Critical or High left. Image size 167 MB → 79 MB. The new image passes all 38 functional checks (including mutual-TLS and TLS-version checks) in 3 runs each, the same as the original.
Final image: **`redis:7.4.12-wolfi-lowcve`**, built from `Dockerfile.wolfi`.

## 1. Results summary

| | Original | Candidate A: purge | **Final: Wolfi rebuild** | Change (orig → final) |
|---|---|---|---|---|
| Image | `redis@sha256:2e3eb114…172a90` (`redis:7-bookworm`) | `redis:7.4.12-purge` | `redis:7.4.12-wolfi-lowcve` (`sha256:085fb606…`) | |
| Base / OS | Debian 12.15 (bookworm) | Debian 12.15, stripped, `FROM scratch` | Wolfi (`cgr.dev/chainguard/wolfi-base@sha256:be019c1c…`), glibc 2.44 | |
| Redis | 7.4.12, jemalloc 5.3.0, TLS | same binaries as original | 7.4.12 rebuilt from the same tarball and SHA-256, same flags | same version |
| Packages installed | 89 | 6 | 22 (apk) | |
| Size (MB, uncompressed) | 167.3 | 67.3 | 79.3 | −53 % |
| Critical | 1 | 1 | **0** | −1 |
| High | 21 | 7 | **0** | −21 |
| Medium | 42 | 14 | **1** | −41 |
| Low | 13 | 7 | **3** | −10 |
| Negligible | 36 | 10 | **0** | −36 |
| **Total unique CVEs** | **113** | **39** | **4** | **−109** |
| Package matches (raw grype rows) | 238 | 39 | 4 | |
| Tests passed (38 checks × 3 runs) | 114/114 | 114/114 | 114/114 | no regressions |

Key outcomes:
- **Approach 1, remove unused packages: 113 → 39.** Redis only needs `libc6` and `libssl3` at runtime, plus `/bin/sh` for its entrypoint. Dropping the other 83 packages removed util-linux, PAM, perl, systemd libs, gnupg, gnutls, ncurses, tar and their CVEs.
- **Approach 2, rebuild on a smaller, fresher base: 113 → 4.** All 30 glibc CVEs in Debian's glibc 2.36 are marked `wont-fix` or `not-fixed`, and the 5 OpenSSL 3.0 CVEs have no fix in bookworm. Package removal cannot touch them. Rebuilding the same Redis 7.4.12 on Wolfi (glibc 2.44, OpenSSL 3.6) removed them.
- **Approach 3, upgrade packages that have a fix:** `apk upgrade` in the final image. On the baseline it could not help, because 0 of 113 CVEs had a fixed Debian package. On Wolfi it keeps every package at its newest patched version at build time.
- **Nothing new was introduced:** 0 CVEs appear in the final image that were not in the original.
- **Remaining 4:** 2 in Redis's own code, matched by NVD CPE and low-impact, and 2 in glibc 2.44, published in November 2026 with no upstream fix yet. See §5.

## 1a. Where the CVEs come from, and the plan

All 113 baseline CVEs come from **OS packages**, except 2 that are matched against the Redis binary itself. Grouped by Debian source package:

| Source package (binary packages) | CVEs | C | H | M | L | N | Why it is in the image | Plan |
|---|---|---|---|---|---|---|---|---|
| glibc (libc-bin, libc6) | 30 | 1 | 4 | 13 | 5 | 7 | C library | Needed by redis (libc, libm). Debian 2.36 fixes: none (wont-fix/not-fixed) -> switch base to Wolfi glibc 2.44 |
| gnutls28 (libgnutls30) | 9 |  |  | 3 |  | 6 | apt (https) | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| util-linux (bsdutils, libblkid1, libmount1, libsmartcols1, libuuid1, mount, util-linux, util-linux-extra) | 8 |  | 3 | 3 |  | 2 | setpriv in entrypoint + base system | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| gcc-12 (gcc-12-base, libgcc-s1, libstdc++6) | 7 |  | 2 | 3 | 1 | 1 | C/C++ runtime of base system | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| systemd (libsystemd0, libudev1) | 7 |  |  | 2 | 1 | 4 | libs pulled by util-linux/apt | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| coreutils (coreutils) | 5 |  |  |  | 1 | 4 | base system / entrypoint (id, chown) | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| gnupg2 (gpgv) | 5 |  |  | 2 | 2 | 1 | apt signature check | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| openssl (libssl3) | 5 |  | 3 | 1 |  | 1 | TLS for redis | Needed for TLS. Debian 3.0 has no fixes -> switch base (Wolfi OpenSSL 3.6) |
| perl (perl-base) | 5 |  | 2 | 1 |  | 2 | debconf/dpkg scripts | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| tar (tar) | 4 |  |  | 3 |  | 1 | dpkg | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| ncurses (libtinfo6, ncurses-base, ncurses-bin) | 3 |  | 1 | 2 |  |  | bash/terminal | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| pam (libpam-modules, libpam-modules-bin, libpam-runtime, libpam0g) | 3 |  | 1 | 2 |  |  | login/passwd | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| acl (libacl1) | 2 |  | 2 |  |  |  | coreutils | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| dash (dash) | 2 |  |  |  |  | 2 | /bin/sh | /bin/sh for entrypoint; kept in A, replaced by busybox on Wolfi |
| gzip (gzip) | 2 |  | 1 | 1 |  |  | base system | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| libgcrypt20 (libgcrypt20) | 2 |  |  |  |  | 2 | apt/gpgv | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| p11-kit (libp11-kit0) | 2 |  |  | 2 |  |  | gnutls | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| redis (redis) | 2 |  |  |  | 2 |  | the application | The app itself; NVD CPE match, no upstream 7.4.x fix -> accept / mitigate |
| shadow (login, passwd) | 2 |  |  |  | 1 | 1 | useradd at build time | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| zlib (zlib1g) | 2 |  | 1 | 1 |  |  | dpkg/apt | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| apt (apt, libapt-pkg6.0) | 1 |  |  |  |  | 1 | package manager | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| attr (libattr1) | 1 |  |  | 1 |  |  | coreutils | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| bzip2 (libbz2-1.0) | 1 |  |  | 1 |  |  | dpkg | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| diffutils (diffutils) | 1 |  |  |  |  | 1 | base system | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| dpkg (dpkg) | 1 |  |  | 1 |  |  | package manager | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |
| libtasn1-6 (libtasn1-6) | 1 |  | 1 |  |  |  | gnutls | Not used by redis at runtime -> remove package (approach 1) / absent from Wolfi image |

**Plan derived from this table:**
1. **Upgrade what has a fix.** Nothing qualifies: 0/113 CVEs have a fixed Debian 12 package (62 not-fixed, 49 wont-fix, 2 unknown). Step skipped on Debian; applied on the new base (`apk upgrade`).
2. **Remove what Redis does not use (approach 1).** 22 of the 26 source packages (all except glibc, openssl, dash and redis itself) are only needed by apt/dpkg, the login tools, the shell utilities or the official entrypoint's root→`setpriv` step. Redis links only `libc`, `libm`, `libssl` and `libcrypto` (`ldd`). Removing them is expected to clear 74 CVEs. Result: 74.
3. **Replace what Redis does use but Debian won't fix (approach 2).** glibc (30) and OpenSSL (5) can't be removed. A base with current glibc/OpenSSL (Wolfi) plus a source rebuild of the same Redis 7.4.12 is expected to clear them. Result: 35 more (all 30 glibc + all 5 OpenSSL CVEs, and dash's 2).
4. **Assess what is left by hand** (§5): the Redis binary's 2 CVEs, plus anything the new base still reports.

## 2. Final Dockerfile

`Dockerfile.wolfi` (uses `files/docker-entrypoint.sh`, shown below it):

```dockerfile
# Redis 7.4.12 rebuilt from the official source on Wolfi (fresh glibc + OpenSSL), TLS enabled like the official image.
ARG BASE=cgr.dev/chainguard/wolfi-base@sha256:be019c1c74fe69204a42c4e10bc4d886a49bf5403ffa74374ef7baa408fc9a26

FROM ${BASE} AS build
RUN apk add --no-cache build-base linux-headers openssl-3.6-dev
ADD --checksum=sha256:324ab63d55c607639b419f547b213c62ae39ff50e09870e450a11c272567b84f \
    https://github.com/redis/redis/archive/refs/tags/7.4.12.tar.gz /redis.tar.gz
WORKDIR /src
# Same patch as the official image: protected-mode off, so other containers can connect.
RUN tar -xzf /redis.tar.gz --strip-components=1 \
 && sed -i 's/\("protected-mode",.*, *\)1\( *,\)/\10\2/' src/config.c \
 && grep -q '"protected-mode",.*, *0 *,' src/config.c \
 && make -j"$(nproc)" BUILD_TLS=yes \
 && make PREFIX=/out install \
 && rm /out/bin/redis-benchmark

FROM ${BASE}
RUN apk upgrade --no-cache \
 && apk add --no-cache so:libssl.so.3 so:libcrypto.so.3 tzdata \
 && addgroup -S -g 999 redis \
 && adduser -S -D -H -u 999 -G redis -s /sbin/nologin redis \
 && install -d -o redis -g redis /data
COPY --from=build /out/bin/ /usr/local/bin/
COPY --chmod=755 files/docker-entrypoint.sh /usr/local/bin/
ENV REDIS_VERSION=7.4.12
WORKDIR /data
VOLUME /data
USER redis
EXPOSE 6379
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["redis-server"]
```

`files/docker-entrypoint.sh`:

```sh
#!/bin/sh
# Minimal entrypoint: same argument handling and umask as the official one,
# but the image already runs as the unprivileged "redis" user (USER redis),
# so the root -> setpriv/chown branch (util-linux, findutils, coreutils) is not needed.
set -e
if [ "${1#-}" != "$1" ] || [ "${1%.conf}" != "$1" ]; then
	set -- redis-server "$@"
fi
um="$(umask)"
if [ "$um" = '0022' ]; then
	umask 0077
fi
exec "$@"
```

Build and run: `docker build -f Dockerfile.wolfi -t redis:7.4.12-wolfi-lowcve .` then `docker run -d -p 6379:6379 redis:7.4.12-wolfi-lowcve`.

## 3. How we did it

### Analysis of the original

- **Inventory:** Debian 12.15, 89 packages, Redis 7.4.12 compiled into `/usr/local/bin`. `ldd redis-server` shows only `libc.so.6`, `libm.so.6`, `libssl.so.3` and `libcrypto.so.3`. The entrypoint additionally uses `sh`, `find`, `chown`, `id` and `setpriv`.
- **Counting:** the scan has 238 grype rows but 113 unique CVEs. One CVE is reported once per binary package built from the same source. For example, each util-linux CVE appears 8 times (util-linux, mount, bsdutils, libblkid1, libmount1, libsmartcols1, libuuid1, util-linux-extra), and each glibc CVE twice (libc6, libc-bin). All figures in this report are unique CVE IDs.
- **Fix status of the 113:** 62 `not-fixed`, 49 `wont-fix`, 2 `unknown`, **0 fixed**. So `apt-get upgrade` cannot remove a single one. The only levers are removing packages or changing the base.
- **Where they live:** glibc 30, util-linux 8, gcc-12 runtime libs 7, systemd libs 7, gnutls 9, perl 5, OpenSSL 5, PAM 4, plus about 30 more spread over tar, gzip, coreutils, ncurses, gnupg and others. Only glibc, OpenSSL and the Redis binary itself are actually used by Redis.

### Approaches

1. **Remove unneeded packages, then flatten (`Dockerfile.purge`).** Starts from the original image (pinned by digest), keeps `base-files base-passwd libc6 libssl3 dash tzdata`, purges everything else with dpkg, and copies the result into `FROM scratch`. The scanner sees exactly what is left, because dpkg removed both the files and their status entries. Result: 39.
2. **Smaller and fresher base with a multi-stage source build (`Dockerfile.wolfi`).** Builds Redis 7.4.12 from the same upstream tarball (SHA-256 verified) with the official image's TLS build (`BUILD_TLS=yes`) and its protected-mode patch. The official image also passes jemalloc page sizes by hand (`--with-lg-page=12 --with-lg-hugepage=21`); I left that out because jemalloc detects the same values on an x86_64 build machine (on 64K-page arm64 hosts, add the flags back). Only `redis-server`, `redis-cli` and the `make install` symlinks go into the runtime image. Result: 4.
3. **Upgrade packages with available fixes:** `apk upgrade --no-cache` in the runtime stage.

Base images evaluated before choosing (unique CVEs of the bare base, same DB): `wolfi-base` 2, `chainguard/glibc-dynamic`, `distroless base-debian12/13`, `debian:trixie-slim`, `alpine:3.22/3.23` and `redis:7-alpine` (scans in `scans/bases/`). Alpine (musl) gave 8 in an earlier attempt. Wolfi keeps glibc, which matches the original's runtime, and scored lowest.

### Tools and settings

- Tools: docker 29.8.0, grype 0.122.0 (DB built 2026-11-20T06:21Z) and `summarize_scan.py`. syft was not used, because grype's built-in cataloguer was enough.
- The baseline and all candidates were scanned with the same DB build.
- **Note on 114 vs 113:** an earlier scan of the same digest on the 2026-11-19 DB showed 114 unique CVEs (24 High). Between the two DB builds, 6 libssl3 CVEs dropped out: 4 High (CVE-2026-124709, -95691, -95692, -88823) and 2 Medium (CVE-2026-88822, -35190). Most of them concern QUIC and AES-GCM-SIV, which OpenSSL 3.0 doesn't ship. 5 new CVEs arrived (CVE-2026-84786 High; CVE-2026-127039, -127040, -127231 Medium; CVE-2026-126765 Low). The image did not change; only the vulnerability data did.

## 4. Steps

| # | Change tried | Unique CVEs after | Change vs baseline | Tests | Kept? | Why |
|---|---|---|---|---|---|---|
| 0 | Baseline `redis:7-bookworm` | 113 | — | 114/114 | — | reference |
| 1 | `apt-get upgrade` of packages with fixes | 113 | 0 | — | No | 0 of 113 CVEs have a fixed Debian 12 package |
| 2 | Purge all non-runtime packages + flatten (`Dockerfile.purge`) | 39 | −74 | 114/114 | Kept as fallback | Same binaries; remaining CVEs are in glibc 2.36 / OpenSSL 3.0, which Redis needs |
| 2a | Same, first attempt (plain `dpkg --purge`) | — | — | — | Fixed | Removal scripts failed once perl and coreutils were gone; skipped them, see §6 |
| 3 | Rebuild Redis 7.4.12 on `wolfi-base` + `apk upgrade` (`Dockerfile.wolfi`) | **4** | **−109** | 114/114 | **Yes, final** | Current glibc/OpenSSL; nothing new introduced |
| — | Static binary on `distroless/static` (0 CVEs reported) | not built | — | — | No | Statically linked glibc/OpenSSL would be invisible to the scanner: fewer CVEs reported, not fewer CVEs |

## 5. Remaining risks (final image)

| CVE | Package | Severity | Fix status | Fix coming? (source, checked 2026-11-20) | Decision | Mitigation |
|---|---|---|---|---|---|---|
| CVE-2026-115819 | glibc 2.44-r24 | Medium (4.8) | no fix upstream yet | Published 2026-11-11 (GLIBC-SA-2026-0027). Debian and Amazon list it as unfixed/pending. Wolfi usually ships glibc fixes within days. | **Upgrade when available** | Affects only *wide* scanf (`swscanf`, `fwscanf`…) writing `%s`/`%[` into a narrow char buffer. Redis does not use the wide scanf family, so the code path is not reachable. |
| CVE-2026-100290 | glibc 2.44-r24 | Low (3.7) | no fix upstream yet | GLIBC-SA-2026-0028; no fixed release yet | **Upgrade when available** | Double free in `regcomp`/`regexec` only when a memory allocation fails, i.e. under memory pressure. Redis does not call POSIX regex. Set `maxmemory` and a container memory limit. |
| CVE-2025-46686 | redis 7.4.12 (binary) | Low (3.5) | disputed by Redis | Redis states that abusing the protocol by an authenticated client is outside its security model. Vendor entries put a fix in 8.0.3+; no 7.4.x fix. | **Accepted risk** | Needs an authenticated client. Require a password/ACL (`requirepass` or ACL users), do not expose 6379 publicly, set `maxmemory` and `client-query-buffer-limit`. |
| CVE-2025-49112 | redis 7.4.12 (binary) | Low (3.1) | no upstream Redis fix | The CVE names Valkey (`setDeferredReply` underflow, fixed in Valkey 8.1.2). Redis upstream treats it as hardening. Debian lists redis as unfixed; some vendors backport a patch. | **Accepted risk**; upgrade Redis when 7.4.x or 8.x carries the change | Grype matches every Redis version by CPE ("none" constraint). Same network controls as above. |

Container-level mitigations already in place: the server runs as uid 999 (not root), there is no package manager use at runtime, only `redis-server` and `redis-cli` are installed, and `/data` is the only writable path needed. Recommended at deploy time: `--read-only` with `/data` as a volume, `--cap-drop ALL`, `--security-opt no-new-privileges` and a network policy that limits 6379 to clients.

**Rescan plan:** scan in CI on every build and weekly with a fresh grype DB. Fail the build on any new Critical/High, and on any CVE that has a fix available. Rebuild weekly so `apk upgrade` picks up Wolfi fixes; the two glibc CVEs should drop out once Wolfi ships the patched glibc. Track Redis 7.4.x releases for the two Redis CVEs, and consider moving to Redis 8.x.


### Next steps and priorities

| Priority | Action | Resolves | When |
|---|---|---|---|
| 1 | Deploy with network controls: `requirepass`/ACL users, 6379 reachable only by clients, `maxmemory` + container memory limit, `client-query-buffer-limit` | Exposure to CVE-2025-46686 / -49112 (need network access + auth) and CVE-2026-100290 (memory pressure) | now |
| 2 | Runtime hardening: `--read-only` with `/data` volume, `--cap-drop ALL`, `--security-opt no-new-privileges` | Limits impact of any future Redis bug | now |
| 3 | Rebuild weekly (`docker build --pull`) so `apk upgrade` picks up the patched Wolfi glibc | CVE-2026-115819, CVE-2026-100290 | as soon as Wolfi ships glibc with GLIBC-SA-2026-0027/0028 fixes |
| 4 | CI gate: grype on every build + weekly with fresh DB; fail on new Critical/High or any CVE with a fix available | Regressions / new CVEs | ongoing |
| 5 | Track Redis 7.4.x releases; evaluate Redis 8.x (CVE-2025-46686 is listed as fixed in 8.0.3+) and backport the `setDeferredReply` hardening patch if needed | CVE-2025-46686, CVE-2025-49112 | next Redis upgrade |
| 6 | Optional further shrink: drop `apk-tools`/`busybox` in a final `FROM scratch`-style stage (0 CVEs today, smaller attack surface) | attack surface, size | nice to have |

### Behaviour differences from the official image

- **Always runs as `redis` (uid 999).** The official entrypoint starts as root, `chown`s `/data` and drops to `redis` with `setpriv`. That needs util-linux, findutils and coreutils, which carry 10+ CVEs, so it was removed. If you bind-mount a host directory, make it writable by uid 999 (`chown 999:999 <dir>`). A named Docker volume works as is: the image's `/data` is already owned by `redis`, and the tests confirm it.
- **`--user 0` / `--user root`** now runs Redis as root instead of dropping privileges. Don't do that.
- **`redis-benchmark` is not included.** It's a load-testing tool, not part of the server.
- **No `bash`/coreutils in the purge image** (the Wolfi image has busybox). `docker exec … sh` still works in both.

## 6. Test plan and results

**What "working correctly" means:** the new image must behave like the original for everything a Redis user relies on. That means the same version, it starts and serves commands, it persists data, it can be reached over the network by name, TLS works, it shuts down cleanly, and it runs unprivileged. `tests/redis_test.sh` checks all of these with exact expected values. It waits for readiness by polling `PING` (no fixed sleeps), uses a fresh container and volume per run, cleans up with `trap`, and runs **3 times per image**. Results go to `tests/<label>.tsv`. A check that passes on the original but fails on a candidate blocks that candidate.

**38 checks per run, 3 runs per image.** Every cell below is runs passed / 3.

| # | Check | How (exact expected value) | Original | Purge | **Final (Wolfi)** |
|---|---|---|---|---|---|
| | **Image and process** | | | | |
| 1 | version | `redis-server --version` contains `v=7.4.12` | 3/3 | 3/3 | 3/3 |
| 2 | startup_ready | default CMD, `PING` → `PONG` within 30 s (polled) | 3/3 | 3/3 | 3/3 |
| 3 | runs_as_uid_999 | `docker top`: redis-server uid = 999 | 3/3 | 3/3 | 3/3 |
| 4 | jemalloc | `INFO memory` → `mem_allocator:jemalloc-5.3.0` | 3/3 | 3/3 | 3/3 |
| | **Commands and data types** | | | | |
| 5 | set_get | `SET k1 hello` / `GET` → `OK hello` | 3/3 | 3/3 | 3/3 |
| 6 | update_key | `SET k2 first`, `SET k2 updated`, `GET` → `updated` | 3/3 | 3/3 | 3/3 |
| 7 | exists | `EXISTS k2` → 1 | 3/3 | 3/3 | 3/3 |
| 8 | append | `APPEND k2 " world"` → `updated world` | 3/3 | 3/3 | 3/3 |
| 9 | incr | 3× `INCR n` → 3 | 3/3 | 3/3 | 3/3 |
| 10 | decr | `SET counter 10`, `INCR`, 2× `DECR` → 9 | 3/3 | 3/3 | 3/3 |
| 11 | del | `DEL k2`, `EXISTS` → 0 | 3/3 | 3/3 | 3/3 |
| 12 | list | `RPUSH`/`LRANGE` → a,b,c | 3/3 | 3/3 | 3/3 |
| 13 | sets | `SADD` apple banana orange; `SISMEMBER apple`=1, `grape`=0, `SCARD`=3 | 3/3 | 3/3 | 3/3 |
| 14 | hash | `HSET`/`HGET` | 3/3 | 3/3 | 3/3 |
| 15 | sorted_set | `ZADD`/`ZRANGE` → one,two | 3/3 | 3/3 | 3/3 |
| 16 | expire_ttl | `SET … EX 100`, `TTL` > 0 | 3/3 | 3/3 | 3/3 |
| 17 | expired_key_nil | `SET tmp v EX 1`, poll until `GET` → nil (expired after ≈300 ms; 5 s limit) | 3/3 | 3/3 | 3/3 |
| 18 | dbsize | `DBSIZE` → exactly 8 (k1 n l h z e counter s) | 3/3 | 3/3 | 3/3 |
| 19 | lua_eval | `EVAL "return redis.call('get',KEYS[1])"` → hello | 3/3 | 3/3 | 3/3 |
| | **Network, persistence, lifecycle** | | | | |
| 20 | dns_network_client | 2nd container: `redis-cli -h redis-svc ping` over a user network | 3/3 | 3/3 | 3/3 |
| 21 | save_rdb | `SAVE` → OK (`/data` writable by uid 999) | 3/3 | 3/3 | 3/3 |
| 22 | final_ping | `PING` → PONG after all operations | 3/3 | 3/3 | 3/3 |
| 23 | graceful_stop | `docker stop` < 10 s, exit code 0 (measured 0.60–0.88 s) | 3/3 | 3/3 | 3/3 |
| 24 | shutdown_log | log contains `ready to exit` | 3/3 | 3/3 | 3/3 |
| 25 | no_errors_in_log | no fatal / segfault / crash lines | 3/3 | 3/3 | 3/3 |
| 26 | persistence_restart | new container on the same volume reads the keys back | 3/3 | 3/3 | 3/3 |
| 27 | args_and_aof | `docker run IMG --appendonly yes --maxmemory 10mb` applied | 3/3 | 3/3 | 3/3 |
| | **TLS** (TLS-only server, `--port 0`, client certificates required) | | | | |
| 28 | tls_ping | `redis-cli --tls` with trusted client cert → PONG | 3/3 | 3/3 | 3/3 |
| 29 | tls_set_get | `SET`/`GET` over TLS → tls-value | 3/3 | 3/3 | 3/3 |
| 30 | tls_plaintext_port_disabled | plain `redis-cli -p 6379` → refused | 3/3 | 3/3 | 3/3 |
| 31 | tls_plaintext_client_rejected | plain client on the TLS port → refused | 3/3 | 3/3 | 3/3 |
| 32 | tls_no_client_cert_rejected | TLS client without a certificate → refused | 3/3 | 3/3 | 3/3 |
| 33 | tls_rogue_client_cert_rejected | client cert signed by an untrusted CA → refused | 3/3 | 3/3 | 3/3 |
| 34 | tls_untrusted_server_rejected | client trusting only the rogue CA refuses the server | 3/3 | 3/3 | 3/3 |
| 35 | tls13_handshake | host `openssl s_client -tls1_3` → `TLSv1.3` | 3/3 | 3/3 | 3/3 |
| 36 | tls12_handshake | host `openssl s_client -tls1_2` → `TLSv1.2` | 3/3 | 3/3 | 3/3 |
| 37 | tls11_rejected | host `openssl s_client -tls1_1` → no handshake | 3/3 | 3/3 | 3/3 |
| 38 | tls_final_ping | server still answers after the failed handshakes | 3/3 | 3/3 | 3/3 |
| | **Total** | | **114/114** | **114/114** | **114/114** |

Run them: `bash steps/run-tests.sh`, or for one image `IMAGE=<img> LABEL=<name> RUNS=3 bash tests/redis_test.sh`.

**Independent cross-check:** `tests/compare_test.sh`, a separate test script with 27 checks per image (data operations, expiry, SAVE, DBSIZE and the same TLS positive/negative/protocol tests), was also run unchanged with `ORIGINAL=redis:7-bookworm` and `SECURED=redis:7.4.12-wolfi-lowcve`. Result: **27/27 on each image, "ALL TESTS PASSED ON BOTH IMAGES!"** (`tests/compare_test_results.txt`, `tests/compare_test.log`). Every check in that script is also in `redis_test.sh` (rows 2, 5–18, 21–22, 28–38).

## 7. Challenges and lessons learned

- **Count unique CVEs, not rows.** Grype reported 238 rows for 113 CVEs. Removing one source package such as util-linux removes 8 rows but only 8 CVEs, not 64.
- **The vulnerability DB changes daily.** The same image showed 114 on 11-19 and 113 on 11-20. Before and after must be scanned with the same DB, and the DB date belongs in the report.
- **"Upgrade" was the obvious first move and did nothing.** Every finding in bookworm was `not-fixed` or `wont-fix`. Reading the fix-state column first saved time.
- **Removing essential packages breaks dpkg's own removal scripts,** because they call perl, coreutils and the PAM tools that are being removed. Plain `dpkg --purge` left packages half-removed, and those stay visible to the scanner. Deleting the `prerm`/`postrm` scripts of the dropped packages first gave a clean removal. Coreutils commands (`chmod`, `rm`) also had to run *before* the purge.
- **Don't hide CVEs.** A static binary on `distroless/static` scans as 0, but only because the scanner can't see the glibc and OpenSSL linked inside. The Wolfi build installs `libssl`/`libcrypto` as real apk packages so they stay visible and patchable.
- **Keep the official build behaviour, not necessarily its exact lines.** Rebuilding from source is only a fair comparison if the binary behaves the same: TLS, jemalloc and protected-mode. The first version of `Dockerfile.wolfi` copied the official build line for line (46 lines). The simplified one (31 lines) uses `ADD --checksum`, a single `make`/`make install`, and drops the jemalloc page-size flags, which jemalloc detects itself on x86_64. Same 4 CVEs, same 114/114 test results. The jemalloc and TLS checks in §6 verify it.
- **Environment issues.** The tools ran in WSL with Docker installed as a snap. Snap confinement hides `/tmp` from the Docker daemon (the TLS test certificates had to move to `$HOME`). A wrong `~/snap` permission (`drw-r--r--`) broke the docker client after a snap refresh and was reset to 755.
- **Purge image caveat:** `libgcc-s1` was removed. Redis doesn't link it, but glibc loads `libgcc_s` on demand for `pthread_cancel`, which Redis only uses while killing threads during crash reporting. The Wolfi image keeps `libgcc`, so it is not affected.

## Appendix A: Files

| Path | Content |
|---|---|
| `Dockerfile.wolfi`, `files/docker-entrypoint.sh` | final image |
| `Dockerfile.purge` | approach 1 candidate |
| `scans/baseline.json`, `scans/candidate-purge.json`, `scans/final.json` | raw grype output (same DB) |
| `summaries/baseline.txt`, `candidate-*.txt`, `compare.txt`, `compare-purge.txt` | summaries / before-after |
| `summaries/baseline.csv`, `summaries/final.csv` | one row per CVE × package |
| `tests/redis_test.sh`, `tests/{original,purge,wolfi}.tsv` | test script and per-run results |
| `tests/compare_test.sh`, `tests/compare_test_results.txt` | independent comparison test and its results |
| `steps/*.sh`, `steps/*.py` | every command run, as scripts |

## Appendix B: CVE lists

### Final image (4)

| CVE | Severity | Package | Matched via |
|---|---|---|---|
| CVE-2026-115819 | Medium | glibc-2.44 2.44-r24 | NVD CPE (≥2.2, ≤2.44) |
| CVE-2026-100290 | Low | glibc-2.44 2.44-r24 | NVD CPE (≥2.3, ≤2.44) |
| CVE-2025-46686 | Low | redis 7.4.12 (binary) | NVD CPE (≤8.0.3) |
| CVE-2025-49112 | Low | redis 7.4.12 (binary) | NVD CPE (all versions) |

### Full list: every baseline CVE and what happened to it

Legend: **A** = removed by package removal (`Dockerfile.purge`), **B** = removed by the Wolfi rebuild (gone from final, still present after A), **remains** = still in final image.

| # | CVE | Severity | Source package | Fix state (Debian) | After A (purge) | Final (Wolfi) |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-5450 | Critical | glibc | wont-fix | present | **removed (B)** |
| 2 | CVE-2026-54369 | High | acl | wont-fix | **removed (A)** | removed (A) |
| 3 | CVE-2026-54370 | High | acl | wont-fix | **removed (A)** | removed (A) |
| 4 | CVE-2026-102010 | High | gcc-12 | wont-fix | **removed (A)** | removed (A) |
| 5 | CVE-2026-95619 | High | gcc-12 | wont-fix | **removed (A)** | removed (A) |
| 6 | CVE-2026-19499 | High | glibc | wont-fix | present | **removed (B)** |
| 7 | CVE-2026-5435 | High | glibc | wont-fix | present | **removed (B)** |
| 8 | CVE-2026-5928 | High | glibc | wont-fix | present | **removed (B)** |
| 9 | CVE-2026-84243 | High | glibc | not-fixed | present | **removed (B)** |
| 10 | CVE-2026-41992 | High | gzip | wont-fix | **removed (A)** | removed (A) |
| 11 | CVE-2025-13151 | High | libtasn1-6 | wont-fix | **removed (A)** | removed (A) |
| 12 | CVE-2025-69720 | High | ncurses | wont-fix | **removed (A)** | removed (A) |
| 13 | CVE-2026-107493 | High | openssl | not-fixed | present | **removed (B)** |
| 14 | CVE-2026-107496 | High | openssl | not-fixed | present | **removed (B)** |
| 15 | CVE-2026-84786 | High | openssl | not-fixed | present | **removed (B)** |
| 16 | CVE-2025-6020 | High | pam | not-fixed | **removed (A)** | removed (A) |
| 17 | CVE-2026-82560 | High | perl | wont-fix | **removed (A)** | removed (A) |
| 18 | CVE-2026-9538 | High | perl | wont-fix | **removed (A)** | removed (A) |
| 19 | CVE-2026-53613 | High | util-linux | not-fixed | **removed (A)** | removed (A) |
| 20 | CVE-2026-53615 | High | util-linux | not-fixed | **removed (A)** | removed (A) |
| 21 | CVE-2026-78410 | High | util-linux | not-fixed | **removed (A)** | removed (A) |
| 22 | CVE-2026-85091 | High | zlib | not-fixed | **removed (A)** | removed (A) |
| 23 | CVE-2026-54371 | Medium | attr | wont-fix | **removed (A)** | removed (A) |
| 24 | CVE-2026-42250 | Medium | bzip2 | wont-fix | **removed (A)** | removed (A) |
| 25 | CVE-2026-91094 | Medium | dpkg | not-fixed | **removed (A)** | removed (A) |
| 26 | CVE-2026-114690 | Medium | gcc-12 | wont-fix | **removed (A)** | removed (A) |
| 27 | CVE-2026-114691 | Medium | gcc-12 | wont-fix | **removed (A)** | removed (A) |
| 28 | CVE-2026-125709 | Medium | gcc-12 | not-fixed | **removed (A)** | removed (A) |
| 29 | CVE-2026-115819 | Medium | glibc | not-fixed | present | **remains** |
| 30 | CVE-2026-121757 | Medium | glibc | not-fixed | present | **removed (B)** |
| 31 | CVE-2026-121758 | Medium | glibc | not-fixed | present | **removed (B)** |
| 32 | CVE-2026-124024 | Medium | glibc | not-fixed | present | **removed (B)** |
| 33 | CVE-2026-18374 | Medium | glibc | wont-fix | present | **removed (B)** |
| 34 | CVE-2026-19542 | Medium | glibc | wont-fix | present | **removed (B)** |
| 35 | CVE-2026-6238 | Medium | glibc | wont-fix | present | **removed (B)** |
| 36 | CVE-2026-6791 | Medium | glibc | wont-fix | present | **removed (B)** |
| 37 | CVE-2026-77117 | Medium | glibc | wont-fix | present | **removed (B)** |
| 38 | CVE-2026-80489 | Medium | glibc | wont-fix | present | **removed (B)** |
| 39 | CVE-2026-8674 | Medium | glibc | wont-fix | present | **removed (B)** |
| 40 | CVE-2026-86805 | Medium | glibc | not-fixed | present | **removed (B)** |
| 41 | CVE-2026-89092 | Medium | glibc | wont-fix | present | **removed (B)** |
| 42 | CVE-2025-30258 | Medium | gnupg2 | wont-fix | **removed (A)** | removed (A) |
| 43 | CVE-2025-68972 | Medium | gnupg2 | wont-fix | **removed (A)** | removed (A) |
| 44 | CVE-2026-127039 | Medium | gnutls28 | not-fixed | **removed (A)** | removed (A) |
| 45 | CVE-2026-127040 | Medium | gnutls28 | not-fixed | **removed (A)** | removed (A) |
| 46 | CVE-2026-127231 | Medium | gnutls28 | not-fixed | **removed (A)** | removed (A) |
| 47 | CVE-2026-41991 | Medium | gzip | wont-fix | **removed (A)** | removed (A) |
| 48 | CVE-2023-50495 | Medium | ncurses | wont-fix | **removed (A)** | removed (A) |
| 49 | CVE-2025-6141 | Medium | ncurses | wont-fix | **removed (A)** | removed (A) |
| 50 | CVE-2026-95690 | Medium | openssl | not-fixed | present | **removed (B)** |
| 51 | CVE-2026-13757 | Medium | p11-kit | wont-fix | **removed (A)** | removed (A) |
| 52 | CVE-2026-18938 | Medium | p11-kit | wont-fix | **removed (A)** | removed (A) |
| 53 | CVE-2024-10041 | Medium | pam | wont-fix | **removed (A)** | removed (A) |
| 54 | CVE-2026-54411 | Medium | pam | wont-fix | **removed (A)** | removed (A) |
| 55 | CVE-2026-15534 | Medium | perl | wont-fix | **removed (A)** | removed (A) |
| 56 | CVE-2026-15059 | Medium | systemd | wont-fix | **removed (A)** | removed (A) |
| 57 | CVE-2026-16742 | Medium | systemd | wont-fix | **removed (A)** | removed (A) |
| 58 | CVE-2026-18477 | Medium | tar | wont-fix | **removed (A)** | removed (A) |
| 59 | CVE-2026-18508 | Medium | tar | wont-fix | **removed (A)** | removed (A) |
| 60 | CVE-2026-5704 | Medium | tar | wont-fix | **removed (A)** | removed (A) |
| 61 | CVE-2026-13595 | Medium | util-linux | not-fixed | **removed (A)** | removed (A) |
| 62 | CVE-2026-27456 | Medium | util-linux | wont-fix | **removed (A)** | removed (A) |
| 63 | CVE-2026-3184 | Medium | util-linux | wont-fix | **removed (A)** | removed (A) |
| 64 | CVE-2026-27171 | Medium | zlib | wont-fix | **removed (A)** | removed (A) |
| 65 | CVE-2016-2781 | Low | coreutils | wont-fix | **removed (A)** | removed (A) |
| 66 | CVE-2026-115456 | Low | gcc-12 | not-fixed | **removed (A)** | removed (A) |
| 67 | CVE-2026-100290 | Low | glibc | not-fixed | present | **remains** |
| 68 | CVE-2026-126765 | Low | glibc | not-fixed | present | **removed (B)** |
| 69 | CVE-2026-6368 | Low | glibc | wont-fix | present | **removed (B)** |
| 70 | CVE-2026-95818 | Low | glibc | not-fixed | present | **removed (B)** |
| 71 | CVE-2026-97399 | Low | glibc | not-fixed | present | **removed (B)** |
| 72 | CVE-2026-105712 | Low | gnupg2 | wont-fix | **removed (A)** | removed (A) |
| 73 | CVE-2026-57062 | Low | gnupg2 | wont-fix | **removed (A)** | removed (A) |
| 74 | CVE-2025-46686 | Low | redis | unknown | present | **remains** |
| 75 | CVE-2025-49112 | Low | redis | unknown | present | **remains** |
| 76 | CVE-2024-56433 | Low | shadow | wont-fix | **removed (A)** | removed (A) |
| 77 | CVE-2026-40228 | Low | systemd | wont-fix | **removed (A)** | removed (A) |
| 78 | CVE-2011-3374 | Negligible | apt | not-fixed | **removed (A)** | removed (A) |
| 79 | CVE-2017-18018 | Negligible | coreutils | not-fixed | **removed (A)** | removed (A) |
| 80 | CVE-2025-5278 | Negligible | coreutils | not-fixed | **removed (A)** | removed (A) |
| 81 | CVE-2026-56391 | Negligible | coreutils | not-fixed | **removed (A)** | removed (A) |
| 82 | CVE-2026-56392 | Negligible | coreutils | not-fixed | **removed (A)** | removed (A) |
| 83 | CVE-2026-102473 | Negligible | dash | not-fixed | present | **removed (B)** |
| 84 | CVE-2026-102474 | Negligible | dash | not-fixed | present | **removed (B)** |
| 85 | CVE-2026-53910 | Negligible | diffutils | not-fixed | **removed (A)** | removed (A) |
| 86 | CVE-2022-27943 | Negligible | gcc-12 | not-fixed | **removed (A)** | removed (A) |
| 87 | CVE-2010-4756 | Negligible | glibc | not-fixed | present | **removed (B)** |
| 88 | CVE-2018-20796 | Negligible | glibc | not-fixed | present | **removed (B)** |
| 89 | CVE-2019-1010022 | Negligible | glibc | not-fixed | present | **removed (B)** |
| 90 | CVE-2019-1010023 | Negligible | glibc | not-fixed | present | **removed (B)** |
| 91 | CVE-2019-1010024 | Negligible | glibc | not-fixed | present | **removed (B)** |
| 92 | CVE-2019-1010025 | Negligible | glibc | not-fixed | present | **removed (B)** |
| 93 | CVE-2019-9192 | Negligible | glibc | not-fixed | present | **removed (B)** |
| 94 | CVE-2022-3219 | Negligible | gnupg2 | not-fixed | **removed (A)** | removed (A) |
| 95 | CVE-2011-3389 | Negligible | gnutls28 | not-fixed | **removed (A)** | removed (A) |
| 96 | CVE-2026-67693 | Negligible | gnutls28 | not-fixed | **removed (A)** | removed (A) |
| 97 | CVE-2026-88647 | Negligible | gnutls28 | not-fixed | **removed (A)** | removed (A) |
| 98 | CVE-2026-88648 | Negligible | gnutls28 | not-fixed | **removed (A)** | removed (A) |
| 99 | CVE-2026-95184 | Negligible | gnutls28 | not-fixed | **removed (A)** | removed (A) |
| 100 | CVE-2026-95210 | Negligible | gnutls28 | not-fixed | **removed (A)** | removed (A) |
| 101 | CVE-2018-6829 | Negligible | libgcrypt20 | not-fixed | **removed (A)** | removed (A) |
| 102 | CVE-2024-2236 | Negligible | libgcrypt20 | not-fixed | **removed (A)** | removed (A) |
| 103 | CVE-2025-27587 | Negligible | openssl | not-fixed | present | **removed (B)** |
| 104 | CVE-2011-4116 | Negligible | perl | not-fixed | **removed (A)** | removed (A) |
| 105 | CVE-2023-31486 | Negligible | perl | not-fixed | **removed (A)** | removed (A) |
| 106 | CVE-2007-5686 | Negligible | shadow | not-fixed | **removed (A)** | removed (A) |
| 107 | CVE-2013-4392 | Negligible | systemd | not-fixed | **removed (A)** | removed (A) |
| 108 | CVE-2023-31437 | Negligible | systemd | not-fixed | **removed (A)** | removed (A) |
| 109 | CVE-2023-31438 | Negligible | systemd | not-fixed | **removed (A)** | removed (A) |
| 110 | CVE-2023-31439 | Negligible | systemd | not-fixed | **removed (A)** | removed (A) |
| 111 | CVE-2005-2541 | Negligible | tar | not-fixed | **removed (A)** | removed (A) |
| 112 | CVE-2022-0563 | Negligible | util-linux | not-fixed | **removed (A)** | removed (A) |
| 113 | CVE-2025-14104 | Negligible | util-linux | not-fixed | **removed (A)** | removed (A) |

New CVEs in final image not present in baseline: 0 []

Totals: removed by A = 74, additionally removed by B = 35, remaining = 4

## Appendix C: Commands run (condensed)

```
docker pull redis:7-bookworm                      # digest sha256:2e3eb114…172a90
grype redis@sha256:2e3eb114… -o json > scans/baseline.json
python3 summarize_scan.py scans/baseline.json > summaries/baseline.txt
bash steps/05-deps.sh                             # ldd + dpkg -S: runtime needs libc6, libssl3, sh
bash steps/06-scan-bases.sh                       # scan candidate base images
docker build -f Dockerfile.purge -t redis:7.4.12-purge .
bash steps/scan-only.sh redis:7.4.12-purge purge  # 39
docker build -f Dockerfile.wolfi -t redis:7.4.12-wolfi .
bash steps/scan-only.sh redis:7.4.12-wolfi wolfi  # 4
bash steps/run-tests.sh                           # 3 images x 3 runs x 38 checks, all pass
bash steps/run-compare.sh                        # independent compare_test.sh: 27/27 on both images
docker tag redis:7.4.12-wolfi redis:7.4.12-wolfi-lowcve
python3 summarize_scan.py --compare scans/baseline.json scans/final.json > summaries/compare.txt
```

Sources for §5: [Debian tracker CVE-2025-49112](https://security-tracker.debian.org/tracker/CVE-2025-49112), [NVD CVE-2025-49112](https://nvd.nist.gov/vuln/detail/cve-2025-49112), [NVD CVE-2025-46686](https://nvd.nist.gov/vuln/detail/CVE-2025-46686), [Chainguard CVE-2025-46686](https://images.chainguard.dev/security/CVE-2025-46686), [Debian tracker CVE-2026-115819](https://security-tracker.debian.org/tracker/CVE-2026-115819), [oss-security 2026-11-11](https://www.openwall.com/lists/oss-security/2026/11/11/8), [Amazon Linux CVE-2026-115819](https://explore.alas.aws.amazon.com/CVE-2026-115819.html).
