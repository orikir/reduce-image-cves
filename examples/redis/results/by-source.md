# redis@sha256:2e3eb11462c4e3759e6972678dd051d150ff54b1e60714b3c33b701260172a90: 113 unique CVEs in 26 source packages (DB 2026-11-20T06:21:00Z)

| source package | binary packages | CVEs | Crit | High | Med | Low | Negl | fix states |
|---|---|---|---|---|---|---|---|---|
| glibc | libc-bin, libc6 | 30 | 1 | 4 | 13 | 5 | 7 | not-fixed 17, wont-fix 13 |
| gnutls28 | libgnutls30 | 9 |  |  | 3 |  | 6 | not-fixed 9 |
| util-linux | bsdutils, libblkid1, libmount1, libsmartcols1, libuuid1, mount, util-linux, util-linux-extra | 8 |  | 3 | 3 |  | 2 | not-fixed 6, wont-fix 2 |
| gcc-12 | gcc-12-base, libgcc-s1, libstdc++6 | 7 |  | 2 | 3 | 1 | 1 | not-fixed 3, wont-fix 4 |
| systemd | libsystemd0, libudev1 | 7 |  |  | 2 | 1 | 4 | not-fixed 4, wont-fix 3 |
| coreutils | coreutils | 5 |  |  |  | 1 | 4 | not-fixed 4, wont-fix 1 |
| gnupg2 | gpgv | 5 |  |  | 2 | 2 | 1 | not-fixed 1, wont-fix 4 |
| openssl | libssl3 | 5 |  | 3 | 1 |  | 1 | not-fixed 5 |
| perl | perl-base | 5 |  | 2 | 1 |  | 2 | not-fixed 2, wont-fix 3 |
| tar | tar | 4 |  |  | 3 |  | 1 | not-fixed 1, wont-fix 3 |
| ncurses | libtinfo6, ncurses-base, ncurses-bin | 3 |  | 1 | 2 |  |  | wont-fix 3 |
| pam | libpam-modules, libpam-modules-bin, libpam-runtime, libpam0g | 3 |  | 1 | 2 |  |  | not-fixed 1, wont-fix 2 |
| acl | libacl1 | 2 |  | 2 |  |  |  | wont-fix 2 |
| dash | dash | 2 |  |  |  |  | 2 | not-fixed 2 |
| gzip | gzip | 2 |  | 1 | 1 |  |  | wont-fix 2 |
| libgcrypt20 | libgcrypt20 | 2 |  |  |  |  | 2 | not-fixed 2 |
| p11-kit | libp11-kit0 | 2 |  |  | 2 |  |  | wont-fix 2 |
| redis | redis | 2 |  |  |  | 2 |  | unknown 2 |
| shadow | login, passwd | 2 |  |  |  | 1 | 1 | not-fixed 1, wont-fix 1 |
| zlib | zlib1g | 2 |  | 1 | 1 |  |  | not-fixed 1, wont-fix 1 |
| apt | apt, libapt-pkg6.0 | 1 |  |  |  |  | 1 | not-fixed 1 |
| attr | libattr1 | 1 |  |  | 1 |  |  | wont-fix 1 |
| bzip2 | libbz2-1.0 | 1 |  |  | 1 |  |  | wont-fix 1 |
| diffutils | diffutils | 1 |  |  |  |  | 1 | not-fixed 1 |
| dpkg | dpkg | 1 |  |  | 1 |  |  | not-fixed 1 |
| libtasn1-6 | libtasn1-6 | 1 |  | 1 |  |  |  | wont-fix 1 |

Next: for each source package decide: needed at runtime? -> remove it / replace the base / upgrade / accept.
