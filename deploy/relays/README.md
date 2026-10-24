# Deploying a fleet of relays

Several relays (Vector runs two, in Europe and Asia) run the same build and are
upgraded one at a time, so they are never all restarting at once.

```
deploy/relays/deploy.sh               # HEAD, to every relay in hosts.env order
deploy/relays/deploy.sh <commit>      # a given commit; also how to go back
deploy/relays/deploy.sh --only eu     # one relay
deploy/relays/status.sh               # build, uptime, connections, sync, warnings
```

Copy `hosts.env.example` to `hosts.env` (git ignores it) and list your relays,
how to reach them over SSH, and which one builds.

What a deploy does:

1. **One build.** The commit (`git archive`, so only committed work ships) is
   tested and built once on the build box (`box-build.sh`): `cargo test
   --workspace --release` on Linux, and nothing ships if one test fails. The
   binary is stamped with its commit (`RELAY_BUILD_REV`): `/stats` `build`, the
   landing page's footer and the startup log say which commit runs.
2. **The same bytes everywhere,** checked by SHA-256 on arrival.
3. **Staggered and checked** (`install.sh` on each host): every release is kept
   in `/usr/local/lib/magnitude-relay/releases/<commit>/`, and
   `/usr/local/bin/magnitude-relay` is a symlink switched atomically. After the
   restart (about 0.6 s) the relay must be active, answering, reporting the new
   commit within 30 s, and then stay up for `SOAK` seconds without restarting.
   Any failure puts the previous release back and stops the run, so the next
   host is never touched. The five newest releases stay on each host.

Settings are each host's own (`/etc/magnitude-relay/relay.toml`: identity, URLs,
`[[sync]]`, `[[peer]]`) and a deploy never touches them.

## A new host

The service, its user and its settings exist before the first deploy:

1. A system user: `useradd --system --home /var/lib/magnitude-relay --shell /usr/sbin/nologin magnitude-relay`
2. Settings: `magnitude-relay init /etc/magnitude-relay/relay.toml`, then edit
   (readable by the relay's user only if it holds a peer secret).
3. Data: `/var/lib/magnitude-relay`, owned by that user. To move in from strfry,
   `strfry export | magnitude-relay --config /etc/magnitude-relay/relay.toml import -`
   before the first start.
4. The unit: `magnitude-relay.service` here, in `/etc/systemd/system/`.
5. Add the host to `hosts.env` and run `deploy.sh --only <host>`.

## Host tuning

**Linux software RAID (md).** By default md marks an array "clean" 0.2 s after
its last write, and the next write first waits while md rewrites its superblock
on every drive. A relay that commits a few times a second pays that on most
syncs (we measured ~16 ms on client NVMe drives). Raising the delay keeps the
array "active" between commits; with md's write-intent bitmap, crash recovery
still only rechecks the regions written last:

```
echo 10 > /sys/block/md2/md/safe_mode_delay
# and at every boot, in /etc/udev/rules.d/90-md-safe-mode.rules:
ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="md2", TEST=="md/safe_mode_delay", ATTR{md/safe_mode_delay}="10"
```
