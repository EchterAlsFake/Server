# Dashboard deployment

The dashboard app and broker are in the separate `eaf-dashboard` checkout.
The Server image supplies website analytics and revenue reports. The Acer serves
the download hostname. The Pixel publishes the dashboard and website. The VPS
continues to forward TCP and operate the existing authenticated fleet monitor.

- Build the two ARM64 service images using their normal build pipeline. The
  matching rollback images and prior configuration are saved under the dated
  `/root/pf-dashboard-backup-*` directory on the Pixel.
- Install the broker and its report modules under the `pornfetch` account's
  `.local/lib/eaf-dashboard`. The dashboard Quadlet requires the broker and
  mounts `%t/eaf-dashboard-broker` at `/run/eaf-dashboard` read-only. The
  broker and application have separate systemd runtime directories. The Quadlet
  decrypts its existing systemd credential into the private application runtime
  directory at startup.
- Install the reporting timer and the host-specific service as
  `pf-dashboard-reports.service`. On the Acer, the inventory reader uses
  `/srv/pornfetch-website-releases` and `/srv/pornfetch-repo`. Attach its two
  read-only snapshots to the existing authenticated health agent. The Pixel
  fetches them through the VPS monitor using the pinned certificate in
  `/etc/infra-monitor/vps-monitor.crt`.
- Install the Caddy traffic snippet and import it in the serving site blocks.
  On the Pixel, preserve the live JSON TLS settings when adapting the Caddyfile.
  Validate and reload Caddy on each HTTP origin. Only aggregate transfer counts
  and normalized endpoint groups persist in the reporting database.
- Enable the website analytics, privacy, and financial reporting timers in the
  Pixel's `pornfetch` user manager. The broker needs read ACLs on the reports
  and data used by existing operations. The revenue export contains hashed
  order references, dates, statuses, currencies and recorded amounts.
- Verify the live dashboard health, analytics report timestamp, fleet, installer
  inventory, and a cross-origin embed. Roll back the app image or Caddy
  configuration independently by restoring the recorded tag or backed-up file
  and restarting the corresponding service. Database backups are for recovery.
