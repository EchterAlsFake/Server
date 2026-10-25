// Privacy copy and click timings share one source so the cursor, checkbox and
// explanation always advance together. Times are local to the privacy scene.
export const privacySteps = [
  {
    at: 0.4,
    until: 4.5,
    label: "Anonymous Mode",
    copy: "Hide the app from people looking over your shoulder, or friends and family using your device",
  },
  {
    at: 4.5,
    until: 7,
    label: "Tor Integration",
    copy: "Download videos using Tor in restricted countries",
  },
  {
    at: 7,
    until: 11.5,
    label: "SNI Obfuscation",
    copy: "Bypass firewalls and hide Porn Fetch from your ISP*",
    footnote:
      "* Not a proof for privacy, best effort to hide the SNI name. Destination IP may still be visible",
  },
] as const;
