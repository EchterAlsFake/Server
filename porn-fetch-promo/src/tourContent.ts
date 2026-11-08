// Privacy copy and click timings share one source so the cursor, checkbox and
// explanation always advance together. Times are local to the privacy scene.
export const privacySteps = [
  {
    at: 0.4,
    until: 4.5,
    label: "Anonymous Mode",
    copy: "Conceal sensitive details on your screen when other people are nearby",
  },
  {
    at: 4.5,
    until: 7,
    label: "Tor Integration",
    copy: "Route supported connections through Tor",
  },
  {
    at: 7,
    until: 11.5,
    label: "SNI Obfuscation",
    copy: "Configure SNI fragmentation for supported connections*",
    footnote:
      "* Support depends on your platform and network. Destination IP addresses may remain visible.",
  },
] as const;
