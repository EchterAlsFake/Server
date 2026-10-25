import { interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { Pill, PINK } from "./FetchInterface";
import { privacySteps } from "./tourContent";
import {
  Check,
  Dropdown,
  Field,
  Spin,
  SettingsWindow,
  SettingsRow,
  FeatureCursor,
  clamp,
  glide,
} from "./FeaturePrimitives";

export const PrivacySettings = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const t = frame / fps;
  return (
    <SettingsWindow active="Privacy" scrollSize={0.93}>
      <SettingsRow top={0}>
        <Check
          label="Anonymous Mode"
          checked={t >= privacySteps[0].at}
          focus={t >= privacySteps[0].at && t < privacySteps[0].until}
        />
      </SettingsRow>
      <SettingsRow top={55}>
        <Check label="Encrypted Client Hello" checked />
      </SettingsRow>
      <SettingsRow top={110}>
        <Check label="DNS over HTTPS" checked />
      </SettingsRow>
      <SettingsRow top={165}>
        <Check
          label="Enable Tor Integration"
          checked={t >= privacySteps[1].at}
          focus={t >= privacySteps[1].at && t < privacySteps[1].until}
        />
      </SettingsRow>
      <SettingsRow top={220}>
        <Check
          label="Route License / Update checking through .onion domain"
          checked
        />
      </SettingsRow>
      <SettingsRow top={278}>
        <Field
          name="Primary encrypted DNS"
          value="https://dns.mullvad.net/dns-query"
          style={{ flex: 1 }}
        >
          <span
            style={{
              position: "absolute",
              top: -10,
              left: 10,
              background: "#1b1b1e",
              padding: "0 5px",
              fontSize: 13,
              color: "#77777a",
            }}
          >
            Enter Primary DNS (Must support DNS over HTTPS)
          </span>
          https://dns.mullvad.net/dns-query
        </Field>
      </SettingsRow>
      <SettingsRow top={340}>
        <Field
          name="Fallback encrypted DNS"
          value="https://dns.quad9.net/dns-query"
          style={{ flex: 1 }}
        >
          <span
            style={{
              position: "absolute",
              top: -10,
              left: 10,
              background: "#1b1b1e",
              padding: "0 5px",
              fontSize: 13,
              color: "#77777a",
            }}
          >
            Enter Fallback DNS (Must support DNS over HTTPS)
          </span>
          https://dns.quad9.net/dns-query
        </Field>
      </SettingsRow>
      <SettingsRow top={407}>
        <Check
          label="SNI Obfuscation"
          checked={t >= privacySteps[2].at}
          focus={t >= privacySteps[2].at && t < privacySteps[2].until}
        />
      </SettingsRow>
      <div
        style={{
          position: "absolute",
          top: 462,
          left: 8,
          display: "flex",
          gap: 27,
          alignItems: "center",
          fontSize: 16,
          color: t >= privacySteps[2].at ? "#f7f7f8" : "#67676b",
        }}
      >
        {[
          "Lite SNI Obfuscation",
          "Strict SNI Obfuscation (Requires Admin / root rights)",
        ].map((label, i) => (
          <div
            key={label}
            style={{ display: "flex", alignItems: "center", gap: 8 }}
          >
            <span
              style={{
                width: 17,
                height: 17,
                border: `2px solid ${t >= privacySteps[2].at && i === 0 ? PINK : "#626264"}`,
                borderRadius: "50%",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              {t >= privacySteps[2].at && i === 0 && (
                <span
                  style={{
                    width: 9,
                    height: 9,
                    background: PINK,
                    borderRadius: "50%",
                  }}
                />
              )}
            </span>
            {label}
          </div>
        ))}
      </div>
      <SettingsRow top={519}>
        <Pill
          name="Set up proxy"
          style={{
            flex: 1,
          }}
        >
          Set up proxy...
        </Pill>
      </SettingsRow>
      <FeatureCursor
        points={[
          [0, 595, -75],
          [0.15, 595, -75],
          [0.38, 85, 18],
          [3.85, 85, 18],
          [4.48, 85, 183],
          [6.35, 85, 183],
          [6.98, 85, 425],
          [11.1, 85, 425],
        ]}
        clicks={privacySteps.map(({ at }) => at)}
        until={11.3}
      />
    </SettingsWindow>
  );
};

export const SystemSettings = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const t = frame / fps;
  const scroll = interpolate(frame, [0.15 * fps, 0.65 * fps], [0, 118], glide);
  const binding = "tun0".slice(
    0,
    Math.floor(interpolate(frame, [1.05 * fps, 1.3 * fps], [0, 4], clamp)),
  );
  return (
    <SettingsWindow active="System" scroll={scroll} scrollSize={0.8}>
      <SettingsRow top={0}>
        <Check label="Search for Updates" checked />
      </SettingsRow>
      <SettingsRow top={67}>
        <Check label="Ignore Errors" />
      </SettingsRow>
      <SettingsRow top={134}>
        <Check label="Allow redacted error reports" />
      </SettingsRow>
      <SettingsRow top={201}>
        <Check label="Trust Environment (Advanced)" />
      </SettingsRow>
      <SettingsRow top={268}>
        <Check label="Enable Debug Mode (Not recommended)" />
      </SettingsRow>
      <SettingsRow top={335}>
        <Dropdown name="Log level" value="DEBUG" style={{ flex: 1 }} />
      </SettingsRow>
      <SettingsRow top={406}>
        <Field
          name="HTTP version"
          value={t >= 0.75 ? "v3" : "v2"}
          focus={t >= 0.65 && t < 1}
          style={{ flex: 1 }}
        >
          <span
            style={{
              position: "absolute",
              top: -10,
              left: 10,
              padding: "0 5px",
              background: "#1b1b1e",
              color: t >= 0.65 && t < 1 ? PINK : "#77777a",
              fontSize: 13,
            }}
          >
            HTTP Version may be: v1; v2; v3
          </span>
          {t >= 0.75 ? "v3" : "v2"}
        </Field>
      </SettingsRow>
      <SettingsRow top={477}>
        <Field
          name="Browser impersonation"
          value={t >= 0.95 ? "safari" : "chrome"}
          focus={t >= 0.9 && t < 1.15}
          style={{ flex: 1 }}
        >
          <span
            style={{
              position: "absolute",
              top: -10,
              left: 10,
              padding: "0 5px",
              background: "#1b1b1e",
              color: "#77777a",
              fontSize: 13,
            }}
          >
            e.g., 'chrome', 'safari', 'edge'
          </span>
          {t >= 0.95 ? "safari" : "chrome"}
        </Field>
      </SettingsRow>
      <SettingsRow top={548}>
        <Field
          name="Custom JA3 String"
          placeholder="Custom JA3 String"
          style={{ flex: 1 }}
        />
      </SettingsRow>
      <SettingsRow top={619}>
        <Field
          name="Network interface or IP"
          value={binding || undefined}
          placeholder="e.g., eth0, wlan0, tun0, 10.6.3.20"
          focus={t >= 1.05}
          style={{ flex: 1 }}
        />
      </SettingsRow>
      <FeatureCursor
        points={[
          [0, -100, 125],
          [0.15, -100, 125],
          [0.7, 550, 434],
          [0.85, 550, 434],
          [1.04, 500, 647],
          [1.6, 500, 647],
        ]}
        clicks={[0.7, 1.05]}
        until={1.8}
      />
    </SettingsWindow>
  );
};

export const PerformanceSettings = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const t = frame / fps;
  return (
    <SettingsWindow active="Performance" scrollSize={0.69}>
      <SettingsRow top={0}>
        <span style={{ width: 230, flexShrink: 0 }}>Download workers:</span>
        <Spin
          name="Download workers"
          value={Math.round(
            interpolate(frame, [0.3 * fps, 0.7 * fps], [20, 32], clamp),
          )}
          focus={t >= 0.3 && t < 0.85}
          style={{ flex: 1 }}
        />
      </SettingsRow>
      <SettingsRow top={61}>
        <span style={{ width: 230, flexShrink: 0 }}>
          Network delay (requests/sec):
        </span>
        <Spin name="Network delay" value={0} style={{ flex: 1 }} />
      </SettingsRow>
      <SettingsRow top={122}>
        <span style={{ width: 230, flexShrink: 0 }}>Parallel Downloads:</span>
        <Spin
          name="Parallel Downloads"
          value={Math.round(
            interpolate(frame, [0.7 * fps, 1.05 * fps], [1, 4], clamp),
          )}
          focus={t >= 0.7 && t < 1.2}
          style={{ flex: 1 }}
        />
      </SettingsRow>
      <SettingsRow top={183}>
        <span style={{ width: 230, flexShrink: 0 }}>Maximum retries:</span>
        <Spin name="Maximum retries" value={4} style={{ flex: 1 }} />
      </SettingsRow>
      <SettingsRow top={244}>
        <span style={{ width: 230, flexShrink: 0 }}>Maximum timeout:</span>
        <Spin name="Maximum timeout" value={10} style={{ flex: 1 }} />
      </SettingsRow>
      <SettingsRow top={305}>
        <span style={{ width: 230, flexShrink: 0 }}>
          Processing Delay (videos/sec):
        </span>
        <Spin name="Processing delay" value={0} style={{ flex: 1 }} />
      </SettingsRow>
      <SettingsRow top={366}>
        <span style={{ width: 230, flexShrink: 0 }}>Speed Limit (MB/s):</span>
        <Spin
          name="Speed Limit"
          value={t >= 1.25 ? "8,00" : "0,00"}
          focus={t >= 1.2 && t < 1.6}
          style={{ flex: 1 }}
        />
      </SettingsRow>
      <SettingsRow top={427}>
        <span style={{ width: 230, flexShrink: 0 }}>Videos Concurrency:</span>
        <Spin
          name="Videos Concurrency"
          value={Math.round(
            interpolate(frame, [1.5 * fps, 1.8 * fps], [10, 16], clamp),
          )}
          focus={t >= 1.5 && t < 1.95}
          style={{ flex: 1 }}
        />
      </SettingsRow>
      <SettingsRow top={488}>
        <span style={{ width: 230, flexShrink: 0 }}>Pages concurrency:</span>
        <Spin
          name="Pages concurrency"
          value={t >= 1.85 ? 4 : 2}
          focus={t >= 1.8 && t < 2.2}
          style={{ flex: 1 }}
        />
      </SettingsRow>
      <FeatureCursor
        points={[
          [0, -100, 75],
          [0.15, -100, 75],
          [0.3, 1080, 28],
          [0.6, 1080, 28],
          [0.7, 1080, 150],
          [1, 1080, 150],
          [1.25, 900, 394],
          [1.4, 900, 394],
          [1.7, 1080, 455],
          [1.85, 1080, 516],
          [2.1, 1080, 516],
        ]}
        clicks={[0.3, 0.7, 1.25, 1.7, 1.85]}
        until={2.2}
      />
    </SettingsWindow>
  );
};
