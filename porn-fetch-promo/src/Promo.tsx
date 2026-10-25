import {
  AbsoluteFill,
  Easing,
  Freeze,
  Interactive,
  Sequence,
  Track,
  interpolate,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { FetchInterface, PINK, UiIcon } from "./FetchInterface";
import { AdvancedConfiguration } from "./AdvancedConfiguration";
import { Accounts } from "./Accounts";
import { AccountMessage, PrivacyExplanation } from "./FeatureOverlays";
import {
  PerformanceSettings,
  PrivacySettings,
  SystemSettings,
} from "./Settings";

const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;
const smooth = { ...clamp, easing: Easing.bezier(0.65, 0, 0.35, 1) };

const Atmosphere = () => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const phase = Math.sin((frame / durationInFrames) * Math.PI * 2);
  return (
    <AbsoluteFill style={{ background: "#0b0b0f", overflow: "hidden" }}>
      <div
        style={{
          position: "absolute",
          width: 1500,
          height: 800,
          left: 200,
          top: 590,
          borderRadius: "50%",
          background:
            "radial-gradient(ellipse, #9e355b2b 0%, #6a22451a 34%, transparent 68%)",
          translate: `${phase * 45}px ${phase * 16}px`,
        }}
      />
      <div
        style={{
          position: "absolute",
          width: 1200,
          height: 900,
          right: -400,
          top: -380,
          borderRadius: "50%",
          background: "radial-gradient(ellipse, #77364c24, transparent 68%)",
        }}
      />
      <div
        style={{
          position: "absolute",
          left: 112,
          right: 112,
          top: 116,
          height: 1,
          background:
            "linear-gradient(90deg, #ffffff1a, #ffffff08 70%, #f28bb428)",
        }}
      />
      <div
        style={{
          position: "absolute",
          left: 112,
          top: 117,
          width: 1,
          height: 825,
          background: "linear-gradient(#ffffff0a, transparent)",
        }}
      />
      <div
        style={{
          position: "absolute",
          right: 112,
          top: 117,
          width: 1,
          height: 825,
          background: "linear-gradient(#ffffff0a, transparent)",
        }}
      />
      <svg
        width="1920"
        height="1080"
        style={{ position: "absolute", opacity: 0.12 }}
      >
        <ellipse
          cx="960"
          cy="1045"
          rx="1060"
          ry="540"
          fill="none"
          stroke="#f28bb4"
          strokeWidth="0.7"
        />
      </svg>
    </AbsoluteFill>
  );
};

const Brand = () => (
  <>
    <Interactive.Div
      name="Brand · Porn Fetch"
      style={{
        position: "absolute",
        left: 112,
        top: 55,
        display: "flex",
        alignItems: "center",
        gap: 16,
      }}
    >
      <div
        style={{
          width: 40,
          height: 40,
          border: "1px solid #f28bb445",
          borderRadius: 11,
          background: "linear-gradient(145deg, #f28bb413, #f28bb404)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <UiIcon kind="download" size={26} />
      </div>
      <div style={{ fontSize: 26, letterSpacing: 3.4, fontWeight: 700 }}>
        PORN<span style={{ color: PINK, marginLeft: 9 }}>FETCH</span>
      </div>
    </Interactive.Div>
    <Interactive.Div
      name="Brand descriptor"
      style={{
        position: "absolute",
        right: 112,
        top: 71,
        color: "#a3a0aa",
        fontSize: 13,
        letterSpacing: 3,
      }}
    >
      YOUR COLLECTION. YOUR CONTROL.
    </Interactive.Div>
  </>
);

// Each chapter has an explicit reading hold. Playback rates stretch the existing
// detailed interactions without duplicating the UI or changing the demo content.
const chapters = [
  {
    from: 0,
    to: 5.5,
    lead: "One link.",
    accent: "All yours.",
    copy: "Paste a link. Pick your quality. Fetch.",
    label: "01 / SINGLE VIDEO",
  },
  {
    from: 5.5,
    to: 11,
    lead: "More videos.",
    accent: "One click.",
    copy: "Select the collection. Download together.",
    label: "02 / MODEL COLLECTION",
  },
  {
    from: 11,
    to: 16,
    lead: "Your library.",
    accent: "Your rules.",
    copy: "Regex filters. Quality and date ranges. Custom filename templates.",
    label: "03 / ORGANIZE LIKE AN EXPERT",
  },
  {
    from: 16,
    to: 22,
    lead: "Your likes.",
    accent: "Your library.",
    copy: "Your account collections, across supported websites.",
    label: "04 / ACCOUNT LIBRARIES",
  },
  {
    from: 22,
    to: 33.5,
    lead: "Your privacy.",
    accent: "Your choice.",
    copy: "Encrypted DNS, Tor integration, SNI obfuscation and proxy controls.",
    label: "05 / PRIVACY CONTROLS",
  },
  {
    from: 33.5,
    to: 36.5,
    lead: "Fine-tune",
    accent: "everything.",
    copy: "Set the HTTP version, browser identity and network interface.",
    label: "06 / ADVANCED SETTINGS",
  },
  {
    from: 36.5,
    to: 39.65,
    lead: "Power at",
    accent: "your pace.",
    copy: "Workers, parallel downloads, speed limits and concurrency.",
    label: "07 / PERFORMANCE",
  },
  {
    from: 39.65,
    to: 40.3,
    lead: "One link.",
    accent: "All yours.",
    copy: "Paste a link. Pick your quality. Fetch.",
    label: "01 / SINGLE VIDEO",
  },
];
const boundaries = [5.5, 11, 16, 22, 33.5, 36.5, 39.65];

const Editorial = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const chapter =
    chapters.find(({ from, to }) => frame >= from * fps && frame < to * fps) ??
    chapters[0];
  return (
    <Interactive.Div
      name="Chapter editorial"
      style={{
        opacity: interpolate(
          frame,
          [
            chapter.from * fps,
            (chapter.from + 0.14) * fps,
            (chapter.to - 0.15) * fps,
            chapter.to * fps,
          ],
          [chapter.from === 0 ? 1 : 0, 1, 1, 0],
          clamp,
        ),
        translate: `0 ${interpolate(frame, [chapter.from * fps, (chapter.from + 0.2) * fps], [chapter.from === 0 ? 0 : 9, 0], smooth)}px`,
      }}
    >
      <Interactive.Div
        name="Hero headline"
        style={{
          position: "absolute",
          left: 218,
          top: 140,
          fontWeight: 600,
          fontSize: 94,
          letterSpacing: -5,
          lineHeight: 1.12,
        }}
      >
        {chapter.lead}
        <span style={{ color: PINK }}> {chapter.accent}</span>
      </Interactive.Div>
      <Interactive.Div
        name="Hero supporting line"
        style={{
          position: "absolute",
          left: 223,
          top: 257,
          fontSize: 23,
          color: "#aaa5b0",
          letterSpacing: 0.1,
        }}
      >
        {chapter.copy}
      </Interactive.Div>
      <Interactive.Div
        name="Sequence marker"
        style={{
          position: "absolute",
          right: 223,
          top: 264,
          display: "flex",
          alignItems: "center",
          gap: 12,
          color: "#c0b6c0",
          fontSize: 12,
          letterSpacing: 2.2,
        }}
      >
        <span
          style={{
            width: 5,
            height: 5,
            background: PINK,
            borderRadius: "50%",
            boxShadow: "0 0 12px #f28bb499",
          }}
        />
        {chapter.label}
      </Interactive.Div>
    </Interactive.Div>
  );
};

const FeatureTour = () => {
  const { fps } = useVideoConfig();
  return (
    <Track name="Editable application tour">
      <Sequence
        name="Video and model downloads · slower pacing"
        durationInFrames={Math.round(9.35 * fps)}
        playbackRate={0.85}
        layout="none"
      >
        <FetchInterface />
      </Sequence>
      <Sequence
        name="Advanced Configuration · filters and naming"
        from={11 * fps}
        durationInFrames={Math.round(4.15 * fps)}
        playbackRate={0.83}
        layout="none"
      >
        <AdvancedConfiguration />
      </Sequence>
      <Sequence
        name="Account tabs · two seconds per provider"
        from={16 * fps}
        durationInFrames={6 * fps}
        layout="none"
      >
        <Accounts />
      </Sequence>
      <Sequence
        name="Settings · privacy reading holds"
        from={22 * fps}
        durationInFrames={11.5 * fps}
        layout="none"
      >
        <PrivacySettings />
      </Sequence>
      <Sequence
        name="Settings · system and interface binding"
        from={33.5 * fps}
        durationInFrames={2 * fps}
        playbackRate={2 / 3}
        layout="none"
      >
        <SystemSettings />
      </Sequence>
      <Sequence
        name="Settings · performance"
        from={36.5 * fps}
        durationInFrames={Math.round(2.35 * fps)}
        playbackRate={2.35 / 3.15}
        layout="none"
      >
        <PerformanceSettings />
      </Sequence>
      <Sequence
        name="Restore opening state · seamless loop"
        from={39.65 * fps}
        durationInFrames={Math.round(0.35 * fps)}
        layout="none"
      >
        <Freeze frame={0}>
          <FetchInterface />
        </Freeze>
      </Sequence>
    </Track>
  );
};

// One app window throughout. Transition blur does not create compositing copies.
const AppCamera = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const boundary = boundaries.find((t) => Math.abs(frame / fps - t) < 0.14);
  return (
    <Interactive.Div
      name="Single interface camera"
      style={{
        position: "absolute",
        left: 264,
        top: 332,
        width: 1392,
        height: 718,
        transformOrigin: "50% 45%",
        scale: interpolate(
          frame,
          [
            0,
            0.6 * fps,
            1.95 * fps,
            2.71 * fps,
            4.65 * fps,
            5.17 * fps,
            5.53 * fps,
            6.47 * fps,
            7.65 * fps,
            10.7 * fps,
            11 * fps,
            12.4 * fps,
            15.2 * fps,
            16 * fps,
            17 * fps,
            21.5 * fps,
            22 * fps,
            23.2 * fps,
            26.2 * fps,
            26.5 * fps,
            28.7 * fps,
            29 * fps,
            30.3 * fps,
            33.2 * fps,
            33.5 * fps,
            34.7 * fps,
            36.2 * fps,
            36.5 * fps,
            37.8 * fps,
            39.3 * fps,
            39.8 * fps,
            40 * fps,
          ],
          [
            1.02, 1.02, 1.085, 1.085, 1.045, 1.045, 1.015, 1.055, 1.04, 1.04,
            1.015, 1.045, 1.045, 1.02, 1.04, 1.04, 1.02, 1.045, 1.045, 1.04,
            1.04, 1.04, 1.045, 1.045, 1.02, 1.04, 1.04, 1.02, 1.04, 1.04, 1.02,
            1.02,
          ],
          { ...smooth, output: "perceptual-scale" },
        ),
        translate: `0 ${interpolate(frame, [0, 1.95 * fps, 2.71 * fps, 4.7 * fps, 5.53 * fps, 6.47 * fps, 7.76 * fps, 10.7 * fps, 11 * fps, 12.4 * fps, 16 * fps, 17 * fps, 21.5 * fps, 22 * fps, 23.2 * fps, 33.2 * fps, 33.5 * fps, 34.7 * fps, 36.5 * fps, 37.8 * fps, 39.3 * fps, 39.8 * fps, 40 * fps], [0, -15, -15, -5, 0, -8, -3, -3, 0, -4, 0, -3, -3, 0, -4, -4, 0, -3, 0, -3, -3, 0, 0], smooth)}px`,
        filter:
          boundary === undefined
            ? "none"
            : `blur(${interpolate(frame, [(boundary - 0.14) * fps, boundary * fps, (boundary + 0.14) * fps], [0, 1.6, 0], clamp)}px)`,
      }}
    >
      <FeatureTour />
    </Interactive.Div>
  );
};

const FeatureCopy = () => {
  const { fps } = useVideoConfig();
  return (
    <Track name="Readable feature explanations">
      <Sequence
        name="Account benefit · centered overlay"
        from={16 * fps}
        durationInFrames={6 * fps}
        layout="none"
      >
        <AccountMessage />
      </Sequence>
      <Sequence
        name="Privacy explanations · synchronized to clicks"
        from={22 * fps}
        durationInFrames={11.5 * fps}
        layout="none"
      >
        <PrivacyExplanation />
      </Sequence>
    </Track>
  );
};

const TransitionLight = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const boundary = boundaries.find((t) => Math.abs(frame / fps - t) < 0.3);
  if (boundary === undefined) return null;
  return (
    <Interactive.Div
      name="Chapter light sweep"
      style={{
        position: "absolute",
        left: -500,
        top: 292,
        width: 520,
        height: 850,
        pointerEvents: "none",
        background:
          "linear-gradient(90deg, transparent, #f28bb407 25%, #ffbdde24 52%, #f28bb40a 65%, transparent)",
        filter: "blur(16px)",
        rotate: "-15deg",
        mixBlendMode: "screen",
        opacity: interpolate(
          frame,
          [
            (boundary - 0.3) * fps,
            boundary * fps,
            (boundary + (boundary === 39.65 ? 0.2 : 0.3)) * fps,
          ],
          [0, 0.85, 0],
          clamp,
        ),
        translate: `${interpolate(frame, [(boundary - 0.3) * fps, (boundary + (boundary === 39.65 ? 0.2 : 0.3)) * fps], [0, 2600], smooth)}px 0`,
      }}
    />
  );
};

export const PornFetchPromo = () => (
  <AbsoluteFill
    style={{
      fontFamily: "Arial, Helvetica, sans-serif",
      color: "#f7f4f7",
      overflow: "hidden",
    }}
  >
    <Atmosphere />
    <Brand />
    <Editorial />
    <AppCamera />
    <FeatureCopy />
    <TransitionLight />
  </AbsoluteFill>
);
