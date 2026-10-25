import {
  AbsoluteFill,
  Easing,
  Interactive,
  interpolate,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { PINK } from "./FetchInterface";
import { clamp } from "./FeaturePrimitives";
import { privacySteps } from "./tourContent";

export const AccountMessage = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  return (
    <AbsoluteFill
      style={{
        pointerEvents: "none",
        opacity: interpolate(
          frame,
          [0, 0.3 * fps, 5.7 * fps, 6 * fps],
          [0, 1, 1, 0],
          clamp,
        ),
      }}
    >
      <div
        style={{
          position: "absolute",
          left: 220,
          right: 220,
          top: 438,
          height: 216,
          background:
            "linear-gradient(90deg, transparent, #0b0b0ff5 12%, #0b0b0ff5 88%, transparent)",
          boxShadow: "0 0 55px 12px #0b0b0f65",
        }}
      />
      <Interactive.Div
        name="Account benefit · central text overlay"
        style={{
          position: "absolute",
          left: 330,
          right: 330,
          top: "50%",
          translate: "0 -50%",
          textAlign: "center",
          fontSize: 54,
          fontWeight: 600,
          lineHeight: 1.2,
          letterSpacing: -1.6,
          color: "#f7f4f7",
          textShadow: "0 3px 24px #000c",
        }}
      >
        <span style={{ display: "block" }}>Download your account history,</span>{" "}
        <span style={{ display: "block", color: PINK }}>
          liked videos, and playlists
        </span>{" "}
        <span style={{ display: "block" }}>from supported websites</span>
      </Interactive.Div>
    </AbsoluteFill>
  );
};

export const PrivacyExplanation = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const step = privacySteps.find(
    ({ at, until }) => frame >= at * fps && frame < until * fps,
  );
  if (!step) return null;
  return (
    <Interactive.Div
      name={`Privacy explanation · ${step.label}`}
      style={{
        position: "absolute",
        left: 850,
        top: 486,
        width: 780,
        padding: "30px 34px 32px",
        boxSizing: "border-box",
        borderRadius: 18,
        border: "1px solid #f28bb43b",
        background: "linear-gradient(130deg, #171319fa, #101014fa)",
        boxShadow: "0 18px 70px #0009, 0 0 40px #f28bb40a",
        pointerEvents: "none",
        opacity: interpolate(
          frame,
          [
            step.at * fps,
            (step.at + 0.18) * fps,
            (step.until - 0.18) * fps,
            step.until * fps,
          ],
          [0, 1, 1, 0],
          clamp,
        ),
        translate: `0 ${interpolate(frame, [step.at * fps, (step.at + 0.28) * fps], [12, 0], { ...clamp, easing: Easing.bezier(0.22, 1, 0.36, 1) })}px`,
      }}
    >
      <Interactive.Div
        name={`${step.label} explanation heading`}
        style={{
          color: PINK,
          fontSize: 22,
          fontWeight: 600,
          letterSpacing: 1.3,
          marginBottom: 16,
        }}
      >
        {step.label}
      </Interactive.Div>
      <Interactive.Div
        name={`${step.label} explanation text`}
        style={{
          color: "#f7f4f7",
          fontSize: 35,
          fontWeight: 500,
          lineHeight: 1.28,
          letterSpacing: -0.5,
          textWrap: "balance",
        }}
      >
        {step.copy}
      </Interactive.Div>
      {"footnote" in step && (
        <Interactive.Div
          name="SNI privacy limitation · asterisk note"
          style={{
            marginTop: 22,
            paddingTop: 19,
            borderTop: "1px solid #f28bb42b",
            color: "#bfb5c0",
            fontSize: 22,
            lineHeight: 1.4,
            textWrap: "balance",
          }}
        >
          {step.footnote}
        </Interactive.Div>
      )}
    </Interactive.Div>
  );
};
