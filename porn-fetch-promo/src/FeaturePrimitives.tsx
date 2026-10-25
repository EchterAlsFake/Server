import type { CSSProperties, ReactNode } from "react";
import {
  Easing,
  Interactive,
  interpolate,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { AppWindow, Pill, PINK, UiIcon } from "./FetchInterface";

export const clamp = {
  extrapolateLeft: "clamp",
  extrapolateRight: "clamp",
} as const;
export const glide = { ...clamp, easing: Easing.bezier(0.65, 0, 0.35, 1) };

export const Field = ({
  name,
  value,
  placeholder,
  focus = false,
  children,
  style,
}: {
  name: string;
  value?: string;
  placeholder?: string;
  focus?: boolean;
  children?: ReactNode;
  style?: CSSProperties;
}) => (
  <Interactive.Div
    name={name}
    style={{
      height: 56,
      border: `1px solid ${focus ? PINK : "#626264"}`,
      borderRadius: 5,
      boxSizing: "border-box",
      display: "flex",
      alignItems: "center",
      padding: "0 15px",
      color: value || children ? "#f7f7f8" : "#67676c",
      background: "#1b1b1e",
      fontSize: 16,
      boxShadow: focus
        ? "0 0 18px #f28bb418, inset 0 0 0 1px #f28bb447"
        : "none",
      whiteSpace: "nowrap",
      position: "relative",
      ...style,
    }}
  >
    {children || value || placeholder}
  </Interactive.Div>
);

export const Check = ({
  label,
  checked = false,
  focus = false,
  style,
}: {
  label: string;
  checked?: boolean;
  focus?: boolean;
  style?: CSSProperties;
}) => (
  <Interactive.Div
    name={label}
    style={{
      display: "flex",
      alignItems: "center",
      gap: 9,
      minHeight: 26,
      whiteSpace: "nowrap",
      fontSize: 16,
      ...style,
    }}
  >
    <span
      style={{
        width: 18,
        height: 18,
        border: `2px solid ${checked ? PINK : "#b4b4b7"}`,
        borderRadius: 2,
        background: checked ? PINK : "transparent",
        boxSizing: "border-box",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        boxShadow: focus ? "0 0 18px #f28bb44a" : "none",
      }}
    >
      {checked && (
        <svg width="13" height="13" viewBox="0 0 16 16">
          <path
            d="m3 8 3 3 7-7"
            stroke="white"
            strokeWidth="2"
            fill="none"
            strokeLinecap="round"
          />
        </svg>
      )}
    </span>
    {label}
  </Interactive.Div>
);

export const Spin = ({
  name,
  value,
  focus = false,
  style,
}: {
  name: string;
  value: string | number;
  focus?: boolean;
  style?: CSSProperties;
}) => (
  <Field
    name={name}
    focus={focus}
    style={{ padding: "0 17px", justifyContent: "space-between", ...style }}
  >
    <span
      style={{ width: 18, height: 2, background: "#77777a", flexShrink: 0 }}
    />
    <span style={{ color: "#f7f7f8", fontVariantNumeric: "tabular-nums" }}>
      {value}
    </span>
    <span
      style={{ position: "relative", width: 18, height: 18, flexShrink: 0 }}
    >
      <span
        style={{
          position: "absolute",
          top: 8,
          left: 0,
          width: 18,
          height: 2,
          background: "white",
        }}
      />
      <span
        style={{
          position: "absolute",
          top: 0,
          left: 8,
          width: 2,
          height: 18,
          background: "white",
        }}
      />
    </span>
  </Field>
);

export const Dropdown = ({
  name,
  value,
  focus = false,
  style,
}: {
  name: string;
  value: string;
  focus?: boolean;
  style?: CSSProperties;
}) => (
  <Field
    name={name}
    focus={focus}
    style={{ justifyContent: "space-between", ...style }}
  >
    <span>{value}</span>
    <span
      style={{
        width: 0,
        height: 0,
        borderLeft: "5px solid transparent",
        borderRight: "5px solid transparent",
        borderTop: "5px solid white",
      }}
    />
  </Field>
);

export const Help = () => (
  <Pill name="Setting information" style={{ width: 62, flexShrink: 0 }}>
    <UiIcon kind="information" size={24} />
  </Pill>
);

export const SettingsWindow = ({
  active,
  children,
  scroll = 0,
  scrollSize = 1,
}: {
  active: string;
  children: ReactNode;
  scroll?: number;
  scrollSize?: number;
}) => (
  <AppWindow active="settings">
    <Interactive.Div
      name="Settings categories"
      style={{
        position: "absolute",
        left: 31,
        top: 94,
        width: 166,
        bottom: 31,
        border: "1px solid #626264",
        borderRadius: 3,
      }}
    >
      {["Video", "Performance", "System", "Privacy", "UI"].map((name) => (
        <div
          key={name}
          style={{
            height: 50,
            paddingLeft: 15,
            display: "flex",
            alignItems: "center",
            background: name === active ? "#373739" : "transparent",
            fontWeight: name === active ? 700 : 400,
            fontSize: 16,
            marginTop: name === "Video" ? 10 : 0,
          }}
        >
          {name}
        </div>
      ))}
    </Interactive.Div>
    <div
      style={{
        position: "absolute",
        left: 217,
        top: 94,
        right: 31,
        bottom: 31,
        border: "1px solid #626264",
        borderRadius: 3,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          position: "absolute",
          top: 15,
          left: 18,
          right: 29,
          translate: `0 ${-scroll}px`,
        }}
      >
        {children}
      </div>
      <div
        style={{
          position: "absolute",
          right: 11,
          top: 12,
          bottom: 12,
          width: 12,
          background: "#232325",
        }}
      >
        <div
          style={{
            width: 12,
            height: `${scrollSize * 100}%`,
            background: "#545456",
            translate: `0 ${scroll * 0.45}px`,
          }}
        />
      </div>
    </div>
  </AppWindow>
);

export const SettingsRow = ({
  top,
  children,
}: {
  top: number;
  children: ReactNode;
}) => (
  <div
    style={{
      position: "absolute",
      left: 0,
      right: 0,
      top,
      display: "flex",
      gap: 15,
      alignItems: "center",
      minHeight: 40,
    }}
  >
    <Help />
    {children}
  </div>
);

export type CursorPoint = readonly [seconds: number, x: number, y: number];
export const FeatureCursor = ({
  points,
  clicks = [],
  until = 100,
}: {
  points: readonly CursorPoint[];
  clicks?: readonly number[];
  until?: number;
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const time = frame / fps;
  const click = clicks.find((t) => time >= t && time < t + 0.25);
  return (
    <Interactive.Div
      name="Feature interaction cursor"
      style={{
        position: "absolute",
        left: 0,
        top: 0,
        zIndex: 5,
        pointerEvents: "none",
        opacity: interpolate(
          frame,
          [0, 0.15 * fps, (until - 0.15) * fps, until * fps],
          [0, 1, 1, 0],
          clamp,
        ),
        translate: `${interpolate(
          frame,
          points.map(([t]) => t * fps),
          points.map(([, x]) => x),
          glide,
        )}px ${interpolate(
          frame,
          points.map(([t]) => t * fps),
          points.map(([, , y]) => y),
          glide,
        )}px`,
      }}
    >
      {click !== undefined && (
        <div
          style={{
            position: "absolute",
            width: 52,
            height: 52,
            left: -26,
            top: -26,
            border: `1px solid ${PINK}`,
            borderRadius: "50%",
            scale: interpolate(
              frame,
              [click * fps, (click + 0.25) * fps],
              [0.3, 1.4],
              clamp,
            ),
            opacity: interpolate(
              frame,
              [click * fps, (click + 0.25) * fps],
              [0.8, 0],
              clamp,
            ),
          }}
        />
      )}
      <svg
        width="23"
        height="29"
        viewBox="0 0 23 29"
        style={{ filter: "drop-shadow(0 2px 3px #0009)" }}
      >
        <path
          d="M2 2v21l5.7-5 4.8 9 4-2-4.7-8.8H20Z"
          fill="#f9f5f7"
          stroke="#18151a"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
      </svg>
    </Interactive.Div>
  );
};
