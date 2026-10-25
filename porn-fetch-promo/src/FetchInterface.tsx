import type { CSSProperties } from "react";
import {
  Easing,
  Interactive,
  interpolate,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";

export const PINK = "#f28bb4";
const PANEL = "#1b1b1e";
const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;
const smooth = { ...clamp, easing: Easing.bezier(0.22, 1, 0.36, 1) };
const columns = "176px 350px 280px 138px 108px 98px 180px";

// Coordinates follow the supplied screenshots in a 1392 px UI space.
// Controls, labels, selections and progress fills remain separate layers.
export const UiIcon = ({
  kind,
  size = 25,
}: {
  kind: string;
  size?: number;
}) => {
  if (kind === "download")
    return (
      <svg width={size} height={size} viewBox="0 0 28 28" fill="none">
        <path
          d="M14 3v15m-5-5 5 5 5-5M8 24h12"
          stroke="#4cebaa"
          strokeWidth="1.6"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    );
  if (kind === "account")
    return (
      <svg width={size} height={size} viewBox="0 0 28 28" fill="none">
        <circle
          cx="14"
          cy="14"
          r="11"
          fill="#76cbff"
          stroke="#2684de"
          strokeWidth="2"
        />
        <circle cx="14" cy="11" r="3.2" stroke="#196cb6" strokeWidth="1.7" />
        <path d="M8 21v-3c0-4 12-4 12 0v3" stroke="#196cb6" strokeWidth="1.7" />
      </svg>
    );
  if (kind === "database")
    return (
      <svg width={size} height={size} viewBox="0 0 28 28">
        <path d="M5 6h18v14c0 5-18 5-18 0Z" fill="#9347fa" />
        {[6, 11, 16, 21].map((y) => (
          <ellipse
            key={y}
            cx="14"
            cy={y}
            rx="9"
            ry="3"
            fill={y === 6 ? "#e2c65a" : "none"}
            stroke="#62baff"
            strokeWidth="1.2"
          />
        ))}
        <circle cx="23" cy="22" r="5" fill="#6acbff" />
        <path d="M21 24v-2m2 2v-4m2 4v-3" stroke="#822ce3" />
      </svg>
    );
  if (kind === "settings")
    return (
      <svg width={size} height={size} viewBox="0 0 28 28" fill="none">
        <path
          d="m11 3 1 3h4l1-3 4 2-1 3 2 3 3-1v5l-3 1-2 3 1 3-4 2-1-3h-4l-1 3-4-2 1-3-2-3-3-1v-5l3 1 2-3-1-3Z"
          stroke="#9150cd"
          strokeWidth="2"
          strokeLinejoin="round"
        />
        <circle cx="14" cy="13" r="4" stroke="#4c77d8" strokeWidth="1.5" />
      </svg>
    );
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" fill="none">
      <circle cx="14" cy="14" r="10" stroke="#48c3d6" strokeWidth="2" />
      <circle cx="14" cy="14" r="8.3" stroke="white" strokeWidth="1.5" />
      <path d="M14 12v8" stroke="white" strokeWidth="3" />
      <circle cx="14" cy="8" r="1.5" fill="#ffc58b" />
    </svg>
  );
};

const Navigation = ({ active = "download" }: { active?: string }) => (
  <Interactive.Div
    name="Application navigation"
    style={{
      position: "absolute",
      left: 10,
      right: 10,
      top: 9,
      height: 49,
      display: "grid",
      gridTemplateColumns: "repeat(6, 1fr)",
    }}
  >
    {["download", "account", "database", "settings", "information"].map(
      (kind) => (
        <div
          key={kind}
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            borderBottom:
              kind === active ? `2px solid ${PINK}` : "2px solid transparent",
          }}
        >
          <UiIcon kind={kind} />
        </div>
      ),
    )}
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        fontSize: 16,
      }}
    >
      SUPPORTED WEBSITES
    </div>
  </Interactive.Div>
);

export const Pill = ({
  children,
  disabled = false,
  pink = false,
  pressed = false,
  style,
  name,
}: {
  children: React.ReactNode;
  disabled?: boolean;
  pink?: boolean;
  pressed?: boolean;
  style?: CSSProperties;
  name: string;
}) => (
  <Interactive.Div
    name={name}
    style={{
      height: 40,
      borderRadius: 24,
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
      whiteSpace: "nowrap",
      background: pink
        ? PINK
        : disabled
          ? "#353537"
          : pressed
            ? "#5a4a52"
            : "linear-gradient(#424244, #3d3d3f)",
      color: disabled ? "#77777b" : "#fafafa",
      fontSize: 16,
      boxShadow:
        disabled || pink
          ? "none"
          : "0 2px 5px #0004, inset 0 1px 2px #ffffff08",
      scale: pressed ? 0.97 : 1,
      ...style,
    }}
  >
    {children}
  </Interactive.Div>
);

export const UrlField = ({
  kind,
  index,
  demo = true,
}: {
  kind: "Video" | "Model" | "Playlist";
  index: number;
  demo?: boolean;
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const time = frame / fps;
  const video = kind === "Video";
  const model = kind === "Model";
  const start = video ? 0.5 : 4.87;
  const end = video ? 1.48 : 5.65;
  const url = video
    ? "https://demo.example/video/midnight"
    : "https://demo.example/model/aurora";
  const active =
    demo &&
    ((video && time >= start && time < 1.84) ||
      (model && time >= start && time < 9.42));
  const typed = active
    ? url.slice(
        0,
        Math.floor(
          interpolate(frame, [start * fps, end * fps], [0, url.length], clamp),
        ),
      )
    : "";
  const focus = active && time < (video ? 1.69 : 5.82);
  const click = video
    ? time >= 1.67 && time < 1.79
    : model && time >= 5.82 && time < 5.95;
  const placeholder = video
    ? "Enter a video URL"
    : model
      ? "Enter a model or channel URL"
      : "Enter a playlist URL";
  return (
    <Interactive.Div
      name={`${kind} URL field`}
      style={{
        position: "absolute",
        left: 20,
        top: 73 + index * 61,
        height: 56,
        right: 20,
        display: "flex",
        alignItems: "center",
        gap: 5,
      }}
    >
      <div
        style={{ width: 89, flexShrink: 0, fontSize: 16, whiteSpace: "nowrap" }}
      >
        {kind} URL:
      </div>
      <div
        style={{
          position: "relative",
          flex: 1,
          height: 56,
          borderRadius: 5,
          border: `${focus ? 2 : 1}px solid ${focus ? PINK : "#626264"}`,
          display: "flex",
          alignItems: "center",
          padding: "0 15px",
          color: typed ? "#f6f6f7" : "#67676c",
          fontSize: 16,
          background: PANEL,
          boxShadow: focus ? "0 0 24px #f28bb40b" : "none",
        }}
      >
        {focus && (
          <div
            style={{
              position: "absolute",
              top: -10,
              left: 10,
              padding: "0 5px",
              background: PANEL,
              color: PINK,
              fontSize: 13,
            }}
          >
            {placeholder}
          </div>
        )}
        <span>{typed || (!focus ? placeholder : "")}</span>
        {focus && (
          <span
            style={{
              height: 20,
              width: 1,
              marginLeft: 2,
              background: PINK,
              opacity: Math.sin(time * 12) > -0.2 ? 1 : 0,
            }}
          />
        )}
      </div>
      <Pill
        name={`${kind}: Get ${video ? "Video" : "Videos"}`}
        disabled={!typed}
        pressed={Boolean(click)}
        style={{ width: 125, flexShrink: 0 }}
      >
        {video ? "Get Video" : "Get Videos"}
      </Pill>
    </Interactive.Div>
  );
};

const DownloadActions = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const t = frame / fps;
  const available = (t >= 1.86 && t < 4.55) || (t >= 5.98 && t < 9.42);
  return (
    <>
      <Interactive.Div
        name="Downloads and configuration"
        style={{
          position: "absolute",
          top: 262,
          left: 20,
          right: 20,
          display: "grid",
          gridTemplateColumns: "342px 582px 1fr",
          gap: 2,
        }}
      >
        <Pill name="Downloads tab" pink>
          Downloads
        </Pill>
        <Pill name="Advanced Configuration">Advanced Configuration</Pill>
        <Pill name="Cancel Loading" disabled>
          Cancel Loading
        </Pill>
      </Interactive.Div>
      <Interactive.Div
        name="Selection actions"
        style={{
          position: "absolute",
          top: 323,
          left: 28,
          right: 28,
          display: "flex",
          gap: 8,
        }}
      >
        <Pill
          name="Select All"
          disabled={!available}
          pressed={t >= 6.53 && t < 6.65}
          style={{ width: 114 }}
        >
          Select All
        </Pill>
        <Pill
          name="Clear Selection"
          disabled={!available}
          style={{ width: 154 }}
        >
          Clear Selection
        </Pill>
        <Pill
          name="Download Selected"
          disabled={!available}
          pressed={t >= 7.03 && t < 7.15}
          style={{ width: 183, marginLeft: "auto" }}
        >
          Download Selected
        </Pill>
      </Interactive.Div>
    </>
  );
};

const DownloadRow = ({
  title,
  author,
  duration,
  number,
  appears,
  starts,
  completes,
  disappears,
  selected = false,
}: {
  title: string;
  author: string;
  duration: string;
  number: number;
  appears: number;
  starts: number;
  completes: number;
  disappears: number;
  selected?: boolean;
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const time = frame / fps;
  const running = time >= starts && time < completes;
  const started = time >= starts;
  const progress = Math.round(
    interpolate(frame, [starts * fps, completes * fps], [0, 100], clamp),
  );
  const checked = selected && time >= 6.55;
  return (
    <Interactive.Div
      name={`${number}. ${title}`}
      style={{
        position: "absolute",
        top: 409 + (number - 1) * 73,
        left: 28,
        display: "grid",
        gridTemplateColumns: columns,
        alignItems: "center",
        height: 73,
        fontSize: 16,
        opacity: interpolate(
          frame,
          [
            appears * fps,
            (appears + 0.16) * fps,
            (disappears - 0.16) * fps,
            disappears * fps,
          ],
          [0, 1, 1, 0],
          clamp,
        ),
        translate: `0 ${interpolate(frame, [appears * fps, (appears + 0.25) * fps], [16, 0], smooth)}px`,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 18,
          paddingLeft: 13,
        }}
      >
        <Interactive.Div
          name={`${number}: selection checkbox`}
          style={{
            width: 18,
            height: 18,
            boxSizing: "border-box",
            border: `2px solid ${checked ? PINK : started ? "#626267" : "#b4b4b7"}`,
            borderRadius: 2,
            flexShrink: 0,
            background: checked ? PINK : "transparent",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          {checked && (
            <svg width="13" height="13" viewBox="0 0 16 16">
              <path
                d="m3 8 3.2 3.2L13 4"
                fill="none"
                stroke="#242027"
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
          )}
        </Interactive.Div>
        <Pill
          name={`${number}: Download`}
          disabled={started}
          pressed={!selected && time >= 2.16 && time < 2.28}
          style={{ width: 116, flexShrink: 0 }}
        >
          Downlo...
        </Pill>
      </div>
      <Interactive.Div
        name={`${number}: title`}
        style={{
          overflow: "hidden",
          whiteSpace: "nowrap",
          textOverflow: "ellipsis",
          paddingRight: 16,
        }}
      >
        {number}) {title}
      </Interactive.Div>
      <Interactive.Div name={`${number}: author`}>{author}</Interactive.Div>
      <Interactive.Div name={`${number}: duration`}>
        {duration} min
      </Interactive.Div>
      <Interactive.Div
        name={`${number}: quality dropdown`}
        style={{
          width: 100,
          height: 56,
          border: "1px solid #606064",
          borderRadius: 5,
          display: "flex",
          alignItems: "center",
          padding: "0 15px",
          boxSizing: "border-box",
          gap: 30,
        }}
      >
        720
        <span
          style={{
            width: 0,
            height: 0,
            borderLeft: "5px solid transparent",
            borderRight: "5px solid transparent",
            borderTop: "5px solid #fafafa",
          }}
        />
      </Interactive.Div>
      <Pill
        name={`${number}: Stop / Resume`}
        disabled={!running}
        style={{ width: 90 }}
      >
        {running ? (
          <span style={{ width: 11, height: 11, background: "#fafafa" }} />
        ) : (
          <span
            style={{
              width: 0,
              height: 0,
              borderTop: "7px solid transparent",
              borderBottom: "7px solid transparent",
              borderLeft: "11px solid #77777a",
            }}
          />
        )}
      </Pill>
      <Interactive.Div
        name={`${number}: progress`}
        style={{
          width: 180,
          height: 30,
          position: "relative",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontVariantNumeric: "tabular-nums",
          fontWeight: 600,
        }}
      >
        <div
          style={{
            position: "absolute",
            left: 0,
            right: 0,
            top: 13,
            height: 4,
            background: "#58404d",
          }}
        />
        <Interactive.Div
          name={`${number}: progress fill`}
          style={{
            position: "absolute",
            left: 0,
            top: 13,
            height: 4,
            width: `${interpolate(frame, [starts * fps, completes * fps], [0, 100], clamp)}%`,
            background: PINK,
            boxShadow: running ? "0 0 14px #f28bb460" : "none",
          }}
        />
        <span style={{ position: "relative", textShadow: "0 1px 4px #1b1b1e" }}>
          {progress}%
        </span>
      </Interactive.Div>
    </Interactive.Div>
  );
};

const Downloads = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const time = frame / fps;
  const empty = time < 1.86 || (time >= 4.55 && time < 5.98) || time >= 9.42;
  return (
    <>
      <Interactive.Div
        name="Download table headings"
        style={{
          position: "absolute",
          left: 28,
          top: 382,
          display: "grid",
          gridTemplateColumns: columns,
          fontSize: 16,
        }}
      >
        {[
          "Select / Download",
          "Title",
          "Author",
          "Duration",
          "Quality",
          "Stop / Resume",
          "Progress",
        ].map((label) => (
          <div
            key={label}
            style={{
              whiteSpace: "nowrap",
              fontSize: label === "Stop / Resume" ? 14 : 16,
            }}
          >
            {label}
          </div>
        ))}
      </Interactive.Div>
      {empty && (
        <Interactive.Div
          name="No downloads"
          style={{
            position: "absolute",
            top: 527,
            left: 0,
            right: 0,
            textAlign: "center",
            fontSize: 16,
            opacity:
              time >= 9.42
                ? interpolate(frame, [9.42 * fps, 9.65 * fps], [0, 1], clamp)
                : 1,
          }}
        >
          No downloads
        </Interactive.Div>
      )}
      <DownloadRow
        number={1}
        title="Midnight in motion — The film"
        author="Aurora Studio"
        duration="18"
        appears={1.86}
        starts={2.2}
        completes={3.95}
        disappears={4.55}
      />
      <DownloadRow
        number={1}
        title="Midnight in motion — The film"
        author="Aurora Studio"
        duration="18"
        appears={5.98}
        starts={7.17}
        completes={8.55}
        disappears={9.42}
        selected
      />
      <DownloadRow
        number={2}
        title="After hours — Studio session"
        author="Aurora Studio"
        duration="14"
        appears={6.08}
        starts={7.17}
        completes={8.65}
        disappears={9.42}
        selected
      />
      <DownloadRow
        number={3}
        title="Velvet skies — Director’s cut"
        author="Aurora Studio"
        duration="16"
        appears={6.18}
        starts={7.17}
        completes={8.75}
        disappears={9.42}
        selected
      />
      <DownloadRow
        number={4}
        title="Neon reflections — The collection"
        author="Aurora Studio"
        duration="12"
        appears={6.28}
        starts={7.17}
        completes={8.85}
        disappears={9.42}
        selected
      />
    </>
  );
};

const DemoPointer = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const t = frame / fps;
  const ripple = [1.7, 2.2, 5.86, 6.57, 7.07].find(
    (click) => t >= click && t <= click + 0.28,
  );
  return (
    <Interactive.Div
      name="Demo cursor and click feedback"
      style={{
        position: "absolute",
        zIndex: 10,
        left: 0,
        top: 0,
        translate: `${interpolate(frame, [0, 1.35 * fps, 1.64 * fps, 1.85 * fps, 2.14 * fps, 2.35 * fps, 4.8 * fps, 5.58 * fps, 5.8 * fps, 6.03 * fps, 6.5 * fps, 6.7 * fps, 7.01 * fps, 7.35 * fps, 9.5 * fps, 10 * fps], [1160, 1160, 1310, 1310, 130, 130, 1130, 1130, 1310, 1310, 86, 86, 1260, 1260, 1160, 1160], smooth)}px ${interpolate(frame, [0, 1.35 * fps, 1.64 * fps, 1.85 * fps, 2.14 * fps, 2.35 * fps, 4.8 * fps, 5.58 * fps, 5.8 * fps, 6.03 * fps, 6.5 * fps, 6.7 * fps, 7.01 * fps, 7.35 * fps, 9.5 * fps, 10 * fps], [140, 140, 105, 105, 448, 448, 163, 163, 163, 163, 345, 345, 345, 345, 140, 140], smooth)}px`,
        opacity: interpolate(
          frame,
          [
            0,
            1.25 * fps,
            1.45 * fps,
            2.4 * fps,
            2.7 * fps,
            5.45 * fps,
            5.65 * fps,
            7.4 * fps,
            7.65 * fps,
            10 * fps,
          ],
          [0, 0, 1, 1, 0, 0, 1, 1, 0, 0],
          clamp,
        ),
      }}
    >
      {ripple !== undefined && (
        <div
          style={{
            position: "absolute",
            width: 74,
            height: 74,
            left: -37,
            top: -37,
            borderRadius: "50%",
            border: `1.5px solid ${PINK}`,
            background: "#f28bb410",
            scale: interpolate(
              frame,
              [ripple * fps, (ripple + 0.28) * fps],
              [0.25, 1.3],
              clamp,
            ),
            opacity: interpolate(
              frame,
              [ripple * fps, (ripple + 0.28) * fps],
              [0.85, 0],
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

export const AppWindow = ({
  children,
  active = "download",
}: {
  children: React.ReactNode;
  active?: string;
}) => (
  <Interactive.Div
    name="Porn Fetch · editable desktop interface"
    style={{
      width: 1392,
      height: 718,
      position: "relative",
      borderRadius: 15,
      background: PANEL,
      border: "1.5px solid #38a5e8",
      boxSizing: "border-box",
      color: "#f7f7f8",
      fontFamily: "Arial, sans-serif",
      boxShadow: "0 35px 90px #0009, 0 0 0 7px #ffffff03, 0 0 65px #f28bb40b",
      overflow: "hidden",
    }}
  >
    <div
      style={{
        position: "absolute",
        left: 9,
        right: 9,
        top: 63,
        bottom: 9,
        border: "2px solid #080809",
        borderRadius: 11,
      }}
    />
    <Navigation active={active} />
    {children}
  </Interactive.Div>
);

export const FetchInterface = () => (
  <AppWindow>
    <UrlField kind="Video" index={0} />
    <UrlField kind="Model" index={1} />
    <UrlField kind="Playlist" index={2} />
    <DownloadActions />
    <Downloads />
    <DemoPointer />
  </AppWindow>
);
