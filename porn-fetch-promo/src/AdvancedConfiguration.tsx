import {
  Interactive,
  interpolate,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { AppWindow, Pill, UrlField } from "./FetchInterface";
import {
  Check,
  Dropdown,
  Field,
  Spin,
  FeatureCursor,
  clamp,
  glide,
} from "./FeaturePrimitives";

const Group = ({
  name,
  top,
  height,
  children,
}: {
  name: string;
  top: number;
  height: number;
  children: React.ReactNode;
}) => (
  <Interactive.Div
    name={name}
    style={{ position: "absolute", left: 0, right: 0, top }}
  >
    <div style={{ height: 24, paddingLeft: 12, fontSize: 16 }}>{name}</div>
    <div
      style={{
        position: "relative",
        border: "1px solid #626264",
        borderRadius: 3,
        height,
        padding: 12,
        boxSizing: "border-box",
      }}
    >
      {children}
    </div>
  </Interactive.Div>
);

const FilterRow = ({
  label,
  row,
  children,
}: {
  label: string;
  row: number;
  children: React.ReactNode;
}) => (
  <div
    style={{
      position: "absolute",
      left: 12,
      right: 12,
      top: 12 + row * 66,
      display: "flex",
      alignItems: "center",
      gap: 12,
      height: 56,
    }}
  >
    <div style={{ width: 142, flexShrink: 0 }}>{label}</div>
    <div style={{ flex: 1, display: "flex", gap: 12, alignItems: "center" }}>
      {children}
    </div>
  </div>
);

export const AdvancedConfiguration = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const t = frame / fps;
  const template = "$author - ${publish_dt:%Y-%m-%d} - $title";
  const typed = template.slice(
    0,
    Math.floor(
      interpolate(frame, [2.15 * fps, 3.2 * fps], [0, template.length], clamp),
    ),
  );
  return (
    <AppWindow>
      <UrlField kind="Video" index={0} demo={false} />
      <UrlField kind="Model" index={1} demo={false} />
      <UrlField kind="Playlist" index={2} demo={false} />
      <Interactive.Div
        name="Advanced Configuration tab"
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
        <Pill name="Downloads">Downloads</Pill>
        <Pill name="Advanced Configuration" pink>
          Advanced Configuration
        </Pill>
        <Pill name="Cancel Loading" disabled>
          Cancel Loading
        </Pill>
      </Interactive.Div>
      <Interactive.Div
        name="Configuration scrolling viewport"
        style={{
          position: "absolute",
          top: 315,
          left: 16,
          right: 26,
          bottom: 20,
          overflow: "hidden",
          fontSize: 16,
        }}
      >
        <Interactive.Div
          name="Filters and filename template"
          style={{
            position: "absolute",
            left: 0,
            right: 18,
            height: 790,
            translate: `0 ${interpolate(frame, [0, 0.5 * fps, 1.1 * fps, 1.45 * fps, 2.1 * fps], [0, 0, -205, -205, -400], glide)}px`,
          }}
        >
          <Group name="General Operations" top={0} height={138}>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1.8fr",
                gap: 12,
              }}
            >
              <Check label="Do not clear videos" />
              <Check label="Cleanup on stop (disables resume for HLS)" />
            </div>
            <div
              style={{
                display: "flex",
                gap: 16,
                alignItems: "center",
                marginTop: 25,
              }}
            >
              <span>Start:</span>
              <Spin name="Start index" value={0} style={{ flex: 1 }} />
              <span>End:</span>
              <Spin name="End index" value={0} style={{ flex: 2 }} />
            </div>
          </Group>
          <Group
            name="Video Filters (Applied during fetch)"
            top={182}
            height={420}
          >
            <FilterRow label="Duration (Minutes):" row={0}>
              <Spin
                name="Minimum duration"
                value={t > 0.25 ? "5 min" : "Any"}
                focus={t > 0.25 && t < 0.6}
                style={{ flex: 1 }}
              />
              <span>-</span>
              <Spin
                name="Maximum duration"
                value={t > 0.4 ? "30 min" : "Any"}
                style={{ flex: 1 }}
              />
            </FilterRow>
            <FilterRow label="Title Regex:" row={1}>
              <Field
                name="Title regex filter"
                value={
                  t > 0.55
                    ? "Midnight|Velvet".slice(
                        0,
                        Math.floor(
                          interpolate(
                            frame,
                            [0.55 * fps, 0.95 * fps],
                            [0, 15],
                            clamp,
                          ),
                        ),
                      )
                    : undefined
                }
                placeholder="e.g., ^Step.*"
                focus={t > 0.55 && t < 0.95}
                style={{ flex: 1 }}
              />
            </FilterRow>
            <FilterRow label="Author Regex:" row={2}>
              <Field
                name="Author regex filter"
                value={t > 0.95 ? ".*Studio$" : undefined}
                placeholder="e.g., .*Studio$"
                focus={t > 0.95 && t < 1.15}
                style={{ flex: 1 }}
              />
            </FilterRow>
            <FilterRow label="Tags Regex:" row={3}>
              <Field
                name="Tags regex filter"
                value={t > 1.1 ? "studio|cinematic" : undefined}
                placeholder="e.g., pov|amateur"
                focus={t > 1.1 && t < 1.3}
                style={{ flex: 1 }}
              />
            </FilterRow>
            <FilterRow label="Quality Range:" row={4}>
              <Dropdown
                name="Minimum quality"
                value={t > 1.25 ? "720p" : "Any"}
                focus={t > 1.25 && t < 1.55}
                style={{ flex: 1 }}
              />
              <span>to</span>
              <Dropdown
                name="Maximum quality"
                value={t > 1.4 ? "1080p" : "Any"}
                style={{ flex: 1 }}
              />
            </FilterRow>
            <FilterRow label="Publish Date:" row={5}>
              <Field
                name="Published after"
                value={t > 1.6 ? "2026-01-01" : undefined}
                placeholder="After (YYYY-MM-DD)"
                focus={t > 1.6 && t < 1.85}
                style={{ flex: 1 }}
              />
              <span>-</span>
              <Field
                name="Published before"
                value={t > 1.75 ? "2026-10-23" : undefined}
                placeholder="Before (YYYY-MM-DD)"
                style={{ flex: 1 }}
              />
            </FilterRow>
          </Group>
          <Group name="Output" top={632} height={80}>
            <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
              <div style={{ width: 177, flexShrink: 0 }}>
                Custom Title formatting:
              </div>
              <Field
                name="Custom title formatting template"
                placeholder="$title"
                value={typed || undefined}
                focus={t >= 2.15}
                style={{
                  flex: 1,
                  fontSize: 19,
                  fontFamily: "monospace",
                  color: typed ? "#f28bb4" : undefined,
                }}
              >
                {typed && (
                  <>
                    {typed}
                    <span
                      style={{
                        width: 1,
                        height: 22,
                        marginLeft: 2,
                        background: "#f28bb4",
                        opacity: t < 3.3 && Math.sin(t * 12) > -0.2 ? 1 : 0,
                      }}
                    />
                  </>
                )}
              </Field>
              <Pill name="Formatting Options" style={{ width: 108 }}>
                Options
              </Pill>
            </div>
          </Group>
          <Pill
            name="Keyboard shortcuts"
            style={{ position: "absolute", top: 737, left: 0, right: 0 }}
          >
            Keyboard shortcuts
          </Pill>
        </Interactive.Div>
      </Interactive.Div>
      <div
        style={{
          position: "absolute",
          right: 12,
          top: 315,
          width: 12,
          height: 210,
          background: "#545456",
          translate: `0 ${interpolate(frame, [0.5 * fps, 2.1 * fps], [0, 168], glide)}px`,
        }}
      />
      <FeatureCursor
        points={[
          [0, 640, 283],
          [0.3, 640, 283],
          [0.9, 585, 460],
          [1.2, 720, 620],
          [1.4, 720, 620],
          [2.1, 700, 615],
          [3.25, 850, 615],
        ]}
        clicks={[0.1, 1.25, 2.15]}
        until={3.45}
      />
    </AppWindow>
  );
};
