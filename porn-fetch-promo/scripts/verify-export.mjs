import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";

// Check the encoded artifact: stills alone did not expose the previous
// renderer-dependent, four-copy compositing glitch.
const file = process.argv[2] || "out/porn-fetch-tour-40s.mp4";
const metadata = JSON.parse(
  execFileSync(
    "ffprobe",
    ["-v", "error", "-show_streams", "-show_format", "-of", "json", file],
    { encoding: "utf8" },
  ),
);
const video = metadata.streams.find((stream) => stream.codec_type === "video");
if (
  video?.width !== 1920 ||
  video?.height !== 1080 ||
  video?.r_frame_rate !== "60/1" ||
  Number(video?.nb_frames) !== 2400 ||
  Number(metadata.format.duration) !== 40 ||
  metadata.streams.some((stream) => stream.codec_type === "audio")
)
  throw new Error(
    "Export dimensions, frame rate, frame count, duration or audio do not match the composition.",
  );
console.log(
  "Verified: 1920×1080 · 60fps · 2400 frames · 40 seconds · no audio",
);

const frames = [108, 648, 930, 1020, 1140, 1260, 1440, 1680, 1890, 2148, 2364];
mkdirSync("out/encoded", { recursive: true });
execFileSync("ffmpeg", [
  "-v",
  "error",
  "-y",
  "-i",
  file,
  "-vf",
  `select=${frames.map((frame) => `eq(n\\,${frame})`).join("+")}`,
  "-fps_mode",
  "vfr",
  "out/encoded/frame-%02d.png",
]);
for (const [index, frame] of frames.entries()) {
  const result = spawnSync(
    "ffmpeg",
    [
      "-hide_banner",
      "-i",
      `out/checks/frame-${String(frame).padStart(3, "0")}.png`,
      "-i",
      `out/encoded/frame-${String(index + 1).padStart(2, "0")}.png`,
      "-lavfi",
      "ssim",
      "-f",
      "null",
      "-",
    ],
    { encoding: "utf8" },
  );
  const similarity = Number(result.stderr?.match(/All:([\d.]+)/)?.[1]);
  if (result.status !== 0 || !Number.isFinite(similarity) || similarity < 0.96)
    throw new Error(
      `Frame ${frame} differs from the reviewed still (SSIM ${similarity}). ${result.stderr}`,
    );
  console.log(
    `Encoded frame ${frame} matches reviewed layout: SSIM ${similarity.toFixed(5)}`,
  );
}
