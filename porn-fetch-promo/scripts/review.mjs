import { bundle } from "@remotion/bundler";
import {
  openBrowser,
  renderStill,
  selectComposition,
} from "@remotion/renderer";
import { mkdir } from "node:fs/promises";

// Reuse one browser and bundle when checking the main interaction beats.
const browser = await openBrowser("chrome", {
  browserExecutable: process.env.REMOTION_BROWSER_EXECUTABLE,
});
try {
  await mkdir("out/checks", { recursive: true });
  const serveUrl = await bundle({ entryPoint: "src/index.ts", rspack: true });
  const composition = await selectComposition({
    serveUrl,
    id: "MyComp",
    puppeteerInstance: browser,
  });
  const frames = process.argv[2]
    ? process.argv[2].split(",").map(Number)
    : [
        0, 108, 300, 570, 648, 780, 930, 1020, 1140, 1260, 1440, 1680, 1890,
        2148, 2364, 2399,
      ];
  for (const frame of frames) {
    await renderStill({
      serveUrl,
      composition,
      frame,
      imageFormat: "png",
      output: `out/checks/frame-${String(frame).padStart(3, "0")}.png`,
      puppeteerInstance: browser,
    });
    console.log(`Checked frame ${frame}`);
  }
} finally {
  await browser.close({ silent: true });
}
