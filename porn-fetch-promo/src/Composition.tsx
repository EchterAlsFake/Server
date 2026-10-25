import { Composition } from "remotion";
import { PornFetchPromo } from "./Promo";

export const MyComposition = () => (
  <Composition
    id="MyComp"
    component={PornFetchPromo}
    durationInFrames={2400}
    fps={60}
    width={1920}
    height={1080}
  />
);

export { PornFetchPromo as MyComponent } from "./Promo";
