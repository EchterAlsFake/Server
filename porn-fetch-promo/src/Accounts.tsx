import { Interactive, useCurrentFrame, useVideoConfig } from "remotion";
import { AppWindow, Pill, PINK } from "./FetchInterface";
import { Field, FeatureCursor } from "./FeaturePrimitives";

export const Accounts = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const t = frame / fps;
  // Each provider stays visible for exactly two seconds. Only the tabs are clicked.
  const index = t < 2 ? 0 : t < 4 ? 1 : 2;
  const provider = ["PornHub", "XHamster", "XVideos"][index];
  const ph = index === 0;
  const xv = index === 2;
  const logged = false;
  const busy = false;
  const username = "";
  const loginY = ph ? 368 : 306;
  const retrievalY = ph ? 426 : 364;
  const fetched = false;
  return (
    <AppWindow active="account">
      <Interactive.Div
        name="Account provider tabs"
        style={{
          position: "absolute",
          left: 16,
          right: 16,
          top: 70,
          height: 49,
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
        }}
      >
        {["PornHub", "XHamster", "XVideos"].map((name, i) => (
          <div
            key={name}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              borderBottom: `2px solid ${i === index ? PINK : "transparent"}`,
              color: i === index ? PINK : "#f7f7f8",
              fontSize: 16,
            }}
          >
            {name}
          </div>
        ))}
      </Interactive.Div>
      <Interactive.Div
        name="Account sign-in instructions"
        style={{ position: "absolute", left: 16, top: 128, fontSize: 16 }}
      >
        {xv
          ? "XVideos uses session tokens instead of an email and password. You can paste both tokens below or import them from your browser."
          : `Sign in with your ${provider} ${ph ? "email address" : "username"} and password, or import the login from your browser.`}
      </Interactive.Div>
      <Interactive.Div
        name="Account login status"
        style={{
          position: "absolute",
          left: 16,
          top: 154,
          fontSize: 16,
          color: logged ? PINK : "#f7f7f8",
        }}
      >
        {logged ? "Logged in to" : "Not logged in to"} {provider}
      </Interactive.Div>
      {ph && (
        <Field
          name="PornHub browser cookie username"
          value={username || undefined}
          placeholder="PornHub username for browser cookies (not email)"
          focus={false}
          style={{ position: "absolute", left: 16, right: 16, top: 177 }}
        />
      )}
      <div
        style={{
          position: "absolute",
          left: 16,
          right: 16,
          top: ph ? 239 : 177,
          display: "grid",
          gridTemplateColumns: xv ? "143px 1fr" : "76px 1fr",
          whiteSpace: "nowrap",
          alignItems: "center",
          gap: "6px 5px",
          fontSize: 16,
        }}
      >
        <span>{xv ? "Session token:" : ph ? "Email:" : "Username:"}</span>
        <Field
          name={`${provider} identity`}
          placeholder={
            xv
              ? "Enter session_token"
              : ph
                ? "Enter your email address"
                : "Enter your username"
          }
        />
        <span>{xv ? "Session token auth:" : "Password:"}</span>
        <Field
          name={`${provider} secret`}
          placeholder={xv ? "Enter session_token_auth" : "Enter your password"}
        />
      </div>
      <div
        style={{
          position: "absolute",
          left: 16,
          right: 16,
          top: loginY,
          display: "grid",
          gridTemplateColumns: xv ? "1fr 1fr" : "345px 1fr",
          gap: 6,
        }}
      >
        <Pill name={`${provider}: Login`} disabled>
          {xv ? "Login with Session Tokens" : "Login"}
        </Pill>
        <Pill
          name={`${provider}: Login with Browser Cookies`}
          disabled={busy || (ph && !username)}
        >
          Login with Browser Cookies
        </Pill>
      </div>
      {ph ? (
        <>
          <div
            style={{
              position: "absolute",
              left: 16,
              right: 16,
              top: retrievalY,
              display: "grid",
              gridTemplateColumns: "1fr 1.26fr 1.1fr",
              gap: 5,
            }}
          >
            <Pill name="Get Watch History" disabled={!logged}>
              Get Watch History
            </Pill>
            <Pill name="Get Recommended Videos" disabled={!logged}>
              Get Recommended Videos
            </Pill>
            <Pill name="Get Subscription Feed" disabled={!logged}>
              Get Subscription Feed
            </Pill>
          </div>
          <Pill
            name="Get Favorite Videos"
            disabled={!logged}
            style={{ position: "absolute", left: 16, top: 483, width: 385 }}
          >
            Get Favorite Videos
          </Pill>
        </>
      ) : xv ? (
        <div
          style={{
            position: "absolute",
            left: 16,
            right: 16,
            top: retrievalY,
            display: "grid",
            gridTemplateColumns: "1.2fr 1fr 1fr",
            gap: 5,
          }}
        >
          <Pill name="Get Watch Later Videos" disabled={!logged}>
            Get Watch Later Videos
          </Pill>
          <Pill name="Get Watch History" disabled={!logged}>
            Get Watch History
          </Pill>
          <Pill name="Get Liked Videos" disabled={!logged}>
            Get Liked Videos
          </Pill>
        </div>
      ) : (
        <>
          <Pill
            name="Get Liked Videos"
            disabled={!logged}
            style={{
              position: "absolute",
              left: 16,
              right: 16,
              top: retrievalY,
            }}
          >
            Get Liked Videos
          </Pill>
          <div
            style={{
              position: "absolute",
              left: 16,
              right: 16,
              top: 416,
              display: "flex",
              alignItems: "center",
              gap: 6,
              fontSize: 16,
            }}
          >
            <span>Account playlist URL:</span>
            <Field
              name="Account playlist URL"
              placeholder="https://xhamster.com/my/playlists/..."
              style={{ flex: 1 }}
            />
            <Pill name="Get Playlist Videos" disabled style={{ width: 175 }}>
              Get Playlist Videos
            </Pill>
          </div>
        </>
      )}
      <Interactive.Div
        name="Account videos destination"
        style={{
          position: "absolute",
          left: 0,
          right: 0,
          top: ph ? 556 : xv ? 436 : 498,
          textAlign: "center",
          fontSize: 16,
          color: fetched ? PINK : "#f7f7f8",
        }}
      >
        Retrieved videos are added to the Downloads page
      </Interactive.Div>
      <FeatureCursor
        points={[
          [0, 244, 94],
          [1.65, 244, 94],
          [2, 696, 94],
          [3.65, 696, 94],
          [4, 1150, 94],
          [5.8, 1150, 94],
        ]}
        clicks={[0, 2, 4]}
        until={5.95}
      />
    </AppWindow>
  );
};
