# Media Archiver Release Pre-flight Checklist

This checklist ensures that server-side updates are fully prepared *before* a new release is published to GitHub. This is especially critical when a new release introduces a **new license key pair**, as failing to follow these steps in order can result in broken updates or rejected licenses.

---

## 🔏 1. Update the License Private Key
Because the new app version expects a new public key for verification, the server must begin signing purchases with the new private key immediately upon launch.

- [ ] Open the `.env` file on your server.
- [ ] Replace `LICENSE_PRIVATE_KEY_B64` with the Base64-encoded version of your **new** Ed25519 private key.
- [ ] *(Optional Housekeeping)*: Replace `mediafetch_public_key.key` in the server directory with your new public key for reference/backups.

## 📝 2. Update the Local Changelog
The server provides the release notes for the auto-updater by reading a local Markdown file, *not* from GitHub.

- [ ] Edit `media_archiver_changelog.md` on the server.
- [ ] Add the release notes for the new version.

## 🍏 3. Generate and Upload the macOS Sparkle Signature (CRITICAL)
Your macOS update endpoint (`/appcast.xml`) relies on a locally stored signature file to validate the downloaded `.dmg`.

- [ ] Boot up your macOS Virtual Machine.
- [ ] Generate the Sparkle signature using the `sign_update` tool (see detailed instructions below).
- [ ] Create a plain text file named **exactly** after the Git tag you are about to publish (e.g., `v2.0.0.txt`).
- [ ] Paste **only** the Base64 signature string into this file.
- [ ] Upload this file into the `signatures/` directory on your server.

> **Warning:** If you publish the release on GitHub first, the server's 5-minute cache will eventually see it. If `signatures/{tag}.txt` is missing by then, the `/appcast.xml` endpoint will crash with a `FileNotFoundError`, breaking auto-updates for all existing macOS users.

## 🔄 4. Restart the Server
Environment variables are loaded when the process starts.

- [ ] Restart your Flask/Gunicorn server process (e.g., `sudo systemctl restart <your-service-name>`).
- [ ] Verify the server is responding by visiting the `/ping` endpoint.

## 🚀 5. Publish on GitHub
- [ ] Go to GitHub and hit **Publish release**. 

*(Note: Try to perform steps 4 and 5 closely together. Once the server restarts, all new purchases get the new license key. You want the new app download available on GitHub immediately so users don't accidentally download the old app and try to use a new license with it).*

---

# 📖 Appendix: How to Use the Sparkle `sign_update` Tool

Since you use a macOS VM infrequently, here is a refresher on how to generate the Sparkle signature for your macOS release.

Sparkle 2 uses Ed25519 signatures. Your private key is typically stored securely in your macOS Keychain (named "Sparkle Ed25519 Private Key") or provided via an exported file.

### Step-by-Step Instructions:

1. **Locate the `sign_update` executable:**
   This tool comes bundled with the Sparkle framework distribution you downloaded when setting up auto-updates. Navigate to the `bin` folder within the Sparkle distribution in your terminal.
   
   ```bash
   cd /path/to/Sparkle/bin
   ```

2. **Run the tool against your `.dmg` file:**
   Run the `sign_update` command and point it to the final, ready-to-distribute `.dmg` file.
   
   ```bash
   ./sign_update /path/to/MediaArchiver_macOS_GUI_Universal.dmg
   ```

3. **Extract the signature:**
   If your private key is in the macOS Keychain, the tool will automatically find it, calculate the signature, and output something like this:
   
   ```text
   sparkle:edSignature="GqGxA...[long base64 string]...hBg==" length="14560000"
   ```

4. **Copy the Base64 String:**
   Look at the output and copy **ONLY** the string inside the quotes of `sparkle:edSignature`. Do not copy the quotes, the `sparkle:edSignature=` prefix, or the `length` property.
   
   *Example: If the output is `sparkle:edSignature="abc123XYZ=="`, you only copy `abc123XYZ==`.*

5. **Save to the server:**
   Paste that exact string into your `vX.X.X.txt` file (e.g., `v1.2.3.txt`) and place it in the `signatures/` folder on the server.

### Troubleshooting Sparkle Keys:
*   If the tool says it can't find your keys, you may need to supply the keys manually if they aren't in the Keychain. You can do this by using the `-s` flag followed by your private key string:
    `./sign_update -s <YOUR_ED25519_PRIVATE_KEY> /path/to/MediaArchiver_macOS_GUI_Universal.dmg`
*   Ensure the `.dmg` you are signing is the exact same, unmodified binary you are uploading to GitHub. Changing even a single byte after signing will break the update process for users.
