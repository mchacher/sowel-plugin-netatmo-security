# Sowel Plugin — Netatmo Security

Sowel integration plugin for Netatmo Security cameras. Discovers cameras, polls their status, and allows toggling monitoring on/off.

## Supported cameras

| Type       | Product                |
| ---------- | ---------------------- |
| NACamera   | Welcome (Indoor)       |
| NOC        | Presence (Outdoor)     |
| NDB        | Doorbell               |
| NPC        | Indoor Advance         |

## Features

- Auto-discovery of all cameras linked to your Netatmo home
- Polls camera status every 5 minutes (configurable): monitoring state, SD card status, Wi-Fi strength
- Toggle camera monitoring on/off via Sowel orders

## Installation

### Via Sowel plugin store

Search for "Netatmo Security" in Administration > Integrations and click Install.

### Manual installation

1. Clone this repository into the Sowel plugins directory:
   ```bash
   cd /path/to/sowel/plugins
   git clone https://github.com/mchacher/sowel-plugin-netatmo-security.git netatmo-security
   cd netatmo-security
   npm install
   npm run build
   ```
2. Restart Sowel. The plugin will appear in Administration > Integrations.

## Netatmo credentials

1. Go to [dev.netatmo.com](https://dev.netatmo.com) and create an app.
2. Note the **Client ID** and **Client Secret**.
3. Generate a token with the following scopes:
   - `read_camera`
   - `write_camera`
   - `access_camera`
   - `read_presence`
   - `write_presence`
   - `access_presence`
4. Copy the **Refresh Token** from the token generation page.
5. Enter all three values in the plugin settings within Sowel (Administration > Integrations > Netatmo Security).

## Configuration

| Setting          | Required | Default | Description                          |
| ---------------- | -------- | ------- | ------------------------------------ |
| Client ID        | Yes      | —       | Netatmo app client ID                |
| Client Secret    | Yes      | —       | Netatmo app client secret            |
| Refresh Token    | Yes      | —       | OAuth2 refresh token (rotated)       |
| Polling interval | No       | 300     | Status polling interval in seconds   |

## License

AGPL-3.0
