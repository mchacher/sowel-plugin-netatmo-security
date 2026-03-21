/**
 * Sowel Plugin — Netatmo Security
 *
 * Discovers Netatmo cameras (Welcome, Presence, Doorbell, Indoor Advance),
 * polls their status, and allows toggling monitoring on/off.
 */

// ============================================================
// Local type definitions (no imports from Sowel source)
// ============================================================

interface Logger {
  child(bindings: Record<string, unknown>): Logger;
  info(obj: Record<string, unknown>, msg: string): void;
  info(msg: string): void;
  warn(obj: Record<string, unknown>, msg: string): void;
  warn(msg: string): void;
  error(obj: Record<string, unknown>, msg: string): void;
  error(msg: string): void;
  debug(obj: Record<string, unknown>, msg: string): void;
  debug(msg: string): void;
}

interface EventBus {
  emit(event: unknown): void;
}

interface SettingsManager {
  get(key: string): string | undefined;
  set(key: string, value: string): void;
}

interface DiscoveredDevice {
  ieeeAddress?: string;
  friendlyName: string;
  manufacturer?: string;
  model?: string;
  data: {
    key: string;
    type: string;
    category: string;
    unit?: string;
  }[];
  orders: {
    key: string;
    type: string;
    dispatchConfig: Record<string, unknown>;
    min?: number;
    max?: number;
    enumValues?: string[];
    unit?: string;
  }[];
}

interface DeviceManager {
  upsertFromDiscovery(
    integrationId: string,
    source: string,
    discovered: DiscoveredDevice,
  ): void;
  updateDeviceData(
    integrationId: string,
    sourceDeviceId: string,
    payload: Record<string, unknown>,
  ): void;
}

interface Device {
  id: string;
  integrationId: string;
  sourceDeviceId: string;
  name: string;
  manufacturer?: string;
  model?: string;
}

interface PluginDeps {
  logger: Logger;
  eventBus: EventBus;
  settingsManager: SettingsManager;
  deviceManager: DeviceManager;
  pluginDir: string;
}

type IntegrationStatus = "connected" | "disconnected" | "not_configured" | "error";

interface IntegrationSettingDef {
  key: string;
  label: string;
  type: "text" | "password" | "number" | "boolean";
  required: boolean;
  placeholder?: string;
  defaultValue?: string;
}

interface IntegrationPlugin {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly icon: string;
  getStatus(): IntegrationStatus;
  isConfigured(): boolean;
  getSettingsSchema(): IntegrationSettingDef[];
  start(options?: { pollOffset?: number }): Promise<void>;
  stop(): Promise<void>;
  executeOrder(
    device: Device,
    dispatchConfig: Record<string, unknown>,
    value: unknown,
  ): Promise<void>;
  refresh?(): Promise<void>;
  getPollingInfo?(): { lastPollAt: string; intervalMs: number } | null;
}

// ============================================================
// Netatmo API types
// ============================================================

interface NetatmoTokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  scope: string[];
}

interface NetatmoHomesDataResponse {
  body: {
    homes: {
      id: string;
      name: string;
    }[];
  };
}

interface NetatmoCameraModule {
  id: string;
  type: string;
  name: string;
  monitoring?: string;
  sd_status?: number;
  alim_status?: number;
  wifi_strength?: number;
}

interface NetatmoHomeStatusResponse {
  body: {
    home: {
      id: string;
      modules: NetatmoCameraModule[];
    };
  };
}

// ============================================================
// Constants
// ============================================================

const PLUGIN_ID = "netatmo-security";
const SETTINGS_PREFIX = `integration.${PLUGIN_ID}.`;
const NETATMO_BASE_URL = "https://api.netatmo.com";
const REQUEST_TIMEOUT_MS = 30_000;
const REFRESH_MARGIN_MS = 300_000; // Refresh token 5 min before expiry
const CAMERA_TYPES = new Set(["NACamera", "NOC", "NDB", "NPC"]);

// ============================================================
// Plugin implementation
// ============================================================

class NetatmoSecurityPlugin implements IntegrationPlugin {
  readonly id = PLUGIN_ID;
  readonly name = "Netatmo Security";
  readonly description = "Netatmo cameras (Welcome, Presence, Doorbell) — monitoring on/off";
  readonly icon = "Camera";

  private logger: Logger;
  private eventBus: EventBus;
  private settingsManager: SettingsManager;
  private deviceManager: DeviceManager;

  // Auth state
  private accessToken: string | null = null;
  private tokenExpiresAt = 0;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;

  // Polling state
  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private lastPollAt: string | null = null;
  private pollIntervalMs = 300_000;

  // Home state
  private homeId: string | null = null;

  // Connection state
  private status: IntegrationStatus = "disconnected";
  private retryTimeout: ReturnType<typeof setTimeout> | null = null;
  private retryCount = 0;

  constructor(deps: PluginDeps) {
    this.logger = deps.logger.child({ module: "netatmo-security" });
    this.eventBus = deps.eventBus;
    this.settingsManager = deps.settingsManager;
    this.deviceManager = deps.deviceManager;
  }

  // ============================================================
  // IntegrationPlugin interface
  // ============================================================

  getStatus(): IntegrationStatus {
    if (!this.isConfigured()) return "not_configured";
    return this.status;
  }

  isConfigured(): boolean {
    return (
      !!this.getSetting("client_id") &&
      !!this.getSetting("client_secret") &&
      !!this.getSetting("refresh_token")
    );
  }

  getSettingsSchema(): IntegrationSettingDef[] {
    return [
      {
        key: "client_id",
        label: "Client ID",
        type: "text",
        required: true,
        placeholder: "From dev.netatmo.com",
      },
      {
        key: "client_secret",
        label: "Client Secret",
        type: "password",
        required: true,
      },
      {
        key: "refresh_token",
        label: "Refresh Token",
        type: "password",
        required: true,
        placeholder: "With camera scopes",
      },
      {
        key: "polling_interval",
        label: "Polling interval (seconds)",
        type: "number",
        required: false,
        defaultValue: "300",
      },
    ];
  }

  async start(options?: { pollOffset?: number }): Promise<void> {
    // Clean up previous state
    this.stopTimers();
    this.accessToken = null;
    this.homeId = null;

    if (!this.isConfigured()) {
      this.status = "not_configured";
      return;
    }

    const rawInterval = parseInt(this.getSetting("polling_interval") ?? "300", 10);
    const pollingIntervalSec = Math.max(180, isNaN(rawInterval) ? 300 : rawInterval);
    this.pollIntervalMs = pollingIntervalSec * 1000;

    try {
      // Step 1: Authenticate (get access token)
      await this.authenticate();

      // Step 2: Get home ID
      this.homeId = await this.fetchHomeId();
      this.logger.info({ homeId: this.homeId }, "Netatmo home discovered");

      // Step 3: Initial poll
      await this.poll();

      // Step 4: Schedule periodic polling
      const offset = options?.pollOffset ?? 0;
      this.schedulePoll(offset);

      this.status = "connected";
      this.retryCount = 0;
      this.eventBus.emit({ type: "system.integration.connected", integrationId: this.id });
      this.logger.info({ pollIntervalMs: this.pollIntervalMs }, "Netatmo Security integration started");
    } catch (err) {
      this.status = "error";
      this.logger.error({ err }, "Failed to start Netatmo Security integration");
      this.scheduleRetry();
    }
  }

  async stop(): Promise<void> {
    this.cancelRetry();
    this.stopTimers();
    this.accessToken = null;
    this.homeId = null;
    this.status = "disconnected";
    this.eventBus.emit({ type: "system.integration.disconnected", integrationId: this.id });
    this.logger.info("Netatmo Security integration stopped");
  }

  async executeOrder(
    device: Device,
    dispatchConfig: Record<string, unknown>,
    value: unknown,
  ): Promise<void> {
    if (this.status !== "connected" || !this.homeId) {
      throw new Error("Netatmo Security integration not connected");
    }

    const param = dispatchConfig["param"] as string | undefined;
    if (param !== "monitoring") {
      throw new Error(`Unsupported order param: ${String(param)}`);
    }

    const monitoringValue = value as string;
    if (monitoringValue !== "on" && monitoringValue !== "off") {
      throw new Error(`Invalid monitoring value: ${monitoringValue}`);
    }

    const cameraId = device.sourceDeviceId;

    await this.callSetState(cameraId, monitoringValue);
    this.logger.info({ cameraId, monitoring: monitoringValue }, "Camera monitoring order executed");

    // Schedule a quick re-poll to confirm the change
    this.scheduleOnDemandPoll();
  }

  async refresh(): Promise<void> {
    if (this.status !== "connected" || !this.homeId) {
      throw new Error("Netatmo Security integration not connected");
    }
    await this.poll();
    this.logger.info("Netatmo Security manual refresh completed");
  }

  getPollingInfo(): { lastPollAt: string; intervalMs: number } | null {
    return { lastPollAt: this.lastPollAt ?? "", intervalMs: this.pollIntervalMs };
  }

  // ============================================================
  // OAuth2 token management
  // ============================================================

  private async authenticate(): Promise<void> {
    await this.doRefreshToken();
    this.scheduleTokenRefresh();
  }

  private async doRefreshToken(): Promise<void> {
    const clientId = this.getSetting("client_id")!;
    const clientSecret = this.getSetting("client_secret")!;
    const refreshToken = this.getSetting("refresh_token")!;

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: clientId,
      client_secret: clientSecret,
    });

    const res = await this.fetchWithTimeout(`${NETATMO_BASE_URL}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Token refresh failed (${res.status}): ${text}`);
    }

    const data = (await res.json()) as NetatmoTokenResponse;
    this.accessToken = data.access_token;
    this.tokenExpiresAt = Date.now() + data.expires_in * 1000;

    // Persist the rotated refresh token back to settings
    if (data.refresh_token) {
      this.settingsManager.set(`${SETTINGS_PREFIX}refresh_token`, data.refresh_token);
    }

    this.logger.info({ expiresIn: data.expires_in }, "Access token refreshed");
  }

  private scheduleTokenRefresh(): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);

    const msUntilExpiry = this.tokenExpiresAt - Date.now();
    const msUntilRefresh = Math.max(msUntilExpiry - REFRESH_MARGIN_MS, 60_000);

    this.refreshTimer = setTimeout(async () => {
      try {
        await this.doRefreshToken();
        this.scheduleTokenRefresh();
      } catch (err) {
        this.logger.error({ err }, "Automatic token refresh failed");
        // Retry in 60s
        this.refreshTimer = setTimeout(() => {
          this.doRefreshToken()
            .then(() => this.scheduleTokenRefresh())
            .catch((retryErr) => {
              this.logger.error({ err: retryErr }, "Token refresh retry failed");
              this.status = "error";
            });
        }, 60_000);
      }
    }, msUntilRefresh);
  }

  /**
   * Ensure we have a valid access token. If expired or missing, refresh.
   * Used before every API call.
   */
  private async ensureToken(): Promise<string> {
    if (!this.accessToken || Date.now() >= this.tokenExpiresAt - REFRESH_MARGIN_MS) {
      await this.doRefreshToken();
      this.scheduleTokenRefresh();
    }
    return this.accessToken!;
  }

  // ============================================================
  // Netatmo API calls
  // ============================================================

  private async fetchHomeId(): Promise<string> {
    const token = await this.ensureToken();

    const res = await this.fetchWithTimeout(`${NETATMO_BASE_URL}/api/homesdata?gateway_types=NACamera&gateway_types=NOC&gateway_types=NDB&gateway_types=NPC`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.status === 401) {
      // Token expired, retry once
      const freshToken = await this.retryWithFreshToken();
      const retryRes = await this.fetchWithTimeout(`${NETATMO_BASE_URL}/api/homesdata?gateway_types=NACamera&gateway_types=NOC&gateway_types=NDB&gateway_types=NPC`, {
        method: "GET",
        headers: { Authorization: `Bearer ${freshToken}` },
      });
      if (!retryRes.ok) {
        const text = await retryRes.text();
        throw new Error(`homesdata failed after token retry (${retryRes.status}): ${text}`);
      }
      const retryData = (await retryRes.json()) as NetatmoHomesDataResponse;
      return this.extractHomeId(retryData);
    }

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`homesdata failed (${res.status}): ${text}`);
    }

    const data = (await res.json()) as NetatmoHomesDataResponse;
    return this.extractHomeId(data);
  }

  private extractHomeId(data: NetatmoHomesDataResponse): string {
    const homes = data.body.homes;
    if (!homes || homes.length === 0) {
      throw new Error("No homes found in Netatmo account");
    }
    return homes[0].id;
  }

  private async fetchHomeStatus(): Promise<NetatmoCameraModule[]> {
    const token = await this.ensureToken();

    const url = `${NETATMO_BASE_URL}/api/homestatus?home_id=${encodeURIComponent(this.homeId!)}`;
    const res = await this.fetchWithTimeout(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.status === 401) {
      const freshToken = await this.retryWithFreshToken();
      const retryRes = await this.fetchWithTimeout(url, {
        method: "GET",
        headers: { Authorization: `Bearer ${freshToken}` },
      });
      if (!retryRes.ok) {
        const text = await retryRes.text();
        throw new Error(`homestatus failed after token retry (${retryRes.status}): ${text}`);
      }
      const retryData = (await retryRes.json()) as NetatmoHomeStatusResponse;
      return this.filterCameraModules(retryData);
    }

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`homestatus failed (${res.status}): ${text}`);
    }

    const data = (await res.json()) as NetatmoHomeStatusResponse;
    return this.filterCameraModules(data);
  }

  private filterCameraModules(data: NetatmoHomeStatusResponse): NetatmoCameraModule[] {
    const modules = data.body.home.modules ?? [];
    return modules.filter((m) => CAMERA_TYPES.has(m.type));
  }

  private async callSetState(cameraId: string, monitoring: string): Promise<void> {
    const token = await this.ensureToken();

    const body = JSON.stringify({
      home: {
        id: this.homeId,
        modules: [{ id: cameraId, monitoring }],
      },
    });

    const res = await this.fetchWithTimeout(`${NETATMO_BASE_URL}/api/setstate`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body,
    });

    if (res.status === 401) {
      const freshToken = await this.retryWithFreshToken();
      const retryRes = await this.fetchWithTimeout(`${NETATMO_BASE_URL}/api/setstate`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${freshToken}`,
          "Content-Type": "application/json",
        },
        body,
      });
      if (!retryRes.ok) {
        const text = await retryRes.text();
        throw new Error(`setstate failed after token retry (${retryRes.status}): ${text}`);
      }
      return;
    }

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`setstate failed (${res.status}): ${text}`);
    }
  }

  /** Force a token refresh and return the new access token (for 401 retry). */
  private async retryWithFreshToken(): Promise<string> {
    this.logger.warn("Got 401, refreshing token and retrying");
    await this.doRefreshToken();
    this.scheduleTokenRefresh();
    return this.accessToken!;
  }

  // ============================================================
  // Polling
  // ============================================================

  private async poll(): Promise<void> {
    try {
      const cameras = await this.fetchHomeStatus();

      this.logger.debug({ cameraCount: cameras.length }, "Camera status polled");

      for (const camera of cameras) {
        // Discover / upsert device definition
        const discovered = this.mapCameraToDiscovered(camera);
        this.deviceManager.upsertFromDiscovery(PLUGIN_ID, PLUGIN_ID, discovered);

        // Update live data values
        const payload: Record<string, unknown> = {
          monitoring: camera.monitoring ?? "unknown",
        };
        if (camera.sd_status !== undefined) {
          payload["sd_status"] = camera.sd_status;
        }
        if (camera.wifi_strength !== undefined) {
          payload["wifi_strength"] = camera.wifi_strength;
        }
        this.deviceManager.updateDeviceData(PLUGIN_ID, camera.name, payload);
      }

      this.lastPollAt = new Date().toISOString();
      this.logger.info({ cameraCount: cameras.length }, "Netatmo Security poll complete");
    } catch (err) {
      this.logger.error({ err }, "Poll failed");
      throw err;
    }
  }

  private mapCameraToDiscovered(camera: NetatmoCameraModule): DiscoveredDevice {
    return {
      friendlyName: camera.name,
      manufacturer: "Netatmo",
      model: camera.type,
      data: [
        { key: "monitoring", type: "enum", category: "generic" },
        { key: "sd_status", type: "number", category: "generic" },
        { key: "wifi_strength", type: "number", category: "generic" },
      ],
      orders: [
        {
          key: "setMonitoring",
          type: "enum",
          enumValues: ["on", "off"],
          dispatchConfig: { param: "monitoring" },
        },
      ],
    };
  }

  private schedulePoll(offsetMs: number): void {
    if (this.pollTimer) clearTimeout(this.pollTimer);

    const delay = offsetMs > 0 ? offsetMs : this.pollIntervalMs;
    this.pollTimer = setTimeout(async () => {
      try {
        await this.poll();
      } catch (_err) {
        // Error already logged in poll()
      }
      // Schedule next poll regardless of success/failure
      this.schedulePoll(0);
    }, delay);
  }

  private scheduleOnDemandPoll(): void {
    // Re-poll after 5 seconds to confirm the order took effect
    setTimeout(async () => {
      try {
        await this.poll();
      } catch (_err) {
        // Error already logged in poll()
      }
    }, 5_000);
  }

  // ============================================================
  // Retry logic
  // ============================================================

  private scheduleRetry(): void {
    this.cancelRetry();
    this.retryCount++;
    const delaySec = Math.min(30 * Math.pow(2, this.retryCount - 1), 600);
    this.logger.warn({ retryCount: this.retryCount, delaySec }, "Scheduling automatic retry");
    this.retryTimeout = setTimeout(() => {
      this.retryTimeout = null;
      this.start().catch((err) => this.logger.error({ err }, "Retry start failed"));
    }, delaySec * 1000);
  }

  private cancelRetry(): void {
    if (this.retryTimeout) {
      clearTimeout(this.retryTimeout);
      this.retryTimeout = null;
    }
  }

  // ============================================================
  // Helpers
  // ============================================================

  private stopTimers(): void {
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  private getSetting(key: string): string | undefined {
    return this.settingsManager.get(`${SETTINGS_PREFIX}${key}`);
  }

  private async fetchWithTimeout(
    url: string,
    init: RequestInit,
  ): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }
  }
}

// ============================================================
// Plugin factory (exported for Sowel plugin loader)
// ============================================================

export function createPlugin(deps: PluginDeps): IntegrationPlugin {
  return new NetatmoSecurityPlugin(deps);
}
