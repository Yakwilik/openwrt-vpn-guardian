export type OverallState = "ok" | "degraded" | "down" | string;

export interface HealthProbe {
  code: number;
  ms: number;
}

export interface TProxyStatus {
  nft: boolean;
  policy: boolean;
  route: boolean;
  backend_socks: boolean;
  front_port: boolean;
  route_table: number;
}

export interface StatusSnapshot {
  now: number;
  overall: OverallState;
  architecture: string;
  control_mode: string;
  failure_policy: string;
  policy_mode: string;
  policy_runtime: string;
  node: string;
  protocol: string;
  endpoint: string;
  vpn_ip: string;
  home_ip: string;
  transparent: string;
  pac_mode: string;
  desired_transparent: string;
  tproxy_active: boolean;
  fallback_direct: boolean;
  failures: number;
  last_switch: number;
  last_failed_node: string;
  last_failed_at: number;
  candidates: number;
  nodes_total: number;
  services: Record<string, string>;
  tproxy: TProxyStatus;
  health_count: number;
  health: Record<string, HealthProbe>;
}

export interface HistorySample {
  ts: number;
  availability: number;
  health: number;
  failed: number;
  overall: string;
  switch: number;
  node: string;
}

export interface HistoryEvent {
  ts: number;
  type: string;
  message: string;
}

export interface HistoryResponse {
  router_tz_offset: number;
  samples: HistorySample[];
  events: HistoryEvent[];
}

export interface ControlState {
  mode: "auto" | "pinned" | "direct" | string;
  pinName?: string;
  failurePolicy: "killswitch" | "failopen" | string;
  updatedAt: number;
}

export interface ActiveNode {
  id: number;
  sub: number;
}

export interface NodeInfo {
  id: number;
  sub: number;
  subscriptionId: number;
  name: string;
  net: string;
  address: string;
  pingLatency: string;
  active: boolean;
  pinned: boolean;
}

export interface SubscriptionInfo {
  id: number;
  name: string;
  address?: string;
  host: string;
  info: string;
  remarks: string;
  autoSelect: boolean;
  nodeCount: number;
}

export interface TransportOption {
  value: string;
  label: string;
}

export interface SelectionState {
  allowedTransports: string[];
  options: TransportOption[];
}

export interface ControlResponse {
  ok: boolean;
  authenticated: boolean;
  authConfigured: boolean;
  authMode: string;
  csrf?: string;
  control: ControlState;
  active: ActiveNode;
  nodes: NodeInfo[];
  subscriptions: SubscriptionInfo[];
  frontEnabled: boolean;
  hardKillSwitch: boolean;
  policyMode: string;
  selection: SelectionState;
  result?: string;
  message?: string;
  error?: string;
}

export type ControlPayload = Record<
  string,
  string | number | boolean | string[] | undefined
>;
