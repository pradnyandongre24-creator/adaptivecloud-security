// frontend/src/pages/AttackDetectionPage.tsx
// Page 1: Attack Detection & Live Fleet — click any node to open full Node Intelligence Dossier
import React, { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import api from '@/api/client';
import {
  ShieldAlert, Laptop, AlertTriangle, Clock, RefreshCw,
  Cloud, Zap, ArrowUpRight, Wifi
} from 'lucide-react';
import NodeModal from '@/components/dashboard/NodeModal';
import type { LiveHost } from '@/components/dashboard/NodeModal';

interface LiveIncident {
  incident_id: string;
  timestamp: string;
  source: string;
  host_id: string;
  tier1_family: string;
  tier1_confidence: number;
  tier2_technique: string | null;
  tier2_confidence: number | null;
  status: string;
  features: Record<string, any>;
  rca?: any;
}

const FAMILY_LABEL: Record<string, string> = {
  ddos: 'DDoS Flood', dos: 'DoS Attack', brute_force: 'Brute Force',
  port_scan: 'Port Scan', port_scan_recon: 'Recon Scan',
  web_attack: 'Web Exploit', cryptomining: 'Crypto Mining',
  botnet: 'Botnet / C2', infiltration: 'Shellcode / RCE',
  exploit_other: 'Exploit', cloud_iam: 'IAM Abuse',
  cloud_storage: 'Data Exfil', privilege_escalation: 'Priv Escalation', benign: 'Normal',
};

const FAMILY_COLOR: Record<string, string> = {
  ddos: 'bg-red-500/15 text-red-400 border border-red-500/30',
  dos: 'bg-red-500/15 text-red-400 border border-red-500/30',
  brute_force: 'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  port_scan: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  port_scan_recon: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  web_attack: 'bg-purple-500/15 text-purple-400 border border-purple-500/30',
  cryptomining: 'bg-pink-500/15 text-pink-400 border border-pink-500/30',
  botnet: 'bg-rose-500/15 text-rose-400 border border-rose-500/30',
  infiltration: 'bg-red-600/15 text-red-300 border border-red-600/30',
  exploit_other: 'bg-orange-600/15 text-orange-300 border border-orange-600/30',
  cloud_iam: 'bg-blue-500/15 text-blue-400 border border-blue-500/30',
  privilege_escalation: 'bg-red-500/15 text-red-400 border border-red-500/30',
  benign: 'bg-green-500/15 text-green-400 border border-green-500/30',
};

function FamilyBadge({ family }: { family: string }) {
  const cls = FAMILY_COLOR[family] ?? 'bg-zinc-700/40 text-zinc-400 border border-zinc-700';
  const label = FAMILY_LABEL[family] ?? family.replace(/_/g, ' ');
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-bold font-mono uppercase ${cls}`}>
      {label}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    awaiting_approval: 'bg-amber-500/20 text-amber-400',
    ready_for_review: 'bg-blue-500/20 text-blue-400',
    approved: 'bg-green-500/20 text-green-400',
    rejected: 'bg-zinc-700 text-zinc-400',
    recorded: 'bg-zinc-700 text-zinc-400',
    executed: 'bg-green-600/20 text-green-300',
    healed: 'bg-emerald-500/20 text-emerald-400',
    verified: 'bg-emerald-500/20 text-emerald-400',
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold capitalize ${map[status] ?? 'bg-zinc-700 text-zinc-400'}`}>
      {status.replace(/_/g, ' ')}
    </span>
  );
}

function ConfBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct >= 90 ? 'bg-red-500' : pct >= 75 ? 'bg-orange-400' : 'bg-yellow-400';
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 rounded-full bg-zinc-800">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] text-zinc-400 font-mono">{pct}%</span>
    </div>
  );
}

function HostCard({ host, onSelect }: { host: LiveHost; onSelect: (h: LiveHost) => void }) {
  const isStressed = (host.cpu ?? 0) > 80;
  const cpuColor = isStressed ? 'text-red-400 font-extrabold animate-pulse' : host.cpu > 60 ? 'text-orange-400' : 'text-emerald-400';
  return (
    <div
      onClick={() => onSelect(host)}
      className={`group flex items-center justify-between border rounded-xl px-4 py-3 transition-all cursor-pointer ${
        isStressed
          ? 'bg-red-500/10 border-red-500/50 shadow-red-500/10 shadow-lg ring-1 ring-red-500/30'
          : 'bg-zinc-900/50 border-zinc-800 hover:border-zinc-600 hover:bg-zinc-800/40'
      }`}
    >
      <div className="flex items-center gap-3">
        <div className={`flex items-center justify-center w-9 h-9 rounded-xl ${
          isStressed ? 'bg-red-500/20 text-red-400 animate-pulse' : host.is_cloud ? 'bg-blue-500/15 text-blue-400' : 'bg-zinc-800 text-zinc-400'
        }`}>
          {host.is_cloud ? <Cloud className="w-4 h-4" /> : <Laptop className="w-4 h-4" />}
        </div>
        <div>
          <div className="flex items-center gap-2">
            <p className="text-xs font-semibold text-white leading-none group-hover:text-blue-300 transition-colors flex items-center gap-1">
              {host.display_label}
              <ArrowUpRight className="w-3 h-3 text-zinc-600 group-hover:text-blue-400 transition-colors" />
            </p>
            {isStressed && (
              <span className="text-[9px] font-bold font-mono px-1.5 py-0.5 rounded bg-red-500 text-black uppercase animate-pulse">
                ATTACK ACTIVE
              </span>
            )}
          </div>
          <p className="text-[10px] text-zinc-500 mt-0.5 font-mono">{host.ip_address}
            {host.region && <span className="text-zinc-600"> · {host.region}</span>}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-5 text-right">
        <div>
          <p className="text-[10px] text-zinc-500 uppercase font-mono">CPU</p>
          <p className={`text-sm font-bold font-mono ${cpuColor}`}>{host.cpu}%</p>
        </div>
        <div>
          <p className="text-[10px] text-zinc-500 uppercase font-mono">RAM</p>
          <p className="text-sm font-bold font-mono text-zinc-300">{host.mem}%</p>
        </div>
        <div className="flex flex-col items-center gap-1">
          <div className={`w-2.5 h-2.5 rounded-full ${isStressed ? 'bg-red-500 animate-ping' : host.status === 'online' ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
          <span className="text-[9px] text-zinc-500 font-mono">{isStressed ? 'ALERT' : 'LIVE'}</span>
        </div>
      </div>
    </div>
  );
}

export default function AttackDetectionPage() {
  const qc = useQueryClient();
  const [filter, setFilter] = useState<string>('all');
  const [injecting, setInjecting] = useState<boolean>(false);
  const [injectedMsg, setInjectedMsg] = useState<string | null>(null);
  const [selectedHost, setSelectedHost] = useState<LiveHost | null>(null);

  const handleInject = async (type: string, hostId: string = 'aws-worker-01') => {
    try {
      setInjecting(true);
      const res = await api.post('/demo/inject', { host_id: hostId, attack_type: type });
      const inc = res.data?.incident;
      setInjectedMsg(`🚨 ${type.toUpperCase()} anomaly injected on ${hostId.includes('aws') ? 'AWS Node' : hostId}! Incident ${inc?.incident_id ?? ''} created.`);
      await refetch();
      await qc.refetchQueries({ queryKey: ['hosts'] });
      setTimeout(() => setInjectedMsg(null), 10000);
    } catch (e: any) {
      setInjectedMsg(`Failed to inject: ${e.message}`);
    } finally {
      setInjecting(false);
    }
  };

  const handleAutoHeal = async (hostId: string = 'aws-worker-01') => {
    try {
      setInjecting(true);
      await api.post('/demo/heal', { host_id: hostId });
      setInjectedMsg('✅ Autonomous Self-Healing Complete — Host telemetry restored to baseline.');
      await refetch();
      await qc.refetchQueries({ queryKey: ['hosts'] });
      setTimeout(() => setInjectedMsg(null), 7000);
    } catch (e: any) {
      setInjectedMsg(`Heal failed: ${e.message}`);
    } finally {
      setInjecting(false);
    }
  };

  const { data: incidents = [], isLoading: incLoading, refetch } = useQuery<LiveIncident[]>({
    queryKey: ['incidents'],
    queryFn: async () => {
      try { const r = await api.get('/incidents?limit=80'); return r.data; }
      catch { return []; }
    },
    refetchInterval: 2000,
  });

  const { data: hosts = [] } = useQuery<LiveHost[]>({
    queryKey: ['hosts'],
    queryFn: async () => {
      try { const r = await api.get('/hosts'); return r.data; }
      catch { return []; }
    },
    refetchInterval: 2000,
  });

  const threats = incidents.filter(i => i.tier1_family !== 'benign');
  const awsHosts = hosts.filter(h => h.is_cloud);
  const localHosts = hosts.filter(h => !h.is_cloud);
  const families = Array.from(new Set(threats.map(i => i.tier1_family)));
  const filtered = filter === 'all' ? threats : threats.filter(i => i.tier1_family === filter);
  const familyCounts: Record<string, number> = {};
  threats.forEach(t => { familyCounts[t.tier1_family] = (familyCounts[t.tier1_family] ?? 0) + 1; });
  const topFamilies = Object.entries(familyCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const maxCount = topFamilies[0]?.[1] ?? 1;

  return (
    <div className="space-y-5">

      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            Attack Detection & Live Fleet
          </h1>
          <p className="text-xs text-zinc-500 mt-0.5">
            Two-Tier ML classifier · UNSW-NB15 ground truth · Click any node to inspect RCA, Self-Healing & Maintenance
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1 bg-zinc-900 border border-zinc-800 rounded-lg p-1">
            <span className="text-[10px] text-zinc-500 font-mono px-2 flex items-center gap-1">
              <Zap className="w-3 h-3 text-yellow-400" /> Quick Demo →
            </span>
            {[
              { type: 'ddos', label: '+ DDoS Flood', cls: 'bg-red-500/15 text-red-400 hover:bg-red-500/30' },
              { type: 'cryptomining', label: '+ Crypto Miner', cls: 'bg-pink-500/15 text-pink-400 hover:bg-pink-500/30' },
              { type: 'brute_force', label: '+ Brute Force', cls: 'bg-orange-500/15 text-orange-400 hover:bg-orange-500/30' },
            ].map(({ type, label, cls }) => (
              <button
                key={type}
                onClick={() => handleInject(type)}
                disabled={injecting}
                className={`text-[10px] font-bold px-2.5 py-1.5 rounded-md transition-colors disabled:opacity-50 ${cls}`}
              >
                {label}
              </button>
            ))}
          </div>
          <button
            onClick={() => { refetch(); qc.refetchQueries({ queryKey: ['hosts'] }); }}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-white transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>
      </div>

      {/* ── Alert Banner ── */}
      {injectedMsg && (
        <div className={`border rounded-xl p-3 flex items-center justify-between text-xs ${
          injectedMsg.startsWith('✅') ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200' : 'bg-red-500/10 border-red-500/30 text-red-200'
        }`}>
          <div className="flex items-center gap-2 font-mono">
            <AlertTriangle className={`w-4 h-4 flex-shrink-0 ${injectedMsg.startsWith('✅') ? 'text-emerald-400' : 'text-red-400 animate-pulse'}`} />
            <span>{injectedMsg}</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleAutoHeal()}
              disabled={injecting}
              className="flex items-center gap-1.5 px-3 py-1 bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-bold rounded-lg shadow transition-colors disabled:opacity-50"
            >
              <Zap className="w-3.5 h-3.5" /> ⚡ Auto-Heal Now
            </button>
            <a href="/rca" className="px-2.5 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-semibold rounded-lg transition-colors">
              Forensic RCA →
            </a>
          </div>
        </div>
      )}

      {/* ── Stat Row ── */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Threats', value: threats.length, color: 'text-red-400', bg: 'border-red-500/20', icon: <ShieldAlert className="w-4 h-4" /> },
          { label: 'AWS Nodes', value: awsHosts.length, color: 'text-blue-400', bg: 'border-blue-500/20', icon: <Cloud className="w-4 h-4" /> },
          { label: 'Local Nodes', value: localHosts.length, color: 'text-zinc-300', bg: 'border-zinc-700', icon: <Laptop className="w-4 h-4" /> },
          { label: 'Active Anomalies', value: threats.filter(t => ['awaiting_approval', 'ready_for_review'].includes(t.status)).length, color: 'text-amber-400', bg: 'border-amber-500/20', icon: <Clock className="w-4 h-4" /> },
        ].map(s => (
          <div key={s.label} className={`bg-zinc-900/60 border ${s.bg} rounded-xl p-4`}>
            <div className={`flex items-center gap-1.5 text-xs font-medium mb-2 ${s.color}`}>
              {s.icon}
              <span className="uppercase tracking-wide font-bold text-[10px]">{s.label}</span>
            </div>
            <p className={`text-3xl font-black font-mono ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* ── Live Fleet + Threat Breakdown ── */}
      <div className="grid grid-cols-5 gap-4">
        {/* Threat Families */}
        <div className="col-span-2 bg-zinc-900/60 border border-zinc-800 rounded-xl p-5">
          <h2 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-4">Attack Family Distribution</h2>
          <div className="space-y-3">
            {topFamilies.map(([fam, cnt]) => (
              <div key={fam}>
                <div className="flex items-center justify-between mb-1.5">
                  <FamilyBadge family={fam} />
                  <span className="text-xs font-mono font-bold text-white">{cnt}</span>
                </div>
                <div className="h-1.5 w-full bg-zinc-800 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-red-500 to-orange-400 transition-all duration-500"
                    style={{ width: `${(cnt / maxCount) * 100}%` }}
                  />
                </div>
              </div>
            ))}
            {topFamilies.length === 0 && (
              <p className="text-xs text-zinc-600 py-6 text-center">System nominal — no threats detected</p>
            )}
          </div>
        </div>

        {/* Live Fleet — Click Any Node */}
        <div className="col-span-3 bg-zinc-900/60 border border-zinc-800 rounded-xl p-5">
          <h2 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-4 flex items-center gap-2">
            <Wifi className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            Live Fleet — {hosts.length} Nodes Connected
            <span className="ml-auto text-zinc-600 font-normal normal-case text-[9px]">↗ Click any node to open Node Intelligence Dossier</span>
          </h2>
          <div className="space-y-2">
            {hosts.map(h => <HostCard key={h.id} host={h} onSelect={setSelectedHost} />)}
            {hosts.length === 0 && (
              <p className="text-xs text-zinc-600 py-8 text-center">Connecting to Telemetry Hub…</p>
            )}
          </div>
        </div>
      </div>

      {/* ── Incidents Table ── */}
      <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-zinc-800">
          <h2 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">
            Detected Attacks ({filtered.length})
          </h2>
          <div className="flex items-center gap-1.5 flex-wrap">
            <button
              onClick={() => setFilter('all')}
              className={`px-2.5 py-1 rounded-lg text-[10px] font-bold transition-all ${filter === 'all' ? 'bg-white text-black' : 'text-zinc-500 hover:text-white'}`}
            >All</button>
            {families.map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-2.5 py-1 rounded-lg text-[10px] font-bold transition-all ${filter === f ? 'bg-white text-black' : 'text-zinc-500 hover:text-white'}`}
              >
                {FAMILY_LABEL[f] ?? f}
              </button>
            ))}
          </div>
        </div>
        {incLoading ? (
          <div className="py-12 text-center text-xs text-zinc-600">Loading incidents…</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-zinc-800 text-zinc-500 font-mono uppercase text-[10px]">
                  <th className="px-5 py-2.5 text-left">Attack Family</th>
                  <th className="px-5 py-2.5 text-left">MITRE Technique</th>
                  <th className="px-5 py-2.5 text-left">Host / Node</th>
                  <th className="px-5 py-2.5 text-left">Data Source</th>
                  <th className="px-5 py-2.5 text-left">ML Confidence</th>
                  <th className="px-5 py-2.5 text-left">Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 25).map((inc) => (
                  <tr
                    key={inc.incident_id}
                    onClick={() => {
                      const h = hosts.find(x => x.id === inc.host_id || inc.host_id?.includes(x.id) || x.id?.includes(inc.host_id?.split(' ')[0] ?? ''));
                      if (h) setSelectedHost(h);
                    }}
                    className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors cursor-pointer"
                    title="Click to open Node Dossier"
                  >
                    <td className="px-5 py-3"><FamilyBadge family={inc.tier1_family} /></td>
                    <td className="px-5 py-3 font-mono text-zinc-400 text-[10px]">{inc.tier2_technique ?? '—'}</td>
                    <td className="px-5 py-3 text-zinc-300 max-w-[160px] truncate font-mono text-[10px]" title={inc.host_id}>{inc.host_id}</td>
                    <td className="px-5 py-3">
                      <span className={`text-[10px] font-mono font-semibold ${inc.source === 'unsw_nb15_replay' ? 'text-blue-400' : inc.source === 'live_aws' ? 'text-emerald-400' : 'text-zinc-500'}`}>
                        {inc.source === 'unsw_nb15_replay' ? '📊 UNSW-NB15' : inc.source === 'live_aws' ? '☁️ AWS Live' : '🖥️ Simulated'}
                      </span>
                    </td>
                    <td className="px-5 py-3"><ConfBar value={inc.tier1_confidence} /></td>
                    <td className="px-5 py-3"><StatusBadge status={inc.status} /></td>
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-5 py-10 text-center text-zinc-600">No threats for this filter</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Node Intelligence Modal ── */}
      {selectedHost && (
        <NodeModal
          host={selectedHost}
          onClose={() => setSelectedHost(null)}
          onInjectAnomaly={handleInject}
          onAutoHeal={handleAutoHeal}
        />
      )}
    </div>
  );
}
