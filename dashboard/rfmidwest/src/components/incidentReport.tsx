"use client";

import type { IncidentAlertPayload } from "@/hooks/webSocketConnection";

export default function IncidentAlertCard(payload: IncidentAlertPayload) {
  // TypeScript now treats `payload` as `IncidentAlertPayload` automatically!
  const { verdict, deviceId, incidentId, timestamp, status } = payload;

  // Dynamic badge color based on risk level
  const getRiskBadgeColor = (risk: string) => {
    switch (risk?.toUpperCase()) {
      case "CRITICAL":
        return "bg-red-500/10 text-red-400 border-red-500/20";
      case "HIGH":
        return "bg-orange-500/10 text-orange-400 border-orange-500/20";
      case "MEDIUM":
        return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
      default:
        return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    }
  };

  return (
    <div className="bg-slate-950 text-slate-100 rounded-xl border border-red-500/30 shadow-2xl overflow-hidden max-w-xl w-full">
      {/* Header Banner */}
      <div className="bg-red-950/40 border-b border-red-500/20 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <span className="flex h-3 w-3 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
          </span>
          <div>
            <h3 className="font-bold text-red-400 text-sm tracking-wide uppercase">
              Incident Alert #{incidentId}
            </h3>
            <p className="text-xs text-slate-400">
              Device:{" "}
              <span className="text-slate-200 font-mono">{deviceId}</span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`text-xs font-bold px-2.5 py-1 rounded-full border ${getRiskBadgeColor(verdict.risk_level)}`}
          >
            {verdict.risk_level} RISK
          </span>
          <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-red-500/20 text-red-300 border border-red-500/30">
            {status}
          </span>
        </div>
      </div>

      {/* Main Body / Verdict Section */}
      <div className="p-6 space-y-5">
        {/* Threat Summary Grid */}
        <div className="grid grid-cols-2 gap-4 bg-slate-900/60 p-4 rounded-lg border border-slate-800/80">
          <div>
            <p className="text-xs text-slate-400 font-medium">Threat Type</p>
            <p className="text-sm font-semibold text-slate-200 mt-0.5">
              {verdict.threat_type}
            </p>
          </div>
          <div>
            <p className="text-xs text-slate-400 font-medium">
              Confidence Score
            </p>
            <p className="text-sm font-semibold text-slate-200 mt-0.5">
              {(verdict.confidence * 100).toFixed(0)}%
            </p>
          </div>
          <div className="col-span-2 pt-2 border-t border-slate-800">
            <p className="text-xs text-slate-400 font-medium">
              Compromised Vector
            </p>
            <p className="text-xs font-mono text-amber-400 mt-0.5">
              {verdict.compromised_vector}
            </p>
          </div>
        </div>

        {/* Risk Justification */}
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
            Risk Justification
          </h4>
          <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/40 p-3 rounded-lg border border-slate-800">
            {verdict.risk_justification}
          </p>
        </div>

        {/* Threat Diagnosis List */}
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
            Threat Diagnosis
          </h4>
          <ul className="space-y-1.5">
            {verdict.threat_diagnosis.map((diagnosis, index) => (
              <li
                key={index}
                className="text-xs text-slate-300 flex items-start gap-2 bg-slate-900/30 px-3 py-2 rounded border border-slate-800/50"
              >
                <span className="text-red-400 font-bold">•</span>
                <span>{diagnosis}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Forensic Analysis */}
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
            Forensic Analysis
          </h4>
          <p className="text-xs text-slate-400 leading-relaxed italic bg-slate-900/20 p-3 rounded-lg border border-slate-800/40">
            &quot;{verdict.forensic_analysis}&quot;
          </p>
        </div>

        {/* PCI Compliance Impact */}
        <div className="bg-red-950/20 border border-red-500/20 p-3 rounded-lg">
          <p className="text-xs font-semibold text-red-400 mb-0.5">
            PCI Compliance Impact
          </p>
          <p className="text-xs text-slate-300">
            {verdict.pci_compliance_impact}
          </p>
        </div>

        {/* Mandatory Containment Action */}
        <div className="bg-red-600/10 border border-red-500/30 p-3.5 rounded-lg flex items-center justify-between">
          <div>
            <p className="text-xs font-bold text-red-400 uppercase tracking-wide">
              Required Containment Action
            </p>
            <p className="text-xs font-mono text-slate-200 mt-0.5">
              {verdict.pci_containment_action}
            </p>
          </div>
          <span className="text-xs font-bold bg-red-600 text-white px-3 py-1.5 rounded shadow">
            {verdict.action}
          </span>
        </div>
      </div>

      {/* Footer Timestamp */}
      <div className="bg-slate-900/80 px-6 py-3 border-t border-slate-800/80 flex justify-between items-center text-xs text-slate-400">
        <span>
          Event: <strong className="text-slate-300">{payload.event}</strong>
        </span>
        <span>{new Date(timestamp * 1000).toLocaleString()}</span>
      </div>
    </div>
  );
}
