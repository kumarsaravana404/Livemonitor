import { useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { 
  ShieldAlert, ShieldCheck, Activity, Globe, MapPin, 
  Smartphone, CircleUser, Search, Bell
} from 'lucide-react';
import clsx from 'clsx';
import { twMerge } from 'tailwind-merge';

// Helper for UI class merging
function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

// ----------------------------------------------------
// Mock Data Generation
// ----------------------------------------------------
const TIMELINE_DATA = Array.from({ length: 24 }).map((_, i) => ({
  time: `${i}:00`,
  safe: Math.floor(Math.random() * 50) + 10,
  suspicious: Math.floor(Math.random() * 10),
  blocked: Math.floor(Math.random() * 5)
}));

const RECENT_ALERTS = [
  { id: 1, type: 'critical', msg: 'Multiple failed logins from unrecognized IP (Moscow, RU)', time: '2 mins ago', ip: '185.112.x.x', user: 'admin@company.com' },
  { id: 2, type: 'warning', msg: 'New device login (iPhone 14) from California, US', time: '1 hr ago', ip: '104.22.x.x', user: 'j.doe@company.com' },
  { id: 3, type: 'info', msg: 'Admin role granted to User (ID: #4092)', time: '3 hrs ago', ip: '192.168.1.1', user: 'system' }
];

const ORIGIN_DATA = [
  { country: 'United States', count: 1421, flag: '🇺🇸' },
  { country: 'India', count: 348, flag: '🇮🇳' },
  { country: 'Germany', count: 112, flag: '🇩🇪' },
  { country: 'Russia (Flags)', count: 48, flag: '🇷🇺' }
];

// ----------------------------------------------------
// Components
// ----------------------------------------------------

export default function Dashboard() {
  const [scope, setScope] = useState<'personal' | 'business'>('business');

  return (
    <div className="flex h-screen w-full bg-[#0F172A] text-slate-200 overflow-hidden font-sans">
      
      {/* SIDEBAR NAVIGATION */}
      <aside className="w-64 border-r border-slate-800 bg-[#0B1120] flex flex-col">
        <div className="p-6 flex items-center gap-3 border-b border-slate-800">
          <div className="w-8 h-8 rounded-lg bg-blue-500 flex items-center justify-center text-white font-bold shadow-[0_0_15px_rgba(59,130,246,0.5)]">
            <ShieldCheck size={20} />
          </div>
          <span className="font-bold text-lg tracking-wide text-white">SecureWatch</span>
        </div>
        
        <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2 mt-4 px-2">Main</div>
          <a href="#" className="flex items-center gap-3 px-3 py-2 rounded-md bg-blue-500/10 text-blue-400">
            <Activity size={18} /> Overview
          </a>
          <a href="#" className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-slate-800/50 text-slate-400 hover:text-slate-200 transition-colors">
            <ShieldAlert size={18} /> Threat Intelligence
          </a>
          <a href="#" className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-slate-800/50 text-slate-400 hover:text-slate-200 transition-colors">
            <Globe size={18} /> Geographic Logs
          </a>
          
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2 mt-8 px-2">Management</div>
          <a href="#" className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-slate-800/50 text-slate-400 hover:text-slate-200 transition-colors">
            <CircleUser size={18} /> Users & Devices
          </a>
        </nav>
        
        {/* Scope Toggle */}
        <div className="p-4 border-t border-slate-800">
          <div className="flex bg-[#0F172A] p-1 rounded-lg border border-slate-700">
            <button 
              onClick={() => setScope('personal')}
              className={cn("flex-1 py-1.5 text-xs font-medium rounded-md transition-all", scope === 'personal' ? "bg-slate-700 text-white shadow" : "text-slate-400 hover:text-slate-200")}
            >Personal</button>
            <button 
              onClick={() => setScope('business')}
              className={cn("flex-1 py-1.5 text-xs font-medium rounded-md transition-all", scope === 'business' ? "bg-slate-700 text-white shadow" : "text-slate-400 hover:text-slate-200")}
            >Business</button>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT */}
      <main className="flex-1 flex flex-col min-w-0 overflow-y-auto relative">
        
        {/* TOP BAR */}
        <header className="h-16 border-b border-slate-800 flex items-center justify-between px-8 bg-[#0F172A]/80 backdrop-blur-md sticky top-0 z-10">
          <div>
            <h1 className="text-lg font-semibold text-white">Login Analytics & Threat View</h1>
            <p className="text-xs text-slate-400">Viewing data for {scope === 'business' ? 'Organization (All Teams)' : 'My Account'}</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
              <input type="text" placeholder="Search IP, User..." className="bg-slate-900 border border-slate-700 rounded-md py-1.5 pl-8 pr-3 text-sm focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 placeholder:text-slate-500 w-64 transition-all" />
            </div>
            <button className="relative text-slate-400 hover:text-white transition-colors">
              <Bell size={20} />
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-red-500 rounded-full border-2 border-[#0F172A]"></span>
            </button>
            <div className="w-8 h-8 rounded-full bg-linear-to-tr from-blue-500 to-emerald-400 ml-2"></div>
          </div>
        </header>

        <div className="p-8 space-y-6">
          
          {/* CRITICAL BANNER */}
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 flex items-start gap-4 shadow-[0_0_20px_rgba(239,68,68,0.05)] animate-in fade-in slide-in-from-top-4">
            <div className="mt-0.5 text-red-500 animate-pulse"><ShieldAlert size={24} /></div>
            <div className="flex-1">
              <h3 className="text-red-400 font-medium">Critical Threat Detected</h3>
              <p className="text-sm text-red-400/80 mt-1">Automated botnet traffic pattern detected attacking standard admin routes from autonomous systems. IP range block rule applied automatically.</p>
            </div>
            <button className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-400 text-sm font-medium rounded-md border border-red-500/30 transition-colors">
              View Threat Logs
            </button>
          </div>

          {/* STATS ROW */}
          <div className="grid grid-cols-4 gap-6">
            <div className="bg-[#1e293b]/50 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
              <div className="flex justify-between items-start mb-2">
                <span className="text-slate-400 text-sm font-medium">Total Authentications</span>
                <Activity size={16} className="text-blue-400" />
              </div>
              <div className="text-3xl font-bold text-white mb-1">24,592</div>
              <div className="text-xs text-emerald-400 flex items-center gap-1">↑ 12% vs last 24h</div>
            </div>
            
            <div className="bg-[#1e293b]/50 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
              <div className="flex justify-between items-start mb-2">
                <span className="text-slate-400 text-sm font-medium">Unknown Devices</span>
                <Smartphone size={16} className="text-yellow-400" />
              </div>
              <div className="text-3xl font-bold text-white mb-1">1,042</div>
              <div className="text-xs text-yellow-400 flex items-center gap-1">⚠ 5% requires 2FA</div>
            </div>

            <div className="bg-[#1e293b]/50 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
              <div className="flex justify-between items-start mb-2">
                <span className="text-slate-400 text-sm font-medium">Threats Blocked</span>
                <ShieldAlert size={16} className="text-red-400" />
              </div>
              <div className="text-3xl font-bold text-white mb-1">328</div>
              <div className="text-xs text-red-400 flex items-center gap-1">↑ 2 High Severity</div>
            </div>

            <div className="bg-[#1e293b]/50 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
              <div className="flex justify-between items-start mb-2">
                <span className="text-slate-400 text-sm font-medium">Geo Locations</span>
                <Globe size={16} className="text-indigo-400" />
              </div>
              <div className="text-3xl font-bold text-white mb-1">14</div>
              <div className="text-xs text-slate-500 w-full truncate">US, IN, DE, RU...</div>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-6">
            {/* CHART */}
            <div className="col-span-2 bg-[#1e293b]/50 border border-slate-800 rounded-xl p-5">
              <div className="flex items-center justify-between mb-6">
                <h3 className="font-medium text-slate-200">24hr Activity Timeline</h3>
                <div className="flex gap-4 text-xs font-medium">
                  <span className="flex items-center gap-1.5 text-blue-400"><span className="w-2 h-2 rounded-full bg-blue-500"></span> Valid Logins</span>
                  <span className="flex items-center gap-1.5 text-yellow-400"><span className="w-2 h-2 rounded-full bg-yellow-500"></span> Suspicious</span>
                  <span className="flex items-center gap-1.5 text-red-400"><span className="w-2 h-2 rounded-full bg-red-500"></span> Blocked</span>
                </div>
              </div>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={TIMELINE_DATA} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorSafe" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="colorSuspicious" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#EAB308" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#EAB308" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#EF4444" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#EF4444" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" stroke="#334155" fontSize={11} tickLine={false} axisLine={false} />
                    <YAxis stroke="#334155" fontSize={11} tickLine={false} axisLine={false} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#0F172A', borderColor: '#1E293B', borderRadius: '8px', fontSize: '12px' }}
                      itemStyle={{ color: '#F1F5F9' }}
                    />
                    <Area type="monotone" dataKey="safe" stroke="#3B82F6" strokeWidth={2} fillOpacity={1} fill="url(#colorSafe)" />
                    <Area type="monotone" dataKey="suspicious" stroke="#EAB308" strokeWidth={2} fillOpacity={1} fill="url(#colorSuspicious)" />
                    <Area type="monotone" dataKey="blocked" stroke="#EF4444" strokeWidth={2} fillOpacity={1} fill="url(#colorBlocked)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* QUICK ORIGINS */}
            <div className="bg-[#1e293b]/50 border border-slate-800 rounded-xl p-5 flex flex-col">
              <h3 className="font-medium text-slate-200 mb-4 flex justify-between items-center">
                Top Origins <MapPin size={16} className="text-slate-400" />
              </h3>
              <div className="flex-1 rounded-lg border border-slate-700/50 bg-[#0F172A]/50 relative overflow-hidden mb-4 flex items-center justify-center min-h-[140px]">
                  {/* Mock Map Background Visual */}
                 <div className="absolute inset-0 opacity-20 pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at 50% 50%, #3B82F6 1px, transparent 1px)', backgroundSize: '20px 20px' }}></div>
                 <div className="absolute top-1/2 left-1/3 w-3 h-3 bg-blue-500 rounded-full shadow-[0_0_15px_#3B82F6]"></div>
                 <div className="absolute top-1/4 right-1/4 w-2 h-2 bg-red-500 rounded-full shadow-[0_0_10px_#EF4444] animate-pulse"></div>
              </div>
              
              <div className="space-y-3">
                {ORIGIN_DATA.map(o => (
                  <div key={o.country} className="flex justify-between items-center text-sm">
                    <span className="flex items-center gap-2 text-slate-300"><span>{o.flag}</span> {o.country}</span>
                    <span className="font-mono text-slate-400">{o.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* EVENTS LIST */}
          <div className="bg-[#1e293b]/50 border border-slate-800 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center bg-[#1e293b]/80">
              <h3 className="font-medium text-slate-200">Actionable Alerts</h3>
              <button className="text-xs text-blue-400 hover:text-blue-300 font-medium">View All Events →</button>
            </div>
            <div className="w-full">
              {RECENT_ALERTS.map(alert => (
                <div key={alert.id} className="flex gap-4 p-4 border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors last:border-0 items-center">
                  <div className="w-2 h-2 rounded-full shrink-0" style={{
                    backgroundColor: alert.type === 'critical' ? '#EF4444' : alert.type === 'warning' ? '#EAB308' : '#3B82F6'
                  }}></div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-slate-200 truncate">{alert.msg}</p>
                    <div className="flex items-center gap-3 mt-1 text-xs text-slate-500 font-mono">
                      <span>{alert.time}</span>
                      <span>&bull;</span>
                      <span>{alert.user}</span>
                      <span>&bull;</span>
                      <span>{alert.ip}</span>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    {alert.type === 'critical' || alert.type === 'warning' ? (
                      <>
                        <button className="px-3 py-1.5 text-xs font-medium rounded bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20 transition-colors">Block Device</button>
                        <button className="px-3 py-1.5 text-xs font-medium rounded bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700 transition-colors">Trust</button>
                      </>
                    ) : (
                      <button className="px-3 py-1.5 text-xs font-medium rounded bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700 transition-colors">Details</button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
          
        </div>
      </main>
    </div>
  );
}
