import React from 'react';
import { useLocalization } from '../hooks/useLocalization';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: 'Dashboard' | 'Rules' | 'Settings' | 'Logs' | 'Fleet' | 'ThreatHunt') => void;
}

const NavLogo: React.FC = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-10 w-10 text-blue-500" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5L12 1Z" />
    <path className="text-[#0D1117]" d="M12 3.17L4 6.3v4.7c0 4.1 2.93 8.23 8 9.4 5.07-1.17 8-5.3 8-9.4V6.3L12 3.17z" />
    <g stroke="white" strokeWidth={1.2} strokeLinecap="round" transform="translate(4 4) scale(0.66)">
      <circle cx="12" cy="12" r="3" />
      <path d="M12 6V3m0 18v-3m6-6h3M3 12h3m7.5-7.5L21 3M3 21l1.5-1.5M21 21l-1.5-1.5M3 3l1.5 1.5" />
    </g>
  </svg>
);

const NavItem = ({ icon, label, isActive, onClick }: { icon: React.ReactNode; label: string; isActive: boolean; onClick: () => void }) => (
  <button
    onClick={onClick}
    className={`flex w-full items-center space-x-3 rounded-lg px-4 py-3 transition-colors duration-200 ${
      isActive ? 'bg-blue-500/20 text-white' : 'text-gray-400 hover:bg-gray-700/50 hover:text-white'
    }`}
  >
    {icon}
    <span className="font-semibold">{label}</span>
  </button>
);

const icon = (path: string) => (
  <svg className="h-6 w-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d={path} />
  </svg>
);

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab }) => {
  const { t } = useLocalization();

  const navItems = [
    { id: 'Dashboard' as const, label: t('dashboardTab'), icon: icon('M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6') },
    { id: 'Fleet' as const, label: t('fleetTab'), icon: icon('M17 20h5V4H2v16h5m10 0v-6a2 2 0 00-2-2H9a2 2 0 00-2 2v6m10 0H7') },
    { id: 'ThreatHunt' as const, label: t('threatHuntTab'), icon: icon('M8 16l4-4 4 4m0-8l-4 4-4-4') },
    { id: 'Rules' as const, label: t('rulesTab'), icon: icon('M9 5h10M9 9h10M9 13h10M9 17h10M4 5h.01M4 9h.01M4 13h.01M4 17h.01') },
    { id: 'Settings' as const, label: t('settingsTab'), icon: icon('M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.096 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z') },
    { id: 'Logs' as const, label: t('logsTab'), icon: icon('M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z') },
  ];

  return (
    <aside className="hidden w-64 flex-col border-r border-gray-700/50 bg-[#161B22] p-4 md:flex">
      <div className="mb-6 flex items-center space-x-3 p-4">
        <NavLogo />
        <h1 className="text-2xl font-bold tracking-wide text-white">NetGuard <span className="text-blue-400">AI</span></h1>
      </div>
      <nav className="flex-1 space-y-2">
        {navItems.map(item => (
          <NavItem
            key={item.id}
            label={item.label}
            icon={item.icon}
            isActive={activeTab === item.id}
            onClick={() => setActiveTab(item.id)}
          />
        ))}
      </nav>
      <div className="p-4 text-center text-xs text-gray-600">
        &copy; {new Date().getFullYear()} NetGuard AI
      </div>
    </aside>
  );
};
