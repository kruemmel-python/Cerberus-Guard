
import React from 'react';
import { useLocalization, Language } from '../hooks/useLocalization';

interface HeaderProps {
  isMonitoring: boolean;
  setIsMonitoring: (isMonitoring: boolean) => void;
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

const PlayIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
    <path d="M8 5v14l11-7z" />
  </svg>
);

const PauseIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
    <path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z" />
  </svg>
);

const ShieldIcon: React.FC<{ className?: string }> = ({ className }) => (
    <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
    </svg>
);

const GlobeIcon: React.FC<{ className?: string }> = ({ className }) => (
    <svg className={className} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 21l5.25-11.25L21 21m-9-3h7.5M3 5.621a48.474 48.474 0 016-.371m0 0c1.12 0 2.233.038 3.334.114M9 5.25V3m3.334 2.364C11.176 10.658 7.69 15.08 3 17.502m9.334-12.138c.896.061 1.785.147 2.666.257m-4.589 8.495a18.023 18.023 0 01-3.827-5.802" />
    </svg>
);


export const Header: React.FC<HeaderProps> = ({ isMonitoring, setIsMonitoring, activeTab, setActiveTab }) => {
  const { t, changeLanguage, currentLanguage, languages } = useLocalization();
  
  const tabKeys: { [key: string]: string } = {
    Dashboard: 'dashboardTab',
    Settings: 'settingsTab',
    Logs: 'logsTab'
  }

  const handleLanguageChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    changeLanguage(e.target.value as Language);
  };

  return (
    <header className="bg-gray-800 shadow-lg">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-20">
          <div className="flex items-center space-x-4">
            <ShieldIcon className="h-8 w-8 text-blue-400"/>
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-wider">{t('headerTitle')}</h1>
            <div className="hidden sm:flex items-center space-x-2">
              <span className={`h-3 w-3 rounded-full ${isMonitoring ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></span>
              <span className="text-sm font-medium text-gray-400">{isMonitoring ? t('monitoringStatus') : t('stoppedStatus')}</span>
            </div>
          </div>
          <div className="flex items-center space-x-2 sm:space-x-4">
            <div className="relative">
                <GlobeIcon className="absolute left-2 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400 pointer-events-none"/>
                <select 
                    value={currentLanguage} 
                    onChange={handleLanguageChange}
                    className="appearance-none bg-gray-700 text-white rounded-md pl-8 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
                >
                    {Object.entries(languages).map(([code, name]) => (
                        <option key={code} value={code}>{name}</option>
                    ))}
                </select>
            </div>
            <nav className="hidden md:flex space-x-2 bg-gray-700 p-1 rounded-lg">
              {Object.keys(tabKeys).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-4 py-2 text-sm font-medium rounded-md transition-colors duration-200 ${
                    activeTab === tab ? 'bg-blue-500 text-white shadow' : 'text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  {t(tabKeys[tab])}
                </button>
              ))}
            </nav>
            <button
              onClick={() => setIsMonitoring(!isMonitoring)}
              className={`flex items-center justify-center w-12 h-12 rounded-full transition-colors duration-300 ${
                isMonitoring
                  ? 'bg-yellow-500 hover:bg-yellow-600 text-white'
                  : 'bg-green-500 hover:bg-green-600 text-white'
              }`}
              aria-label={isMonitoring ? t('stopMonitoring') : t('startMonitoring')}
            >
              {isMonitoring ? <PauseIcon className="h-6 w-6"/> : <PlayIcon className="h-6 w-6"/>}
            </button>
          </div>
        </div>
        <div className="md:hidden flex justify-center pb-2">
           <nav className="flex space-x-1 bg-gray-700 p-1 rounded-lg w-full justify-around">
              {Object.keys(tabKeys).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-3 py-2 text-xs font-medium rounded-md transition-colors duration-200 w-full text-center ${
                    activeTab === tab ? 'bg-blue-500 text-white shadow' : 'text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  {t(tabKeys[tab])}
                </button>
              ))}
            </nav>
        </div>
      </div>
    </header>
  );
};