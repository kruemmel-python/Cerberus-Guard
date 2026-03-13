import React from 'react';

interface StatCardProps {
  title: string;
  value: string | number;
  description: string;
  valueColor?: string;
  children?: React.ReactNode;
}

export const StatCard: React.FC<StatCardProps> = ({ title, value, description, valueColor = 'text-white', children }) => {
  return (
    <div className="bg-[#161B22] p-5 rounded-lg shadow-lg border border-gray-700/50 flex flex-col justify-between">
      <div>
        <p className="text-sm font-medium text-gray-400">{title}</p>
        <p className={`text-3xl font-bold mt-2 ${valueColor}`}>{value}</p>
      </div>
      <p className="text-xs text-gray-500 mt-3">{description}</p>
      {children}
    </div>
  );
};
