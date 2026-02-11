'use client';

import { useState, useEffect } from 'react';
import { Shield, CheckCircle, XCircle, AlertCircle } from 'lucide-react';

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const response = await fetch('/api/scans');
      const data = await response.json();
      setScans(data);
    } catch (error) {
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-indigo-500 via-purple-500 to-pink-500">
        <div className="text-white text-2xl">Loading...</div>
      </div>
    );
  }

  if (scans.length === 0) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-indigo-500 via-purple-500 to-pink-500">
        <div className="bg-white p-10 rounded-2xl shadow-2xl text-center max-w-md">
          <Shield className="w-20 h-20 mx-auto mb-6 text-indigo-600" />
          <h1 className="text-3xl font-bold mb-4 text-gray-800">No Scans Yet</h1>
          <p className="text-gray-600 mb-6">
            Run your first security compliance scan to see results here.
          </p>
          <div className="bg-gray-100 p-4 rounded-lg text-left">
            <code className="text-sm text-gray-800">python3 scanner.py</code>
          </div>
        </div>
      </div>
    );
  }

  const latestScan = scans[scans.length - 1];

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-500 via-purple-500 to-pink-500 p-6">
      <div className="max-w-7xl mx-auto mb-8">
        <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-6 text-white">
          <div className="flex items-center space-x-4">
            <Shield className="w-12 h-12" />
            <div>
              <h1 className="text-3xl font-bold">Security Compliance Dashboard</h1>
              <p className="text-white/80">Real-time security posture monitoring</p>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <StatCard
          icon={<Shield className="w-8 h-8" />}
          label="Compliance Score"
          value={latestScan.complianceScore.toFixed(1) + '%'}
          color="bg-gradient-to-br from-blue-500 to-blue-600"
        />
        <StatCard
          icon={<CheckCircle className="w-8 h-8" />}
          label="Passed Checks"
          value={latestScan.passedChecks}
          color="bg-gradient-to-br from-green-500 to-green-600"
        />
        <StatCard
          icon={<XCircle className="w-8 h-8" />}
          label="Failed Checks"
          value={latestScan.failedChecks}
          color="bg-gradient-to-br from-red-500 to-red-600"
        />
        <StatCard
          icon={<AlertCircle className="w-8 h-8" />}
          label="Total Checks"
          value={latestScan.totalChecks}
          color="bg-gradient-to-br from-purple-500 to-purple-600"
        />
      </div>

      <div className="max-w-7xl mx-auto">
        <div className="bg-white rounded-2xl shadow-2xl p-6">
          <h2 className="text-xl font-bold mb-4 text-gray-800">Security Check Results</h2>
          <div className="space-y-4 max-h-96 overflow-y-auto">
            {latestScan.results.map((result, index) => (
              <div
                key={index}
                className={'p-4 rounded-lg border-l-4 ' + (
                  result.status === 'PASS' ? 'border-green-500 bg-green-50' :
                  result.status === 'FAIL' ? 'border-red-500 bg-red-50' :
                  'border-yellow-500 bg-yellow-50'
                )}
              >
                <div className="flex justify-between items-start mb-2">
                  <div>
                    <span className="text-xs font-mono bg-gray-200 px-2 py-1 rounded">
                      {result.check_id}
                    </span>
                    <h3 className="font-semibold text-gray-800 mt-2">{result.check_name}</h3>
                  </div>
                  <span className={'px-3 py-1 rounded-full text-sm font-semibold ' + (
                    result.status === 'PASS' ? 'bg-green-200 text-green-800' :
                    result.status === 'FAIL' ? 'bg-red-200 text-red-800' :
                    'bg-yellow-200 text-yellow-800'
                  )}>
                    {result.status}
                  </span>
                </div>
                <p className="text-gray-700 text-sm mb-2">{result.description}</p>
                <span className={'text-xs px-2 py-1 rounded ' + (
                  result.severity === 'CRITICAL' ? 'bg-red-600 text-white' :
                  result.severity === 'HIGH' ? 'bg-orange-500 text-white' :
                  result.severity === 'MEDIUM' ? 'bg-yellow-500 text-gray-900' :
                  'bg-green-500 text-white'
                )}>
                  {result.severity}
                </span>
                {result.remediation && (
                  <div className="mt-3 p-3 bg-blue-50 border-l-2 border-blue-500 rounded">
                    <p className="text-sm text-blue-900">
                      <strong>💡 Remediation:</strong> {result.remediation}
                    </p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, color }) {
  return (
    <div className={color + ' rounded-2xl shadow-2xl p-6 text-white'}>
      <div className="flex items-center justify-between mb-4">
        {icon}
        <div className="text-4xl font-bold">{value}</div>
      </div>
      <div className="text-white/90 text-sm font-medium">{label}</div>
    </div>
  );
}
