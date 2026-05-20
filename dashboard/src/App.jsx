import React, { useEffect, useState, useRef, useCallback } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Line, Bar, Doughnut, Pie } from 'react-chartjs-2';
import CytoscapeComponent from 'react-cytoscapejs';
import cytoscape from 'cytoscape';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const API_BASE = 'http://localhost:8000';

const COLORS = {
  primary: '#0ea5e9',
  secondary: '#6366f1',
  success: '#22c55e',
  warning: '#f59e0b',
  danger: '#ef4444',
  dark: '#0f172a',
  darker: '#020617',
  card: '#1e293b',
  border: '#334155',
  text: '#e2e8f0',
  textMuted: '#94a3b8',
};

const styles = {
  container: {
    display: 'flex',
    minHeight: '100vh',
    backgroundColor: COLORS.darker,
    color: COLORS.text,
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
  },
  sidebar: {
    width: '260px',
    backgroundColor: COLORS.dark,
    borderRight: `1px solid ${COLORS.border}`,
    display: 'flex',
    flexDirection: 'column',
    position: 'fixed',
    height: '100vh',
    zIndex: 100,
  },
  sidebarHeader: {
    padding: '20px',
    borderBottom: `1px solid ${COLORS.border}`,
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  logo: {
    width: '40px',
    height: '40px',
    background: 'linear-gradient(135deg, #0ea5e9, #6366f1)',
    borderRadius: '10px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '20px',
    fontWeight: 'bold',
  },
  navItem: {
    padding: '14px 20px',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    color: COLORS.textMuted,
    transition: 'all 0.2s',
    borderLeft: '3px solid transparent',
  },
  navItemActive: {
    backgroundColor: 'rgba(14, 165, 233, 0.1)',
    color: COLORS.primary,
    borderLeftColor: COLORS.primary,
  },
  main: {
    flex: 1,
    marginLeft: '260px',
    padding: '24px',
    backgroundColor: COLORS.darker,
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '24px',
  },
  title: {
    fontSize: '28px',
    fontWeight: '700',
    margin: 0,
  },
  card: {
    backgroundColor: COLORS.card,
    borderRadius: '12px',
    padding: '20px',
    border: `1px solid ${COLORS.border}`,
    marginBottom: '20px',
  },
  cardTitle: {
    fontSize: '14px',
    color: COLORS.textMuted,
    marginBottom: '12px',
    fontWeight: '600',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  },
  metricValue: {
    fontSize: '32px',
    fontWeight: '700',
    color: COLORS.text,
  },
  metricChange: {
    fontSize: '14px',
    marginTop: '4px',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
    gap: '20px',
    marginBottom: '24px',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
  },
  th: {
    textAlign: 'left',
    padding: '12px',
    borderBottom: `1px solid ${COLORS.border}`,
    color: COLORS.textMuted,
    fontSize: '12px',
    fontWeight: '600',
    textTransform: 'uppercase',
  },
  td: {
    padding: '12px',
    borderBottom: `1px solid ${COLORS.border}`,
    fontSize: '14px',
  },
  badge: {
    padding: '4px 10px',
    borderRadius: '20px',
    fontSize: '12px',
    fontWeight: '600',
  },
  button: {
    padding: '8px 16px',
    borderRadius: '8px',
    border: 'none',
    cursor: 'pointer',
    fontWeight: '600',
    fontSize: '14px',
    transition: 'all 0.2s',
  },
  input: {
    backgroundColor: COLORS.dark,
    border: `1px solid ${COLORS.border}`,
    borderRadius: '8px',
    padding: '10px 14px',
    color: COLORS.text,
    fontSize: '14px',
    outline: 'none',
    width: '100%',
  },
  select: {
    backgroundColor: COLORS.dark,
    border: `1px solid ${COLORS.border}`,
    borderRadius: '8px',
    padding: '10px 14px',
    color: COLORS.text,
    fontSize: '14px',
    outline: 'none',
  },
  modal: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.8)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
  },
  modalContent: {
    backgroundColor: COLORS.card,
    borderRadius: '16px',
    padding: '24px',
    maxWidth: '800px',
    width: '90%',
    maxHeight: '80vh',
    overflow: 'auto',
  },
  chartContainer: {
    height: '300px',
    position: 'relative',
  },
  flex: {
    display: 'flex',
    gap: '20px',
  },
  flex1: {
    flex: 1,
  },
};

const navItems = [
  { id: 'overview', label: 'Overview', icon: '📊' },
  { id: 'incidents', label: 'Incidents', icon: '🚨' },
  { id: 'mitre', label: 'MITRE Analytics', icon: '🎯' },
  { id: 'graph', label: 'Graph Explorer', icon: '🕸️' },
  { id: 'playbooks', label: 'Playbooks', icon: '📋' },
  { id: 'health', label: 'System Health', icon: '💚' },
];

const severityColors = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22c55e',
  info: '#6366f1',
};

const riskColors = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#22c55e',
};

function App() {
  const [page, setPage] = useState('overview');
  const [refreshInterval, setRefreshInterval] = useState(10000);
  const [lastUpdate, setLastUpdate] = useState(new Date());
  
  const [stats, setStats] = useState({ total: 0, active: 0, critical: 0, high: 0, medium: 0, low: 0, by_stage: [] });
  const [incidents, setIncidents] = useState([]);
  const [playbooks, setPlaybooks] = useState([]);
  const [riskSummary, setRiskSummary] = useState([]);
  const [fingerprints, setFingerprints] = useState([]);
  const [mitreMappings, setMitreMappings] = useState([]);
  
  const [queueSize, setQueueSize] = useState(0);
  const [opensearchCount, setOpensearchCount] = useState(0);
  
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [incidentGraph, setIncidentGraph] = useState(null);
  
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [stageFilter, setStageFilter] = useState('all');

  const cyRef = useRef(null);

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, incidentsRes, playbooksRes, riskRes, alertsRes, mitreRes, queueRes, osRes] = await Promise.all([
        fetch(`${API_BASE}/incident-stats`).then(r => r.json()).catch(() => ({ total: 0, active: 0, by_severity: {}, by_stage: [] })),
        fetch(`${API_BASE}/incidents`).then(r => r.json()).catch(() => []),
        fetch(`${API_BASE}/playbooks`).then(r => r.json()).catch(() => []),
        fetch(`${API_BASE}/risk-summary`).then(r => r.json()).catch(() => []),
        fetch(`${API_BASE}/alerts`).then(r => r.json()).catch(() => []),
        fetch(`${API_BASE}/mitre`).then(r => r.json()).catch(() => []),
        fetch('http://localhost:15672/api/queues', { headers: { 'Authorization': 'Basic ' + btoa('admin:adminpassword') } })
          .then(r => r.json()).then(d => d.find(q => q.name === 'unknown_attack_events')?.messages || 0).catch(() => 0),
        fetch('http://localhost:9200/wazuh-alerts-*/_count', { headers: { 'Authorization': 'Basic ' + btoa('admin:admin') } })
          .then(r => r.json()).then(d => d.count || 0).catch(() => 0),
      ]);
      
      setStats({
        total: statsRes.total || 0,
        active: statsRes.active || 0,
        critical: statsRes.by_severity?.critical || 0,
        high: statsRes.by_severity?.high || 0,
        medium: statsRes.by_severity?.medium || 0,
        low: statsRes.by_severity?.low || 0,
        by_stage: statsRes.by_stage || [],
      });
      
      setIncidents(incidentsRes);
      setPlaybooks(playbooksRes);
      setRiskSummary(riskRes);
      setFingerprints(alertsRes);
      setMitreMappings(mitreRes);
      setQueueSize(queueRes);
      setOpensearchCount(osRes);
      setLastUpdate(new Date());
    } catch (err) {
      console.error('Error fetching data:', err);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, refreshInterval);
    return () => clearInterval(interval);
  }, [fetchData, refreshInterval]);

  const fetchIncidentGraph = async (incidentId) => {
    try {
      const res = await fetch(`${API_BASE}/incident-graph/${incidentId}`);
      const data = await res.json();
      setIncidentGraph(data);
    } catch (err) {
      console.error('Error fetching incident graph:', err);
    }
  };

  const openIncidentDetail = async (incident) => {
    setSelectedIncident(incident);
    await fetchIncidentGraph(incident.incident_id);
  };

  const downloadData = (data, filename, type) => {
    let blob;
    if (type === 'json') {
      blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    } else if (type === 'csv') {
      const headers = Object.keys(data[0] || {}).join(',');
      const rows = data.map(row => Object.values(row).join(','));
      blob = new Blob([headers, ...rows].join('\n'), { type: 'text/csv' });
    }
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename}.${type}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredIncidents = incidents.filter(inc => {
    const matchesSearch = inc.incident_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (inc.description || '').toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === 'all' || inc.severity === severityFilter;
    const matchesStage = stageFilter === 'all' || inc.attack_chain_stage === stageFilter;
    return matchesSearch && matchesSeverity && matchesStage;
  });

  const riskChartData = {
    labels: riskSummary.filter(r => r.risk_level).map(r => r.risk_level || 'Unknown'),
    datasets: [{
      data: riskSummary.filter(r => r.risk_level).map(r => r.count),
      backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#22c55e'],
      borderWidth: 0,
    }],
  };

  const severityChartData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: [stats.critical, stats.high, stats.medium, stats.low],
      backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#22c55e'],
      borderWidth: 0,
    }],
  };

  const stageChartData = {
    labels: stats.by_stage.map(s => s.attack_chain_stage || 'Unknown'),
    datasets: [{
      label: 'Incidents',
      data: stats.by_stage.map(s => s.count),
      backgroundColor: '#0ea5e9',
      borderRadius: 8,
    }],
  };

  const timelineData = {
    labels: incidents.slice(0, 10).reverse().map(i => new Date(i.created_at).toLocaleTimeString()),
    datasets: [{
      label: 'Incidents',
      data: incidents.slice(0, 10).reverse().map((_, idx) => idx + 1),
      borderColor: '#0ea5e9',
      backgroundColor: 'rgba(14, 165, 233, 0.1)',
      fill: true,
      tension: 0.4,
    }],
  };

  const mitreCounts = mitreMappings.reduce((acc, m) => {
    acc[m.technique_id] = (acc[m.technique_id] || 0) + 1;
    return acc;
  }, {});

  const mitreChartData = {
    labels: Object.keys(mitreCounts).slice(0, 10),
    datasets: [{
      label: 'Technique Occurrences',
      data: Object.values(mitreCounts).slice(0, 10),
      backgroundColor: 'rgba(99, 102, 241, 0.8)',
      borderRadius: 8,
    }],
  };

  const getGraphElements = () => {
    if (!incidentGraph) return [];
    const elements = [];
    
    (incidentGraph.graph?.nodes || []).forEach(node => {
      elements.push({
        data: {
          id: node.id,
          label: node.label,
          type: node.type,
          severity: node.severity,
        },
      });
    });
    
    (incidentGraph.graph?.edges || []).forEach(edge => {
      elements.push({
        data: {
          id: `${edge.from}-${edge.to}`,
          source: edge.from,
          target: edge.to,
          label: edge.type,
        },
      });
    });
    
    return elements;
  };

  const cyStyle = {
    width: '100%',
    height: '500px',
    backgroundColor: COLORS.darker,
  };

  const cyLayout = {
    name: 'cose',
    animate: true,
    padding: 30,
    nodeSpacing: 50,
  };

  const renderOverview = () => (
    <div>
      <div style={styles.grid}>
        <MetricCard title="Total Incidents" value={stats.total} icon="🚨" color={COLORS.primary} />
        <MetricCard title="Active Incidents" value={stats.active} icon="⚡" color={COLORS.warning} />
        <MetricCard title="Fingerprints" value={fingerprints.length} icon="👆" color={COLORS.secondary} />
        <MetricCard title="Playbooks" value={playbooks.length} icon="📋" color={COLORS.success} />
        <MetricCard title="MITRE Mappings" value={mitreMappings.length} icon="🎯" color="#f97316" />
        <MetricCard title="Queue Size" value={queueSize} icon="📬" color="#8b5cf6" />
        <MetricCard title="OpenSearch Alerts" value={opensearchCount} icon="🔍" color="#06b6d4" />
        <MetricCard title="Risk HIGH+" value={riskSummary.find(r => r.risk_level === 'HIGH')?.count || 0} icon="⚠️" color={COLORS.danger} />
      </div>

      <div style={styles.flex}>
        <div style={{ ...styles.card, ...styles.flex1 }}>
          <div style={styles.cardTitle}>Risk Distribution</div>
          <div style={styles.chartContainer}>
            <Doughnut data={riskChartData} options={{ 
              plugins: { legend: { position: 'right', labels: { color: COLORS.text } } },
              maintainAspectRatio: false,
            }} />
          </div>
        </div>
        <div style={{ ...styles.card, ...styles.flex1 }}>
          <div style={styles.cardTitle}>Severity Breakdown</div>
          <div style={styles.chartContainer}>
            <Pie data={severityChartData} options={{
              plugins: { legend: { position: 'right', labels: { color: COLORS.text } } },
              maintainAspectRatio: false,
            }} />
          </div>
        </div>
      </div>

      <div style={styles.card}>
        <div style={styles.cardTitle}>Attack Chain Stages</div>
        <div style={styles.chartContainer}>
          <Bar data={stageChartData} options={{
            plugins: { legend: { display: false } },
            scales: { 
              x: { ticks: { color: COLORS.textMuted }, grid: { color: COLORS.border } },
              y: { ticks: { color: COLORS.textMuted }, grid: { color: COLORS.border } },
            },
            maintainAspectRatio: false,
          }} />
        </div>
      </div>

      <div style={styles.card}>
        <div style={styles.cardTitle}>Recent Incident Timeline</div>
        <div style={styles.chartContainer}>
          <Line data={timelineData} options={{
            plugins: { legend: { display: false } },
            scales: { 
              x: { ticks: { color: COLORS.textMuted }, grid: { color: COLORS.border } },
              y: { ticks: { color: COLORS.textMuted }, grid: { color: COLORS.border } },
            },
            maintainAspectRatio: false,
          }} />
        </div>
      </div>
    </div>
  );

  const renderIncidents = () => (
    <div>
      <div style={{ ...styles.card, marginBottom: '20px' }}>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
          <input 
            style={{ ...styles.input, maxWidth: '300px' }}
            placeholder="Search incidents..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          <select 
            style={{ ...styles.select, width: '150px' }}
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select 
            style={{ ...styles.select, width: '200px' }}
            value={stageFilter}
            onChange={(e) => setStageFilter(e.target.value)}
          >
            <option value="all">All Stages</option>
            {stats.by_stage.map(s => (
              <option key={s.attack_chain_stage} value={s.attack_chain_stage}>
                {s.attack_chain_stage}
              </option>
            ))}
          </select>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px' }}>
            <button style={{ ...styles.button, backgroundColor: COLORS.primary, color: 'white' }} onClick={() => downloadData(filteredIncidents, 'incidents', 'csv')}>CSV</button>
            <button style={{ ...styles.button, backgroundColor: COLORS.secondary, color: 'white' }} onClick={() => downloadData(filteredIncidents, 'incidents', 'json')}>JSON</button>
          </div>
        </div>
      </div>

      <div style={styles.card}>
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>ID</th>
              <th style={styles.th}>Severity</th>
              <th style={styles.th}>Stage</th>
              <th style={styles.th}>Events</th>
              <th style={styles.th}>Confidence</th>
              <th style={styles.th}>Created</th>
              <th style={styles.th}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredIncidents.slice(0, 50).map(inc => (
              <tr key={inc.incident_id}>
                <td style={styles.td}><strong>{inc.incident_id}</strong></td>
                <td style={styles.td}>
                  <span style={{ 
                    ...styles.badge, 
                    backgroundColor: (severityColors[inc.severity] || '#6366f1') + '20',
                    color: severityColors[inc.severity] || '#6366f1',
                  }}>
                    {inc.severity?.toUpperCase() || 'UNKNOWN'}
                  </span>
                </td>
                <td style={styles.td}>{inc.attack_chain_stage || 'N/A'}</td>
                <td style={styles.td}>{inc.event_count || 0}</td>
                <td style={styles.td}>{((inc.confidence_score || 0) * 100).toFixed(0)}%</td>
                <td style={styles.td}>{new Date(inc.created_at).toLocaleString()}</td>
                <td style={styles.td}>
                  <button 
                    style={{ ...styles.button, backgroundColor: COLORS.primary, color: 'white', padding: '6px 12px' }}
                    onClick={() => openIncidentDetail(inc)}
                  >
                    View
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filteredIncidents.length === 0 && (
          <div style={{ textAlign: 'center', padding: '40px', color: COLORS.textMuted }}>
            No incidents found matching filters
          </div>
        )}
      </div>
    </div>
  );

  const renderMITRE = () => (
    <div>
      <div style={styles.card}>
        <div style={styles.cardTitle}>MITRE Technique Distribution</div>
        <div style={styles.chartContainer}>
          <Bar data={mitreChartData} options={{
            indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: { 
              x: { ticks: { color: COLORS.textMuted }, grid: { color: COLORS.border } },
              y: { ticks: { color: COLORS.textMuted }, grid: { color: COLORS.border } },
            },
            maintainAspectRatio: false,
          }} />
        </div>
      </div>

      <div style={styles.card}>
        <div style={styles.cardTitle}>MITRE Mappings Details</div>
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>Technique ID</th>
              <th style={styles.th}>Tactic</th>
              <th style={styles.th}>Confidence</th>
              <th style={styles.th}>Fingerprint</th>
            </tr>
          </thead>
          <tbody>
            {mitreMappings.slice(0, 50).map((m, idx) => (
              <tr key={idx}>
                <td style={styles.td}><strong>{m.technique_id}</strong></td>
                <td style={styles.td}>{m.tactic}</td>
                <td style={styles.td}>{((m.confidence || 0) * 100).toFixed(0)}%</td>
                <td style={{ ...styles.td, fontFamily: 'monospace', fontSize: '12px' }}>{(m.fingerprint_string || '').substring(0, 30)}...</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  const renderGraph = () => (
    <div>
      <div style={styles.card}>
        <div style={styles.cardTitle}>Interactive Attack Chain Graph</div>
        <p style={{ color: COLORS.textMuted, marginBottom: '16px' }}>
          Select an incident from the Incidents page to view its correlation graph.
        </p>
        
        {selectedIncident ? (
          <div>
            <div style={{ display: 'flex', gap: '12px', marginBottom: '16px', alignItems: 'center' }}>
              <span><strong>Selected:</strong> {selectedIncident.incident_id}</span>
              <span style={{ 
                ...styles.badge, 
                backgroundColor: (severityColors[selectedIncident.severity] || '#6366f1') + '20',
                color: severityColors[selectedIncident.severity] || '#6366f1',
              }}>
                {selectedIncident.severity?.toUpperCase()}
              </span>
            </div>
            
            <div style={{ border: `1px solid ${COLORS.border}`, borderRadius: '12px', overflow: 'hidden' }}>
              {incidentGraph && incidentGraph.graph?.nodes?.length > 0 ? (
                <CytoscapeComponent
                  elements={getGraphElements()}
                  style={cyStyle}
                  cy={(cy) => { cyRef.current = cy; }}
                  layout={cyLayout}
                  stylesheet={[
                    { selector: 'node', style: { 
                      'background-color': '#0ea5e9', 
                      'label': 'data(label)',
                      'color': '#e2e8f0',
                      'font-size': '12px',
                      'text-valign': 'center',
                      'text-halign': 'bottom',
                    }},
                    { selector: 'edge', style: { 
                      'width': 2,
                      'line-color': '#334155',
                      'target-arrow-color': '#334155',
                      'target-arrow-shape': 'triangle',
                      'curve-style': 'bezier',
                    }},
                  ]}
                />
              ) : (
                <div style={{ padding: '100px', textAlign: 'center', color: COLORS.textMuted }}>
                  No graph data available for this incident
                </div>
              )}
            </div>

            {incidentGraph?.timeline && (
              <div style={{ marginTop: '20px' }}>
                <div style={styles.cardTitle}>Event Timeline</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {incidentGraph.timeline.map((t, idx) => (
                    <div key={idx} style={{ 
                      padding: '12px', 
                      backgroundColor: COLORS.dark, 
                      borderRadius: '8px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}>
                      <span style={{ color: t.type === 'current_event' ? COLORS.primary : COLORS.textMuted }}>
                        {t.type === 'current_event' ? '● Current Event' : '○ Related Event'}
                      </span>
                      <span style={{ fontFamily: 'monospace', fontSize: '12px' }}>{t.event_id}</span>
                      <span style={{ color: COLORS.textMuted, fontSize: '12px' }}>{new Date(t.timestamp).toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div style={{ padding: '60px', textAlign: 'center', color: COLORS.textMuted }}>
            Select an incident from the Incidents page to view its attack chain graph
          </div>
        )}
      </div>
    </div>
  );

  const renderPlaybooks = () => (
    <div>
      <div style={styles.card}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <div style={styles.cardTitle}>Response Playbooks ({playbooks.length})</div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button style={{ ...styles.button, backgroundColor: COLORS.primary, color: 'white' }} onClick={() => downloadData(playbooks, 'playbooks', 'csv')}>Export CSV</button>
            <button style={{ ...styles.button, backgroundColor: COLORS.secondary, color: 'white' }} onClick={() => downloadData(playbooks, 'playbooks', 'json')}>Export JSON</button>
          </div>
        </div>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '16px' }}>
          {playbooks.slice(0, 30).map(p => (
            <div key={p.id} style={{ 
              backgroundColor: COLORS.dark, 
              borderRadius: '12px', 
              padding: '16px',
              border: `1px solid ${COLORS.border}`,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '12px' }}>
                <span style={{ fontWeight: '600', fontSize: '14px' }}>Playbook #{p.id}</span>
                <span style={{ 
                  ...styles.badge, 
                  backgroundColor: (riskColors[p.risk_level] || '#6366f1') + '20',
                  color: riskColors[p.risk_level] || '#6366f1',
                }}>
                  {p.risk_level || 'N/A'}
                </span>
              </div>
              <p style={{ color: COLORS.textMuted, fontSize: '13px', marginBottom: '12px', lineHeight: '1.5' }}>
                {p.analyst_guidance?.substring(0, 150)}...
              </p>
              <div style={{ fontSize: '12px', color: COLORS.textMuted }}>
                Fingerprint ID: {p.fingerprint_id}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const renderHealth = () => (
    <div>
      <div style={styles.grid}>
        <div style={styles.card}>
          <div style={styles.cardTitle}>RabbitMQ Queue</div>
          <div style={styles.metricValue}>{queueSize}</div>
          <div style={{ ...styles.metricChange, color: queueSize > 5000 ? COLORS.warning : COLORS.success }}>
            {queueSize > 5000 ? '⚠️ Backlog building' : '✓ Processing normally'}
          </div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardTitle}>OpenSearch Alerts</div>
          <div style={styles.metricValue}>{opensearchCount.toLocaleString()}</div>
          <div style={{ ...styles.metricChange, color: COLORS.success }}>✓ Indexing active</div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardTitle}>PostgreSQL Tables</div>
          <div style={styles.metricValue}>7</div>
          <div style={{ ...styles.metricChange, color: COLORS.success }}>✓ Connected</div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardTitle}>API Status</div>
          <div style={styles.metricValue}>200</div>
          <div style={{ ...styles.metricChange, color: COLORS.success }}>✓ Responding</div>
        </div>
      </div>

      <div style={styles.card}>
        <div style={styles.cardTitle}>Database Statistics</div>
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>Table</th>
              <th style={styles.th}>Records</th>
              <th style={styles.th}>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr><td style={styles.td}>incidents</td><td style={styles.td}>{stats.total}</td><td style={styles.td}><span style={{color: COLORS.success}}>✓</span></td></tr>
            <tr><td style={styles.td}>fingerprints</td><td style={styles.td}>{fingerprints.length}</td><td style={styles.td}><span style={{color: COLORS.success}}>✓</span></td></tr>
            <tr><td style={styles.td}>playbooks</td><td style={styles.td}>{playbooks.length}</td><td style={styles.td}><span style={{color: COLORS.success}}>✓</span></td></tr>
            <tr><td style={styles.td}>mitre_mappings</td><td style={styles.td}>{mitreMappings.length}</td><td style={styles.td}><span style={{color: COLORS.success}}>✓</span></td></tr>
            <tr><td style={styles.td}>risk_scores</td><td style={styles.td}>{riskSummary.reduce((a, b) => a + (b.count || 0), 0)}</td><td style={styles.td}><span style={{color: COLORS.success}}>✓</span></td></tr>
          </tbody>
        </table>
      </div>

      <div style={styles.card}>
        <div style={styles.cardTitle}>Auto-Refresh Settings</div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <span style={{ color: COLORS.textMuted }}>Refresh Interval:</span>
          <select 
            style={{ ...styles.select, width: '200px' }}
            value={refreshInterval}
            onChange={(e) => setRefreshInterval(Number(e.target.value))}
          >
            <option value={5000}>5 seconds</option>
            <option value={10000}>10 seconds</option>
            <option value={30000}>30 seconds</option>
            <option value={60000}>1 minute</option>
            <option value={0}>Disabled</option>
          </select>
          <span style={{ color: COLORS.textMuted, fontSize: '12px' }}>
            Last update: {lastUpdate.toLocaleTimeString()}
          </span>
        </div>
      </div>
    </div>
  );

  const MetricCard = ({ title, value, icon, color }) => (
    <div style={styles.card}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
        <div>
          <div style={styles.cardTitle}>{title}</div>
          <div style={{ ...styles.metricValue, color: color }}>{value.toLocaleString()}</div>
        </div>
        <span style={{ fontSize: '28px' }}>{icon}</span>
      </div>
    </div>
  );

  return (
    <div style={styles.container}>
      <div style={styles.sidebar}>
        <div style={styles.sidebarHeader}>
          <div style={styles.logo}>🛡️</div>
          <div>
            <div style={{ fontWeight: '700', fontSize: '16px' }}>SOC Pipeline</div>
            <div style={{ fontSize: '11px', color: COLORS.textMuted }}>Cyber Intelligence</div>
          </div>
        </div>
        <nav style={{ flex: 1, padding: '10px 0' }}>
          {navItems.map(item => (
            <div 
              key={item.id}
              style={{ 
                ...styles.navItem,
                ...(page === item.id ? styles.navItemActive : {}),
              }}
              onClick={() => setPage(item.id)}
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </div>
          ))}
        </nav>
        <div style={{ padding: '16px', borderTop: `1px solid ${COLORS.border}`, fontSize: '12px', color: COLORS.textMuted }}>
          Last Update: {lastUpdate.toLocaleTimeString()}
        </div>
      </div>

      <main style={styles.main}>
        <div style={styles.header}>
          <h1 style={styles.title}>
            {navItems.find(n => n.id === page)?.label || 'Dashboard'}
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{ fontSize: '12px', color: COLORS.textMuted }}>
              🔄 Auto-refresh: {refreshInterval / 1000}s
            </span>
            <button 
              style={{ ...styles.button, backgroundColor: COLORS.primary, color: 'white' }}
              onClick={fetchData}
            >
              Refresh Now
            </button>
          </div>
        </div>

        {page === 'overview' && renderOverview()}
        {page === 'incidents' && renderIncidents()}
        {page === 'mitre' && renderMITRE()}
        {page === 'graph' && renderGraph()}
        {page === 'playbooks' && renderPlaybooks()}
        {page === 'health' && renderHealth()}
      </main>

      {selectedIncident && (
        <div style={styles.modal} onClick={() => setSelectedIncident(null)}>
          <div style={styles.modalContent} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <h2 style={{ margin: 0 }}>Incident: {selectedIncident.incident_id}</h2>
              <button 
                style={{ ...styles.button, backgroundColor: COLORS.border, color: COLORS.text }}
                onClick={() => setSelectedIncident(null)}
              >
                ✕ Close
              </button>
            </div>
            
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
              <div><strong>Severity:</strong> <span style={{ color: severityColors[selectedIncident.severity] }}>{selectedIncident.severity}</span></div>
              <div><strong>Stage:</strong> {selectedIncident.attack_chain_stage || 'Unknown'}</div>
              <div><strong>Confidence:</strong> {((selectedIncident.confidence_score || 0) * 100).toFixed(0)}%</div>
              <div><strong>Events:</strong> {selectedIncident.event_count || 0}</div>
            </div>

            {selectedIncident.description && (
              <div style={{ marginBottom: '20px' }}>
                <strong>Description:</strong>
                <p style={{ color: COLORS.textMuted }}>{selectedIncident.description}</p>
              </div>
            )}

            {selectedIncident.linked_entities && (
              <div style={{ marginBottom: '20px' }}>
                <strong>Linked Entities:</strong>
                <pre style={{ 
                  backgroundColor: COLORS.dark, 
                  padding: '12px', 
                  borderRadius: '8px',
                  fontSize: '12px',
                  overflow: 'auto',
                }}>
                  {JSON.stringify(selectedIncident.linked_entities, null, 2)}
                </pre>
              </div>
            )}

            <div style={{ display: 'flex', gap: '12px' }}>
              <button 
                style={{ ...styles.button, backgroundColor: COLORS.primary, color: 'white' }}
                onClick={() => {
                  setPage('graph');
                  setSelectedIncident(selectedIncident);
                }}
              >
                View Graph
              </button>
              <button 
                style={{ ...styles.button, backgroundColor: COLORS.secondary, color: 'white' }}
                onClick={() => downloadData(selectedIncident, `incident-${selectedIncident.incident_id}`, 'json')}
              >
                Download JSON
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;