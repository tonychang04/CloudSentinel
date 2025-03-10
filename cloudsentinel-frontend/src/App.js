import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Table, Badge, Button, Modal, Form, Spinner, Navbar, Nav, ListGroup, Tab, Tabs } from 'react-bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import './App.css';

// Move these exports to the top level
export const fetchDashboardData = async () => {
  try {
    console.log("Fetching dashboard data...");
    const response = await fetch('/api/dashboard');
    console.log("Dashboard response status:", response.status);
    if (!response.ok) {
      const errorText = await response.text();
      console.error("Error response:", errorText);
      throw new Error(`HTTP error! Status: ${response.status}, Details: ${errorText}`);
    }
    
    const data = await response.json();
    console.log("Dashboard data received:", data);
    return data;
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    throw error;
  }
};

export const fetchLogs = async (filterPattern = '') => {
  try {
    const response = await fetch('/api/logs', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ filter_pattern: filterPattern }),
    });
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error('Error fetching logs:', error);
    throw error;
  }
};

export const blockIp = async (ipAddress, reason) => {
  try {
    const response = await fetch('/api/prevent', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ 
        ip_address: ipAddress,
        action: 'block_ip',
        reason: reason
      }),
    });
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error('Error blocking IP:', error);
    throw error;
  }
};


// Define a consistent color mapping function for risk levels
const getRiskLevelColor = (riskLevel) => {
  switch (riskLevel.toLowerCase()) {
    case 'high':
      return 'danger';  
    case 'medium':
      return 'warning';
    case 'low':
      return 'primary'; 
    case 'blocked':
      return 'purple';    
    case 'info':
    default:
      return 'success'; // Green
  }
};

// Add this function to fetch summary data
const fetchSummary = async () => {
  try {
    const response = await fetch('/api/summary');
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error('Error fetching summary:', error);
    throw error;
  }
};

// Add this component definition before the App function
const SecuritySummary = ({ onClose, onBlockIP }) => {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const loadSummary = async () => {
      try {
        setLoading(true);
        const data = await fetchSummary();
        setSummary(data);
      } catch (err) {
        setError('Failed to load security summary');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    loadSummary();
  }, []);

  if (loading) {
    return (
      <div className="text-center p-5">
        <Spinner animation="border" role="status">
          <span className="visually-hidden">Loading...</span>
        </Spinner>
        <p className="mt-2">Generating security summary...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center p-5">
        <i className="bi bi-exclamation-triangle text-danger fs-1"></i>
        <p className="mt-2">{error}</p>
        <Button variant="primary" onClick={onClose}>Close</Button>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="text-center p-5">
        <i className="bi bi-exclamation-triangle text-warning fs-1"></i>
        <p className="mt-2">No summary data available</p>
        <Button variant="primary" onClick={onClose}>Close</Button>
      </div>
    );
  }

  return (
    <div className="security-summary">
      <Card className="mb-4">
        <Card.Header className="d-flex justify-content-between align-items-center">
          <h5 className="mb-0">Security Summary</h5>
          <small className="text-muted">{summary.time_range}</small>
        </Card.Header>
        <Card.Body>
          <Tabs defaultActiveKey="overview" className="mb-3">
            <Tab eventKey="overview" title="Overview">
              <div className="ai-summary mb-4">
                <h6>Security Analysis</h6>
                <div className="p-3 bg-light rounded">
                  {summary.ai_summary.split('\n').map((paragraph, idx) => (
                    <p key={idx}>{paragraph}</p>
                  ))}
                </div>
              </div>
              
              <div className="row mb-4">
                <div className="col-md-6">
                  <h6>Event Statistics</h6>
                  <ListGroup>
                    <ListGroup.Item className="d-flex justify-content-between align-items-center">
                      Total Events
                      <Badge bg="secondary" pill>{summary.total_events}</Badge>
                    </ListGroup.Item>
                    <ListGroup.Item className="d-flex justify-content-between align-items-center">
                      High Risk Events
                      <Badge bg="danger" pill>{summary.risk_counts.high}</Badge>
                    </ListGroup.Item>
                    <ListGroup.Item className="d-flex justify-content-between align-items-center">
                      Medium Risk Events
                      <Badge bg="warning" text="dark" pill>{summary.risk_counts.medium}</Badge>
                    </ListGroup.Item>
                    <ListGroup.Item className="d-flex justify-content-between align-items-center">
                      Low Risk Events
                      <Badge bg="info" pill>{summary.risk_counts.low}</Badge>
                    </ListGroup.Item>
                  </ListGroup>
                </div>
                
                <div className="col-md-6">
                  <h6>Recommendations</h6>
                  <ListGroup>
                    {summary.recommendations.map((rec, idx) => (
                      <ListGroup.Item key={idx}>
                        <i className="bi bi-check-circle-fill text-success me-2"></i>
                        {rec}
                      </ListGroup.Item>
                    ))}
                  </ListGroup>
                </div>
              </div>
            </Tab>
            
            <Tab eventKey="suspicious" title="Suspicious IPs">
              <h6>Top Suspicious IP Addresses</h6>
              {summary.suspicious_ips && summary.suspicious_ips.length > 0 ? (
                <Table hover responsive>
                  <thead>
                    <tr>
                      <th>IP Address</th>
                      <th>Risk Score</th>
                      <th>Events</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.suspicious_ips.map((ip) => (
                      <tr key={ip.ip}>
                        <td>{ip.ip}</td>
                        <td>
                          <Badge 
                            bg={ip.risk_score > 20 ? 'danger' : ip.risk_score > 10 ? 'warning' : 'info'}
                          >
                            {ip.risk_score}
                          </Badge>
                        </td>
                        <td>{ip.events}</td>
                        <td>
                          {ip.blocked ? (
                            <Badge bg="dark">Blocked</Badge>
                          ) : (
                            <Badge bg="secondary">Active</Badge>
                          )}
                        </td>
                        <td>
                          {!ip.blocked && (
                            <Button 
                              variant="outline-danger" 
                              size="sm"
                              onClick={() => {
                                onBlockIP(ip.ip, `Suspicious activity with risk score ${ip.risk_score}`);
                                onClose();
                              }}
                            >
                              Block
                            </Button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              ) : (
                <p className="text-center">No suspicious IPs detected</p>
              )}
            </Tab>
            
            <Tab eventKey="sources" title="Event Sources">
              <h6>Events by Source</h6>
              {summary.source_counts && Object.keys(summary.source_counts).length > 0 ? (
                <ListGroup>
                  {Object.entries(summary.source_counts).map(([source, count]) => (
                    <ListGroup.Item key={source} className="d-flex justify-content-between align-items-center">
                      {source.charAt(0).toUpperCase() + source.slice(1)}
                      <Badge bg="info" pill>{count}</Badge>
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              ) : (
                <p className="text-center">No source data available</p>
              )}
            </Tab>
          </Tabs>
        </Card.Body>
        <Card.Footer className="text-end">
          <Button variant="secondary" onClick={onClose}>Close</Button>
        </Card.Footer>
      </Card>
    </div>
  );
};

function App() {
  // Separate loading states for different operations
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [logsLoading, setLogsLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [initialLoading, setInitialLoading] = useState(true);
  const [dashboardData, setDashboardData] = useState({
    threat_stats: { high: 0, medium: 0, low: 0, info: 0 },
    blocked_ips: [],
    recent_events: [],
    total_logs_analyzed: 0
  });
  const [showBlockModal, setShowBlockModal] = useState(false);
  const [showLogsModal, setShowLogsModal] = useState(false);
  const [ipToBlock, setIpToBlock] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [logFilter, setLogFilter] = useState('');
  const [logs, setLogs] = useState([]);
  const [lastUpdated, setLastUpdated] = useState('Never');

  // Add a specific state for refresh animation
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Add state variables for auto-refresh intervals
  const [logsRefreshInterval, setLogsRefreshInterval] = useState(null);

  // Add this state to your App component's useState declarations
  const [showSummaryModal, setShowSummaryModal] = useState(false);

  // Format date
  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  // Update the fetchDashboard function
  const fetchDashboard = async (isInitialLoad = false) => {
    try {
      // Set refreshing state instead of dashboardLoading for manual refreshes
      if (!isInitialLoad) {
        setIsRefreshing(true);
      } else {
        setDashboardLoading(true);
      }
      
      const data = await fetchDashboardData();
      
      // Use a function to update state to avoid race conditions
      setDashboardData(prevData => ({
        ...prevData,
        threat_stats: data.threat_stats || prevData.threat_stats,
        blocked_ips: data.blocked_ips || prevData.blocked_ips,
        recent_events: data.recent_events || prevData.recent_events,
        total_logs_analyzed: data.total_logs_analyzed || prevData.total_logs_analyzed
      }));
      
      setLastUpdated(new Date().toLocaleString());
    } catch (error) {
      console.error('Error fetching dashboard:', error);
    } finally {
      setIsRefreshing(false);
      setDashboardLoading(false);
      if (isInitialLoad) {
        setInitialLoading(false);
      }
    }
  };

  // Update handleFetchLogs to use logsLoading
  const handleFetchLogs = async () => {
    try {
      setLogsLoading(true);
      const data = await fetchLogs(logFilter);
      console.log("Logs data received:", data);
      
      if (data.analysis_results) {
        setLogs(data.analysis_results);
      } else {
        setLogs([]);
        console.error("No analysis_results in response:", data);
      }
    } catch (error) {
      console.error('Error fetching logs:', error);
      setLogs([]);
    } finally {
      setLogsLoading(false);
    }
  };

  // Update handleBlockIP to use actionLoading
  const handleBlockIP = async (ipAddress, reason) => {
    if (!ipAddress) return;
    
    try {
      setActionLoading(true);
      await blockIp(ipAddress, reason);
      setShowBlockModal(false);
      setIpToBlock('');
      setBlockReason('');
      fetchDashboard(); // Refresh dashboard after blocking
    } catch (error) {
      console.error('Error blocking IP:', error);
    } finally {
      setActionLoading(false);
    }
  };

  // Function to start logs auto-refresh
  const startLogsAutoRefresh = () => {
    if (logsRefreshInterval) {
      clearInterval(logsRefreshInterval);
    }
    
    // Fetch logs immediately
    handleFetchLogs();
    
    // Set up interval to fetch logs every 5 seconds
    const intervalId = setInterval(() => {
      if (showLogsModal) {
        handleFetchLogs();
      } else {
        // If modal is closed, stop auto-refresh
        clearInterval(intervalId);
        setLogsRefreshInterval(null);
      }
    }, 5000); // 5 seconds
    
    setLogsRefreshInterval(intervalId);
  };

  // Update handleOpenLogsModal to start logs auto-refresh
  const handleOpenLogsModal = () => {
    setShowLogsModal(true);
    // Start auto-refresh when modal opens
    startLogsAutoRefresh();
  };

  // Update handleCloseLogsModal to stop logs auto-refresh
  const handleCloseLogsModal = () => {
    setShowLogsModal(false);
    // Stop auto-refresh when modal closes
    if (logsRefreshInterval) {
      clearInterval(logsRefreshInterval);
      setLogsRefreshInterval(null);
    }
  };

  // Initialize dashboard on component mount
  useEffect(() => {
    // Pass true to indicate this is the initial load
    fetchDashboard(true);
    
    // Set up auto-refresh every 30 seconds
    const interval = setInterval(() => fetchDashboard(false), 30000);
    return () => clearInterval(interval);
  }, []);

  // Show a loading spinner during initial load
  if (initialLoading) {
    return (
      <div className="loading-container">
        <Spinner animation="border" role="status" variant="primary">
          <span className="visually-hidden">Loading...</span>
        </Spinner>
        <p className="mt-2">Loading CloudSentinel...</p>
      </div>
    );
  }

  return (
    <div className="app-container">
      {dashboardLoading && (
        <div className="loading-overlay">
          <Spinner animation="border" variant="light" className="loading-spinner" />
        </div>
      )}

      <Navbar bg="dark" variant="dark" expand="lg">
        <Container fluid>
          <Navbar.Brand href="#">
            <i className="bi bi-shield-check me-2"></i>
            CloudSentinel
          </Navbar.Brand>
          <Navbar.Toggle aria-controls="navbarNav" />
          <Navbar.Collapse id="navbarNav">
            <Nav className="me-auto">
              <Nav.Link active>Dashboard</Nav.Link>
              <Nav.Link onClick={handleOpenLogsModal}>Logs</Nav.Link>
              <Nav.Link onClick={() => setShowBlockModal(true)}>Block IP</Nav.Link>
              <Nav.Link onClick={() => setShowSummaryModal(true)}>
              Security Summary
              </Nav.Link>
            </Nav>
            <Navbar.Text>
              <i className="bi bi-clock"></i> Last updated: {lastUpdated}
            </Navbar.Text>
          </Navbar.Collapse>
        </Container>
      </Navbar>

      <Container fluid className="mt-4">
        <Row className="mb-4">
          <Col md={12}>
            <Card>
              <Card.Header className="d-flex justify-content-between align-items-center">
                <span>Security Overview</span>
                <Button 
                  variant="outline-secondary" 
                  size="sm" 
                  onClick={() => fetchDashboard(false)}
                  disabled={isRefreshing}
                  className="refresh-button"
                >
                  <i className={`bi bi-arrow-clockwise ${isRefreshing ? 'rotating' : ''}`}></i> Refresh
                </Button>
              </Card.Header>
              <Card.Body>
                <Row>
                  <Col md={3}>
                    <div className="stat-card">
                      <div className="stat-value risk-high">{dashboardData.threat_stats.high}</div>
                      <div className="stat-label">High Risk Threats</div>
                    </div>
                  </Col>
                  <Col md={3}>
                    <div className="stat-card">
                      <div className="stat-value risk-medium">{dashboardData.threat_stats.medium}</div>
                      <div className="stat-label">Medium Risk Threats</div>
                    </div>
                  </Col>
                  <Col md={3}>
                    <div className="stat-card">
                      <div className="stat-value risk-low">{dashboardData.threat_stats.low}</div>
                      <div className="stat-label">Low Risk Threats</div>
                    </div>
                  </Col>
                  <Col md={3}>
                    <div className="stat-card">
                      <div className="stat-value">{dashboardData.total_logs_analyzed}</div>
                      <div className="stat-label">Total Logs Analyzed</div>
                    </div>
                  </Col>
                </Row>
              </Card.Body>
            </Card>
          </Col>
        </Row>

        <Row>
          <Col md={8}>
            <Card>
              <Card.Header>Recent Security Events</Card.Header>
              <Card.Body>
                <Table hover responsive className="event-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>IP Address</th>
                      <th>Risk Level</th>
                      <th>Event</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboardData.recent_events.length > 0 ? (
                      dashboardData.recent_events.map((event) => (
                        <tr key={event.id}>
                          <td>{formatDate(event.timestamp)}</td>
                          <td>{event.ip || 'N/A'}</td>
                          <td>
                            <Badge bg={getRiskLevelColor(event.risk_level)}>
                              {event.risk_level.toUpperCase()}
                            </Badge>
                          </td>
                          <td>{event.message}</td>
                          <td>
                            {event.ip && !dashboardData.blocked_ips.includes(event.ip) && (
                              <i className="bi bi-shield-fill-x text-danger action-btn"
                                onClick={() => {
                                  setIpToBlock(event.ip);
                                  setShowBlockModal(true);
                                }}
                                title="Block IP"></i>
                            )}
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="5" className="text-center">No events to display</td>
                      </tr>
                    )}
                  </tbody>
                </Table>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card>
              <Card.Header>Blocked IP Addresses</Card.Header>
              <Card.Body>
                {dashboardData.blocked_ips.length > 0 ? (
                  <ul className="list-group">
                    {dashboardData.blocked_ips.map((ip) => (
                      <li key={ip} className="list-group-item d-flex justify-content-between align-items-center">
                        <span><i className="bi bi-ban text-danger"></i> {ip}</span>
                        <Badge bg="secondary">Blocked</Badge>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="text-center">No blocked IPs</div>
                )}
                <Button variant="primary" className="w-100 mt-3" onClick={() => setShowBlockModal(true)}>
                  <i className="bi bi-shield-fill-x"></i> Block New IP
                </Button>
              </Card.Body>
            </Card>
          </Col>
        </Row>
      </Container>

      {/* Block IP Modal */}
      <Modal show={showBlockModal} onHide={() => setShowBlockModal(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Block IP Address</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form>
            <Form.Group className="mb-3">
              <Form.Label>IP Address</Form.Label>
              <Form.Control
                type="text"
                placeholder="e.g., 192.168.1.1"
                value={ipToBlock}
                onChange={(e) => setIpToBlock(e.target.value)}
                required
              />
            </Form.Group>
            <Form.Group className="mb-3">
              <Form.Label>Reason (Optional)</Form.Label>
              <Form.Control
                as="textarea"
                rows={3}
                placeholder="Why is this IP being blocked?"
                value={blockReason}
                onChange={(e) => setBlockReason(e.target.value)}
              />
            </Form.Group>
          </Form>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowBlockModal(false)}>
            Cancel
          </Button>
          <Button 
            variant="danger" 
            onClick={() => handleBlockIP(ipToBlock, blockReason)}
            disabled={actionLoading}
          >
            {actionLoading ? (
              <>
                <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" />
                <span className="ms-1">Blocking...</span>
              </>
            ) : (
              'Block IP'
            )}
          </Button>
        </Modal.Footer>
      </Modal>

      {/* Logs Modal */}
      <Modal show={showLogsModal} onHide={handleCloseLogsModal} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>Log Analysis</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Row className="mb-3">
            <Col md={8}>
              <div className="input-group">
                <input
                  type="text"
                  className="form-control"
                  placeholder="Filter logs..."
                  value={logFilter}
                  onChange={(e) => setLogFilter(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleFetchLogs()}
                />
              </div>
              <small className="text-muted">Leave empty to show all logs</small>
            </Col>
            <Col md={4} className="text-end">
              <small className="text-muted">
                Auto-refreshing every 5 seconds
              </small>
            </Col>
          </Row>
          
          {logsLoading ? (
            <div className="text-center p-4">
              <Spinner animation="border" role="status">
                <span className="visually-hidden">Loading...</span>
              </Spinner>
            </div>
          ) : logs.length > 0 ? (
            <Table responsive hover size="sm">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>IP Address</th>
                  <th>Risk</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((result) => (
                  <tr key={result.id}>
                    <td>{result.log_data?.timestamp || 'N/A'}</td>
                    <td>{result.log_data?.ip_address || 'N/A'}</td>
                    <td>
                    <Badge bg={getRiskLevelColor(result.risk_level)}>
                              {result.risk_level.toUpperCase()}
                            </Badge>
                    </td>
                    <td>{result.log_data?.message || 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <div className="text-center p-4">
              <p>No logs found matching your criteria.</p>
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={handleCloseLogsModal}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>

      {/* Security Summary Modal */}
      <Modal 
        show={showSummaryModal} 
        onHide={() => setShowSummaryModal(false)} 
        size="lg"
        backdrop="static"
      >
        <Modal.Header closeButton>
          <Modal.Title>
            <i className="bi bi-shield-check me-2"></i>
            Security Summary
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <SecuritySummary 
            onClose={() => setShowSummaryModal(false)} 
            onBlockIP={handleBlockIP}
          />
        </Modal.Body>
      </Modal>
    </div>
  );
}

export default App; 