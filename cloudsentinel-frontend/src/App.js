import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Table, Badge, Button, Modal, Form, Spinner, Navbar, Nav } from 'react-bootstrap';
import axios from 'axios';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import './App.css';

function App() {
  // State variables
  const [loading, setLoading] = useState(false);
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

  // Fetch dashboard data
  const fetchDashboard = async () => {
    setLoading(true);
    try {
      const response = await axios.get('/api/dashboard');
      setDashboardData(response.data);
      setLastUpdated(new Date().toLocaleString());
    } catch (error) {
      console.error('Error fetching dashboard:', error);
      alert(error);
    } finally {
      setLoading(false);
    }
  };

  // Block IP
  const handleBlockIP = async () => {
    if (!ipToBlock) {
      alert('Please enter an IP address');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post('/api/prevent', {
        ip_address: ipToBlock,
        description: blockReason
      });

      if (response.data.success) {
        alert(`Successfully blocked IP: ${ipToBlock}`);
        setShowBlockModal(false);
        setIpToBlock('');
        setBlockReason('');
        fetchDashboard();
      } else {
        alert(`Failed to block IP: ${response.data.message}`);
      }
    } catch (error) {
      console.error('Error blocking IP:', error);
      alert('Failed to block IP');
    } finally {
      setLoading(false);
    }
  };

  // Fetch logs
  const fetchLogs = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/logs', {
        filter_pattern: logFilter
      });
      setLogs(response.data.analysis_results || []);
      fetchDashboard();
    } catch (error) {
      console.error('Error fetching logs:', error);
      alert('Failed to fetch logs');
    } finally {
      setLoading(false);
    }
  };

  // Reset demo
  const resetDemo = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/demo/reset');
      if (response.data.success) {
        alert('Demo data reset successfully');
        fetchDashboard();
      } else {
        alert('Failed to reset demo data');
      }
    } catch (error) {
      console.error('Error resetting demo:', error);
      alert('Failed to reset demo');
    } finally {
      setLoading(false);
    }
  };

  // Format date
  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  // Initialize dashboard on component mount
  useEffect(() => {
    fetchDashboard();
    // Set up auto-refresh every 30 seconds
    const interval = setInterval(fetchDashboard, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app-container">
      {loading && (
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
              <Nav.Link onClick={() => setShowLogsModal(true)}>Logs</Nav.Link>
              <Nav.Link onClick={() => setShowBlockModal(true)}>Block IP</Nav.Link>
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
                <i className="bi bi-arrow-repeat refresh-btn" onClick={fetchDashboard} title="Refresh Dashboard"></i>
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
                            <Badge bg={
                              event.risk_level === 'high' ? 'danger' :
                              event.risk_level === 'medium' ? 'warning' :
                              event.risk_level === 'low' ? 'info' :
                              event.risk_level === 'blocked' ? 'purple' : 'secondary'
                            }>
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
          <Button variant="danger" onClick={handleBlockIP}>
            Block IP
          </Button>
        </Modal.Footer>
      </Modal>

      {/* Logs Modal */}
      <Modal size="xl" show={showLogsModal} onHide={() => setShowLogsModal(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Log Analysis</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Row className="mb-3">
            <Col md={6}>
              <div className="input-group">
                <span className="input-group-text">Filter</span>
                <Form.Control
                  type="text"
                  placeholder="e.g., error, warning, IP address"
                  value={logFilter}
                  onChange={(e) => setLogFilter(e.target.value)}
                />
                <Button variant="primary" onClick={fetchLogs}>
                  Apply
                </Button>
              </div>
            </Col>
            <Col md={6} className="text-end">
              <Button variant="secondary" onClick={fetchLogs}>
                <i className="bi bi-cloud-download"></i> Fetch New Logs
              </Button>
            </Col>
          </Row>
          <Table responsive hover size="sm">
            <thead>
              <tr>
                <th>Time</th>
                <th>IP Address</th>
                <th>User</th>
                <th>Risk</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {logs.length > 0 ? (
                logs.map((result) => (
                  <tr key={result.id}>
                    <td>{result.log_data.timestamp || 'N/A'}</td>
                    <td>{result.log_data.ip_address || 'N/A'}</td>
                    <td>{result.log_data.user || 'N/A'}</td>
                    <td>
                      <Badge bg={
                        result.risk_level === 'high' ? 'danger' :
                        result.risk_level === 'medium' ? 'warning' :
                        result.risk_level === 'low' ? 'info' : 'secondary'
                      }>
                        {result.risk_level.toUpperCase()}
                      </Badge>
                    </td>
                    <td>{result.log_data.message}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="5" className="text-center">No logs to display</td>
                </tr>
              )}
            </tbody>
          </Table>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowLogsModal(false)}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>

      {/* Demo Controls */}
      <div className="demo-controls">
        <Button variant="dark" onClick={resetDemo} title="Reset Demo Data">
          <i className="bi bi-arrow-counterclockwise"></i> Reset Demo
        </Button>
      </div>
    </div>
  );
}

export default App; 