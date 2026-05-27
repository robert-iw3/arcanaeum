import React, { useState, useEffect } from 'react';
import {
  createTheme,
  ThemeProvider,
  CssBaseline,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Button,
  Switch,
  FormControlLabel,
  TextField,
} from '@mui/material';
import { Brightness4, Brightness7 } from '@mui/icons-material';
import axios from 'axios';

const App = () => {
  const [darkMode, setDarkMode] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [results, setResults] = useState(null);
  const [file, setFile] = useState(null);
  const [csrfToken, setCsrfToken] = useState('');

  useEffect(() => {
    axios.get('/api/csrf-token').then(response => {
      setCsrfToken(response.data.csrfToken);
      window.csrfToken = response.data.csrfToken;
    }).catch(() => alert('Failed to fetch CSRF token'));
  }, []);

  const theme = createTheme({
    palette: {
      mode: darkMode ? 'dark' : 'light',
      primary: { main: darkMode ? '#00ff00' : '#00ccff', contrastText: '#0a0a0a' },
      background: { default: darkMode ? '#0a0a0a' : '#1a1a1a' },
      text: { primary: darkMode ? '#00ff00' : '#00ccff' },
    },
    typography: { fontFamily: 'Orbitron, Roboto, sans-serif' },
    components: {
      MuiCssBaseline: {
        styleOverrides: `
          .digital-rain {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            opacity: 0.1;
            background: linear-gradient(to bottom, rgba(0, 255, 0, 0.1), transparent);
            animation: digitalRain 10s linear infinite;
          }
          @keyframes digitalRain {
            0% { background-position: 0 0; }
            100% { background-position: 0 1000px; }
          }
          .glitch {
            position: relative;
            animation: glitch 5s steps(100) infinite;
          }
          @keyframes glitch {
            0% { transform: translate(0); opacity: 1; }
            2% { transform: translate(-1px, 1px); opacity: 0.9; }
            4% { transform: translate(1px, -1px); opacity: 0.9; }
            6% { transform: translate(0); opacity: 1; }
            100% { transform: translate(0); opacity: 1; }
          }
        `,
      },
      MuiTextField: {
        styleOverrides: {
          root: {
            '& .MuiInputBase-root': {
              backgroundColor: darkMode ? '#0a0a0a' : '#1a1a1a',
              color: darkMode ? '#00ff00' : '#00ccff',
              borderColor: darkMode ? '#00ff00' : '#00ccff',
              fontFamily: 'Orbitron, sans-serif',
            },
            '& .MuiOutlinedInput-notchedOutline': {
              borderColor: darkMode ? '#00ff00' : '#00ccff',
            },
            '& .MuiInputLabel-root': {
              color: darkMode ? '#00ff00' : '#00ccff',
            },
            '& .MuiInputLabel-root.Mui-focused': {
              color: darkMode ? '#00ff00' : '#00ccff',
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            backgroundColor: darkMode ? '#00ff00' : '#00ccff',
            color: '#0a0a0a',
            fontFamily: 'Orbitron, sans-serif',
            boxShadow: darkMode ? '0 0 5px #00ff00' : '0 0 5px #00ccff',
            '&:hover': {
              boxShadow: darkMode ? '0 0 10px #00ff00' : '0 0 10px #00ccff',
            },
          },
        },
      },
      MuiTableContainer: {
        styleOverrides: {
          root: {
            border: darkMode ? '1px solid #00ff00' : '1px solid #00ccff',
            boxShadow: darkMode ? '0 0 15px #00ff00' : '0 0 15px #00ccff',
            background: darkMode ? 'rgba(0, 255, 0, 0.05)' : 'rgba(0, 204, 255, 0.05)',
            borderRadius: '5px',
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          root: {
            borderColor: darkMode ? '#00ff00' : '#00ccff',
            fontFamily: 'Orbitron, sans-serif',
            fontSize: '0.9rem',
          },
          head: {
            background: darkMode ? 'rgba(0, 255, 0, 0.2)' : 'rgba(0, 204, 255, 0.2)',
            textTransform: 'uppercase',
            letterSpacing: '1px',
            fontWeight: 700,
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          root: {
            '& .MuiSwitch-track': {
              backgroundColor: darkMode ? '#00ff00' : '#00ccff',
            },
            '& .MuiSwitch-thumb': {
              backgroundColor: darkMode ? '#0a0a0a' : '#1a1a1a',
            },
          },
        },
      },
    },
  });

  const handleLogin = async () => {
    try {
      const response = await axios.post('/api/login', { username, password, csrfToken });
      setToken(response.data.token);
    } catch (error) {
      alert('Invalid credentials');
    }
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setFile(event.target.files?.[0] || null);
  };

  const handleAnalyze = async () => {
    if (!file) return;
    const formData = new FormData();
    formData.append('pcapDir', file);
    formData.append('csrfToken', csrfToken);
    try {
      const response = await axios.post('/api/analyze', formData, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setResults(response.data);
    } catch (error) {
      alert('Analysis failed');
    }
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <div className="digital-rain"></div>
      <div style={{ padding: '20px', maxWidth: '1200px', margin: '0 auto' }} role="main" aria-label="PCAP Analyzer Interface">
        <FormControlLabel
          control={<Switch checked={darkMode} onChange={() => setDarkMode(!darkMode)} inputProps={{ 'aria-label': 'Toggle dark mode' }} />}
          label={darkMode ? <Brightness7 /> : <Brightness4 />}
          className="glitch"
          aria-label="Theme toggle"
        />
        {!token && (
          <div className="glitch" style={{ marginBottom: '20px', padding: '15px', border: `1px solid ${darkMode ? '#00ff00' : '#00ccff'}`, borderRadius: '5px', boxShadow: `0 0 10px ${darkMode ? '#00ff00' : '#00ccff'}`, background: darkMode ? 'rgba(0, 255, 0, 0.1)' : 'rgba(0, 204, 255, 0.1)' }} role="form" aria-label="Login form">
            <TextField label="Username" value={username} onChange={(e) => setUsername(e.target.value)} style={{ marginRight: '10px' }} inputProps={{ 'aria-label': 'Username input' }} />
            <TextField label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} style={{ marginRight: '10px' }} inputProps={{ 'aria-label': 'Password input' }} />
            <Button variant="contained" onClick={handleLogin} aria-label="Login button">Login</Button>
          </div>
        )}
        {token && (
          <div className="glitch" style={{ marginBottom: '20px', padding: '15px', border: `1px solid ${darkMode ? '#00ff00' : '#00ccff'}`, borderRadius: '5px', boxShadow: `0 0 10px ${darkMode ? '#00ff00' : '#00ccff'}`, background: darkMode ? 'rgba(0, 255, 0, 0.1)' : 'rgba(0, 204, 255, 0.1)' }} role="form" aria-label="File upload form">
            <input type="file" onChange={handleFileChange} style={{ margin: '10px 0' }} aria-label="PCAP file input" />
            <Button variant="contained" onClick={handleAnalyze} aria-label="Analyze button">Analyze</Button>
          </div>
        )}
        {results && (
          <TableContainer component={Paper} className="glitch" role="region" aria-label="Analysis results table">
            <Table aria-label="PCAP analysis results">
              <TableHead>
                <TableRow>
                  <TableCell>IP</TableCell>
                  <TableCell>Hosts</TableCell>
                  <TableCell>Size</TableCell>
                  <TableCell>User Agents</TableCell>
                  <TableCell>Certs</TableCell>
                  <TableCell>Timestamps</TableCell>
                  <TableCell>Anomaly Score</TableCell>
                  <TableCell>Cert Anomaly</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {Object.entries(results).map(([ip, info]) => (
                  <TableRow key={ip}>
                    <TableCell>{ip}</TableCell>
                    <TableCell>{JSON.stringify(info.hosts)}</TableCell>
                    <TableCell>{info.size}</TableCell>
                    <TableCell>{info.user_agents.join(', ')}</TableCell>
                    <TableCell>{info.certificates.map(cert => {
                      const parsed = JSON.parse(cert);
                      return `Subject: ${parsed.subject}, Issuer: ${parsed.issuer}, Valid From: ${parsed.valid_from}, Valid To: ${parsed.valid_to}, Expired: ${parsed.expired ? 'Yes' : 'No'}, Self-Signed: ${parsed.self_signed ? 'Yes' : 'No'}`;
                    }).join('; ')}</TableCell>
                    <TableCell>{info.timestamps.join(', ')}</TableCell>
                    <TableCell>{info.anomaly_score.toFixed(2)}</TableCell>
                    <TableCell>{info.cert_anomaly ? 'Yes' : 'No'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </div>
    </ThemeProvider>
  );
};

export default App;