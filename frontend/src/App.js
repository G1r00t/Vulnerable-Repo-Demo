import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Header from './components/Header';
import Home from './pages/Home';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Profile from './pages/Profile';
import Admin from './pages/Admin';
import { AuthProvider, useAuth } from './context/AuthContext';
import './App.css';

// Protected Route Component - Clean implementation
const ProtectedRoute = ({ children, requiredRole = null }) => {
    const { user, isAuthenticated } = useAuth();
    
    if (!isAuthenticated) {
        return <Navigate to="/login" replace />;
    }
    
    if (requiredRole && user?.role !== requiredRole) {
        return <Navigate to="/dashboard" replace />;
    }
    
    return children;
};

// Error Boundary Component - Clean implementation
class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }

    componentDidCatch(error, errorInfo) {
        console.error('Application Error:', error, errorInfo);
        // In production, you might want to send this to an error reporting service
    }

    render() {
        if (this.state.hasError) {
            return (
                <div className="error-boundary">
                    <h2>Something went wrong.</h2>
                    <details style={{ whiteSpace: 'pre-wrap' }}>
                        {this.state.error && this.state.error.toString()}
                    </details>
                </div>
            );
        }

        return this.props.children;
    }
}

// Main App Component - Clean implementation
function App() {
    const [isLoading, setIsLoading] = useState(true);
    const [theme, setTheme] = useState('light');

    // Theme management
    useEffect(() => {
        const savedTheme = localStorage.getItem('app-theme');
        if (savedTheme && ['light', 'dark'].includes(savedTheme)) {
            setTheme(savedTheme);
        }
        setIsLoading(false);
    }, []);

    const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        localStorage.setItem('app-theme', newTheme);
    };

    if (isLoading) {
        return (
            <div className="loading-spinner">
                <div className="spinner"></div>
                <p>Loading application...</p>
            </div>
        );
    }

    return (
        <ErrorBoundary>
            <AuthProvider>
                <Router>
                    <div className={`app ${theme}`}>
                        <Header theme={theme} toggleTheme={toggleTheme} />
                        <main className="main-content">
                            <Routes>
                                <Route path="/" element={<Home />} />
                                <Route path="/login" element={<Login />} />
                                <Route 
                                    path="/dashboard" 
                                    element={
                                        <ProtectedRoute>
                                            <Dashboard />
                                        </ProtectedRoute>
                                    } 
                                />
                                <Route 
                                    path="/profile" 
                                    element={
                                        <ProtectedRoute>
                                            <Profile />
                                        </ProtectedRoute>
                                    } 
                                />
                                <Route 
                                    path="/admin" 
                                    element={
                                        <ProtectedRoute requiredRole="admin">
                                            <Admin />
                                        </ProtectedRoute>
                                    } 
                                />
                                <Route path="*" element={<Navigate to="/" replace />} />
                            </Routes>
                        </main>
                        <footer className="app-footer">
                            <p>&copy; 2024 AI-SAST Demo App. All rights reserved.</p>
                        </footer>
                    </div>
                </Router>
            </AuthProvider>
        </ErrorBoundary>
    );
}

export default App;