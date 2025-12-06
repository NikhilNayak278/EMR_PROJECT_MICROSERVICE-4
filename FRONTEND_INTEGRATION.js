// Frontend Integration Example (JavaScript/HTML)
// This shows how to integrate your Data Access Service with the frontend

// ============================================================
// 1. Authentication Service (frontend)
// ============================================================

class AuthService {
    constructor(apiUrl = 'http://localhost:5004') {
        this.apiUrl = apiUrl;
        this.accessToken = localStorage.getItem('access_token');
        this.refreshToken = localStorage.getItem('refresh_token');
    }

    // Register new user
    async register(username, email, password, role = 'VIEWER') {
        try {
            const response = await fetch(`${this.apiUrl}/api/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password, role })
            });

            if (!response.ok) throw new Error('Registration failed');
            
            const data = await response.json();
            console.log('User registered:', data.user);
            return data;
        } catch (error) {
            console.error('Registration error:', error);
            throw error;
        }
    }

    // Login user
    async login(username, password) {
        try {
            const response = await fetch(`${this.apiUrl}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (!response.ok) throw new Error('Login failed');
            
            const data = await response.json();
            
            // Store tokens
            this.accessToken = data.tokens.access_token;
            this.refreshToken = data.tokens.refresh_token;
            localStorage.setItem('access_token', this.accessToken);
            localStorage.setItem('refresh_token', this.refreshToken);
            localStorage.setItem('user', JSON.stringify(data.user));
            
            console.log('Login successful');
            return data;
        } catch (error) {
            console.error('Login error:', error);
            throw error;
        }
    }

    // Refresh access token
    async refreshAccessToken() {
        try {
            const response = await fetch(`${this.apiUrl}/api/auth/refresh`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.refreshToken}`
                }
            });

            if (!response.ok) throw new Error('Token refresh failed');
            
            const data = await response.json();
            this.accessToken = data.tokens.access_token;
            localStorage.setItem('access_token', this.accessToken);
            
            return data;
        } catch (error) {
            console.error('Token refresh error:', error);
            // Redirect to login if refresh fails
            this.logout();
            throw error;
        }
    }

    // Verify token
    async verifyToken() {
        try {
            const response = await fetch(`${this.apiUrl}/api/auth/verify`, {
                headers: { 'Authorization': `Bearer ${this.accessToken}` }
            });

            if (!response.ok) throw new Error('Token verification failed');
            
            return await response.json();
        } catch (error) {
            console.error('Token verification error:', error);
            return null;
        }
    }

    // Logout
    logout() {
        this.accessToken = null;
        this.refreshToken = null;
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
        console.log('Logged out');
    }

    // Get auth headers
    getAuthHeaders() {
        return {
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json'
        };
    }
}

// ============================================================
// 2. FHIR Data Service (frontend)
// ============================================================

class FHIRDataService {
    constructor(apiUrl = 'http://localhost:5004', authService) {
        this.apiUrl = apiUrl;
        this.authService = authService;
    }

    // Get patient by ID
    async getPatient(patientId) {
        try {
            const response = await fetch(
                `${this.apiUrl}/api/fhir/Patient/${patientId}`,
                { headers: this.authService.getAuthHeaders() }
            );

            if (response.status === 401) {
                // Token expired, try to refresh
                await this.authService.refreshAccessToken();
                return this.getPatient(patientId); // Retry
            }

            if (!response.ok) throw new Error('Failed to get patient');
            
            return await response.json();
        } catch (error) {
            console.error('Get patient error:', error);
            throw error;
        }
    }

    // Search patients
    async searchPatients(filters = {}) {
        try {
            const params = new URLSearchParams({
                page: filters.page || 1,
                per_page: filters.per_page || 20,
                status: filters.status || ''
            });

            const response = await fetch(
                `${this.apiUrl}/api/fhir/Patient?${params.toString()}`,
                { headers: this.authService.getAuthHeaders() }
            );

            if (!response.ok) throw new Error('Failed to search patients');
            
            return await response.json();
        } catch (error) {
            console.error('Search patients error:', error);
            throw error;
        }
    }

    // Get observations for patient
    async getObservations(patientId, filters = {}) {
        try {
            const params = new URLSearchParams({
                patient: patientId,
                page: filters.page || 1,
                per_page: filters.per_page || 20,
                'date-from': filters.dateFrom || '',
                'date-to': filters.dateTo || ''
            });

            const response = await fetch(
                `${this.apiUrl}/api/fhir/Observation?${params.toString()}`,
                { headers: this.authService.getAuthHeaders() }
            );

            if (!response.ok) throw new Error('Failed to get observations');
            
            return await response.json();
        } catch (error) {
            console.error('Get observations error:', error);
            throw error;
        }
    }

    // Get conditions for patient
    async getConditions(patientId, filters = {}) {
        try {
            const params = new URLSearchParams({
                patient: patientId,
                page: filters.page || 1,
                per_page: filters.per_page || 20
            });

            const response = await fetch(
                `${this.apiUrl}/api/fhir/Condition?${params.toString()}`,
                { headers: this.authService.getAuthHeaders() }
            );

            if (!response.ok) throw new Error('Failed to get conditions');
            
            return await response.json();
        } catch (error) {
            console.error('Get conditions error:', error);
            throw error;
        }
    }

    // Get patient bundle (all data for patient)
    async getPatientBundle(patientId) {
        try {
            const response = await fetch(
                `${this.apiUrl}/api/fhir/Patient/${patientId}/Bundle`,
                { headers: this.authService.getAuthHeaders() }
            );

            if (!response.ok) throw new Error('Failed to get patient bundle');
            
            return await response.json();
        } catch (error) {
            console.error('Get patient bundle error:', error);
            throw error;
        }
    }
}

// ============================================================
// 3. Usage Example in HTML/JavaScript
// ============================================================

/*
HTML Example:
===============

<!DOCTYPE html>
<html>
<head>
    <title>EMR Clinical Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; }
        .patient-card { border: 1px solid #ddd; padding: 15px; margin: 10px 0; }
        .observation { background: #f5f5f5; padding: 10px; margin: 5px 0; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="container">
        <h1>EMR Clinical Dashboard</h1>
        
        <div id="auth-section">
            <h2>Login</h2>
            <input type="text" id="username" placeholder="Username">
            <input type="password" id="password" placeholder="Password">
            <button onclick="handleLogin()">Login</button>
            <div id="auth-message"></div>
        </div>

        <div id="dashboard" style="display:none;">
            <h2>Patient Search</h2>
            <input type="text" id="patientId" placeholder="Enter Patient ID">
            <button onclick="handleSearchPatient()">Search</button>
            
            <div id="patient-data"></div>
        </div>
    </div>

    <script>
        // Initialize services
        const authService = new AuthService('http://localhost:5004');
        const fhirService = new FHIRDataService('http://localhost:5004', authService);

        // Login handler
        async function handleLogin() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            try {
                await authService.login(username, password);
                document.getElementById('auth-message').innerHTML = 
                    '<p class="success">Login successful!</p>';
                document.getElementById('auth-section').style.display = 'none';
                document.getElementById('dashboard').style.display = 'block';
            } catch (error) {
                document.getElementById('auth-message').innerHTML = 
                    `<p class="error">Login failed: ${error.message}</p>`;
            }
        }

        // Search patient handler
        async function handleSearchPatient() {
            const patientId = document.getElementById('patientId').value;
            
            if (!patientId) {
                alert('Please enter Patient ID');
                return;
            }

            try {
                // Get patient and all related data
                const bundle = await fhirService.getPatientBundle(patientId);
                displayPatientData(bundle);
            } catch (error) {
                alert(`Error: ${error.message}`);
            }
        }

        // Display patient data
        function displayPatientData(bundle) {
            const container = document.getElementById('patient-data');
            let html = '';

            // Extract patient from bundle
            const patient = bundle.entry[0]?.resource;
            if (patient) {
                const name = patient.name?.[0];
                html += `<div class="patient-card">
                    <h3>Patient Information</h3>
                    <p><strong>Name:</strong> ${name?.given?.[0]} ${name?.family}</p>
                    <p><strong>Gender:</strong> ${patient.gender}</p>
                    <p><strong>Date of Birth:</strong> ${patient.birthDate}</p>
                </div>`;
            }

            // Display observations
            html += '<h3>Medical Observations</h3>';
            bundle.entry.slice(1).forEach(entry => {
                if (entry.resource.resourceType === 'Observation') {
                    const obs = entry.resource;
                    html += `<div class="observation">
                        <strong>${obs.code?.text}</strong>: ${obs.value}
                        <br><small>${obs.effectiveDateTime}</small>
                    </div>`;
                }
            });

            container.innerHTML = html;
        }
    </script>
</body>
</html>
*/

// ============================================================
// 4. React Component Example
// ============================================================

/*
import React, { useState, useEffect } from 'react';
import AuthService from './services/AuthService';
import FHIRDataService from './services/FHIRDataService';

function EMRDashboard() {
    const [authService] = useState(new AuthService('http://localhost:5004'));
    const [fhirService] = useState(new FHIRDataService('http://localhost:5004', authService));
    const [isLoggedIn, setIsLoggedIn] = useState(false);
    const [patientData, setPatientData] = useState(null);
    const [searchId, setSearchId] = useState('');

    const handleLogin = async (username, password) => {
        try {
            await authService.login(username, password);
            setIsLoggedIn(true);
        } catch (error) {
            console.error('Login failed:', error);
        }
    };

    const handleSearch = async () => {
        try {
            const bundle = await fhirService.getPatientBundle(searchId);
            setPatientData(bundle);
        } catch (error) {
            console.error('Search failed:', error);
        }
    };

    if (!isLoggedIn) {
        return <LoginForm onLogin={handleLogin} />;
    }

    return (
        <div className="dashboard">
            <h1>EMR Clinical Dashboard</h1>
            <SearchBar 
                onSearch={() => handleSearch()} 
                onChange={(e) => setSearchId(e.target.value)}
            />
            {patientData && <PatientView bundle={patientData} />}
        </div>
    );
}

export default EMRDashboard;
*/

// ============================================================
// 5. Error Handling & Interceptors
// ============================================================

class APIClient {
    constructor(authService) {
        this.authService = authService;
    }

    async makeRequest(url, options = {}) {
        try {
            let response = await fetch(url, {
                ...options,
                headers: this.authService.getAuthHeaders()
            });

            // Handle token expiration
            if (response.status === 401) {
                await this.authService.refreshAccessToken();
                response = await fetch(url, {
                    ...options,
                    headers: this.authService.getAuthHeaders()
                });
            }

            // Handle errors
            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                throw new Error(error.error || `HTTP ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }
}

// ============================================================
// 6. Usage in Your Frontend
// ============================================================

/*
// In your main application file:

import AuthService from './services/AuthService';
import FHIRDataService from './services/FHIRDataService';

// Initialize services
window.authService = new AuthService('http://localhost:5004');
window.fhirService = new FHIRDataService('http://localhost:5004', window.authService);

// Example: Login and fetch patient data
async function initializeApp() {
    try {
        // Login
        const loginResponse = await window.authService.login('doctor1', 'doctor123');
        console.log('Logged in as:', loginResponse.user.username);

        // Get patient data
        const patient = await window.fhirService.getPatient('pat-001');
        console.log('Patient:', patient);

        // Get observations
        const obs = await window.fhirService.getObservations('pat-001');
        console.log('Observations:', obs);
    } catch (error) {
        console.error('Error initializing app:', error);
    }
}

// Call on page load
window.addEventListener('DOMContentLoaded', initializeApp);
*/