const http = require('http');

function request(options, data) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => body += chunk);
            res.on('end', () => resolve({ statusCode: res.statusCode, body: JSON.parse(body || '{}') }));
        });
        req.on('error', reject);
        if (data) {
            req.write(JSON.stringify(data));
        }
        req.end();
    });
}

async function runTests() {
    const username = 'testuser_' + Date.now();
    const password = 'password123';
    let token;

    console.log('--- Starting Verification ---');

    // 1. Register
    try {
        const res = await request({
            hostname: 'localhost',
            port: 3001,
            path: '/api/register',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, { username, password });
        console.log('Register:', res.statusCode === 201 ? 'PASS' : 'FAIL', res.body);
    } catch (err) {
        console.error('Register Error:', err);
    }

    // 2. Login
    try {
        const res = await request({
            hostname: 'localhost',
            port: 3001,
            path: '/api/login',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, { username, password });
        console.log('Login:', res.statusCode === 200 ? 'PASS' : 'FAIL');
        if (res.statusCode === 200) {
            token = res.body.token;
        }
    } catch (err) {
        console.error('Login Error:', err);
    }

    // 3. Protected Route
    if (token) {
        try {
            const res = await request({
                hostname: 'localhost',
                port: 3001,
                path: '/api/protected',
                method: 'GET',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            console.log('Protected Route:', res.statusCode === 200 ? 'PASS' : 'FAIL', res.body);
        } catch (err) {
            console.error('Protected Route Error:', err);
        }
    } else {
        console.log('Skipping Protected Route test due to login failure.');
    }

    // 4. Invalid Login
    try {
        const res = await request({
            hostname: 'localhost',
            port: 3001,
            path: '/api/login',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, { username, password: 'wrongpassword' });
        console.log('Invalid Login:', res.statusCode === 401 ? 'PASS' : 'FAIL');
    } catch (err) {
        console.error('Invalid Login Error:', err);
    }
}

// 5. Crear liga
let idLiga;
try {
    const res = await request({
        hostname: 'localhost',
        port: 3001,
        path: '/api/ligas',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        }
    }, {
        nombre: 'Liga Test',
        clave: '1234',
        max_jugadores: 5
    });

    console.log('Crear liga:', res.statusCode === 201 ? 'PASS' : 'FAIL', res.body);
    idLiga = res.body.id_liga;
} catch (err) {
    console.error('Crear liga Error:', err);
}

// 6. Ver mercado
if (idLiga) {
    try {
        const res = await request({
            hostname: 'localhost',
            port: 3001,
            path: `/api/mercado/${idLiga}`,
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        console.log('Ver mercado:', res.statusCode === 200 ? 'PASS' : 'FAIL', res.body);
    } catch (err) {
        console.error('Mercado Error:', err);
    }
}



// Wait for server to start (manual delay for simplicity in this script context)
setTimeout(runTests, 2000);