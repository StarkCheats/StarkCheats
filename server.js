const express = require('express');
require('dotenv').config();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const { getDB } = require('./database');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_starkcheats';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'http://localhost:3000/api/auth/discord/callback';
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

app.use(cors());
app.use(express.json());
// Servir archivos estáticos del frontend
app.use(express.static(path.join(__dirname, 'public')));

// ==== Helper Functions ====
const hashPassword = (password) => {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16).toString('hex');
        crypto.pbkdf2(password, salt, 1000, 64, 'sha512', (err, derivedKey) => {
            if (err) reject(err);
            resolve(salt + ":" + derivedKey.toString('hex'));
        });
    });
};

const verifyPassword = (password, storedHash) => {
    return new Promise((resolve) => {
        const [salt, hash] = storedHash.split(':');
        crypto.pbkdf2(password, salt, 1000, 64, 'sha512', (err, derivedKey) => {
            if (err) resolve(false);
            resolve(derivedKey.toString('hex') === hash);
        });
    });
};

// ==== Configuración de Correo (Nodemailer con Ethereal para pruebas locales) ====
let transporter;
async function setupMailer() {
    if (process.env.SMTP_USER && process.env.SMTP_PASS) {
        // Configuración para correo REAL (ej: Gmail, Resend, etc.)
        transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT),
            secure: false, // Debe ser false para el puerto 587 (STARTTLS)
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS,
            },
            tls: {
                ciphers: 'SSLv3',
                rejectUnauthorized: false
            },
            requireTLS: true
        });
        console.log(`[Email] Configurado servidor de correo REAL (${process.env.SMTP_USER})`);
    } else {
        // Ethereal es un servicio gratuito para atrapar correos de prueba
        let testAccount = await nodemailer.createTestAccount();
        transporter = nodemailer.createTransport({
            host: "smtp.ethereal.email",
            port: 587,
            secure: false, 
            auth: {
                user: testAccount.user,
                pass: testAccount.pass,
            },
        });
        console.log(`[Email] MODO PRUEBA: Correo configurado en Ethereal`);
    }
}
setupMailer().then(() => {
    if (transporter) {
        transporter.verify(function(error, success) {
            if (error) {
                console.log("[Email] Error de conexión SMTP:", error.message);
            } else {
                console.log("[Email] Servidor listo para enviar mensajes");
            }
        });
    }
});

// ==== Middleware de Autenticación ====
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Acceso denegado' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido o expirado' });
        req.user = user;
        next();
    });
};

// ==== Rutas de API ====

// 1. Solicitar PIN por correo
app.post('/api/auth/send-code', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !email.includes('@')) return res.status(400).json({ error: 'Email inválido' });

        const db = await getDB();
        
        // Generar PIN de 6 dígitos
        const pin = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Expira en 10 minutos
        const expiresAt = Date.now() + 10 * 60000;
        
        await db.run(
            'INSERT INTO VerificationCodes (email, code, expires_at) VALUES (?, ?, ?)',
            [email, pin, expiresAt]
        );

        // Plantilla de Correo Profesional
        const emailHtml = `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                .container { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; background-color: #0f172a; color: #ffffff; border-radius: 12px; overflow: hidden; border: 1px solid #1e293b; }
                .header { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); padding: 40px 20px; text-align: center; border-bottom: 2px solid #3b82f6; }
                .logo { font-size: 28px; font-weight: bold; color: #3b82f6; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 10px; }
                .content { padding: 40px 30px; line-height: 1.6; }
                .greeting { font-size: 20px; font-weight: 600; margin-bottom: 20px; color: #f8fafc; }
                .pin-container { background-color: #1e293b; border: 1px dashed #3b82f6; border-radius: 8px; padding: 20px; text-align: center; margin: 30px 0; }
                .pin-code { font-size: 36px; font-weight: 800; letter-spacing: 12px; color: #3b82f6; margin: 0; }
                .footer { background-color: #020617; padding: 20px; text-align: center; font-size: 12px; color: #64748b; }
                .warning { font-size: 13px; color: #94a3b8; margin-top: 20px; }
                .btn { display: inline-block; padding: 12px 24px; background-color: #3b82f6; color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 600; margin-top: 10px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">STARK CHEATS</div>
                    <p style="margin: 0; color: #94a3b8; font-size: 14px;">Premium Gaming Solutions</p>
                </div>
                <div class="content">
                    <div class="greeting">¡Hola!</div>
                    <p>Has solicitado un código de acceso para entrar a tu cuenta en <strong>Stark Cheats</strong>. Utiliza el siguiente código PIN para verificar tu identidad:</p>
                    
                    <div class="pin-container">
                        <p style="margin-top: 0; font-size: 12px; color: #3b82f6; text-transform: uppercase;">Tu código de verificación</p>
                        <h1 class="pin-code">${pin}</h1>
                    </div>

                    <p class="warning">Este código es válido por <strong>10 minutos</strong>. Si no has solicitado este código, puedes ignorar este correo de forma segura.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2026 Stark Cheats. Todos los derechos reservados.</p>
                    <p>Este es un correo automático, por favor no respondas a este mensaje.</p>
                </div>
            </div>
        </body>
        </html>
        `;

        // Enviar Correo
        let info = await transporter.sendMail({
            from: process.env.EMAIL_FROM || '"StarkCheats" <noreply@starkcheats.com>',
            to: email,
            subject: `🔐 ${pin} es tu código de acceso - Stark Cheats`,
            html: emailHtml,
        });

        console.log("PIN Generado:", pin);
        console.log("URL de vista previa del correo:", nodemailer.getTestMessageUrl(info));

        res.json({ message: 'Código enviado', previewUrl: nodemailer.getTestMessageUrl(info) });
    } catch (error) {
        console.error("DEBUG EMAIL ERROR:", error);
        res.status(500).json({ error: 'Error del servidor (Email): ' + (error.message || 'Error desconocido') });
    }
});

// 2. Verificar PIN (Login / Registro automático)
app.post('/api/auth/verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) return res.status(400).json({ error: 'Email y código requeridos' });

        const db = await getDB();
        
        // Buscar si el código existe y es válido (Comparación numérica)
        const now = Date.now();
        const record = await db.get(
            'SELECT * FROM VerificationCodes WHERE email = ? AND code = ? AND expires_at > ? ORDER BY id DESC LIMIT 1',
            [email, code, now]
        );

        if (!record) {
            console.log(`[Auth Fail] User: ${email}, Code: ${code}, Now: ${now}`);
            return res.status(401).json({ error: 'Código inválido o expirado' });
        }

        // Ya fue usado, lo borramos (opcional, pero buena práctica)
        await db.run('DELETE FROM VerificationCodes WHERE email = ?', [email]);

        // Verificar si el usuario existe, si no, lo creamos
        let user = await db.get('SELECT * FROM Users WHERE email = ?', [email]);
        if (!user) {
            const result = await db.run('INSERT INTO Users (email) VALUES (?)', [email]);
            user = { id: result.lastID, email, balance: 0.00, role: 'user' };
        }

        // Generar Token JWT
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        // --- ENVIAR CORREO DE ÉXITO Y BIENVENIDA ---
        try {
            const successEmailHtml = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    .container { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; background-color: #0f172a; color: #ffffff; border-radius: 12px; overflow: hidden; border: 1px solid #1e293b; }
                    .header { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); padding: 40px 20px; text-align: center; border-bottom: 2px solid #8b5cf6; }
                    .logo { font-size: 28px; font-weight: bold; color: #a78bfa; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 10px; }
                    .content { padding: 40px 30px; line-height: 1.6; text-align: center; }
                    .greeting { font-size: 24px; font-weight: 700; margin-bottom: 20px; color: #f8fafc; }
                    .success-icon { font-size: 50px; color: #10b981; margin-bottom: 20px; }
                    .discord-btn { display: inline-block; padding: 16px 32px; background-color: #5865F2; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 700; margin-top: 25px; transition: background 0.3s; }
                    .footer { background-color: #020617; padding: 20px; text-align: center; font-size: 12px; color: #64748b; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">STARK CHEATS</div>
                    </div>
                    <div class="content">
                        <div class="success-icon">✅</div>
                        <div class="greeting">¡Acceso Correcto!</div>
                        <p>Te has identificado con éxito en <strong>Stark Cheats</strong>.</p>
                        <p>Estamos encantados de tenerte de vuelta. Para recibir soporte instantáneo, ver actualizaciones y compartir con la comunidad, únete a nuestro Discord oficial:</p>
                        
                        <a href="https://discord.gg/fqghy2as" class="discord-btn">UNIRSE AL DISCORD</a>

                        <p style="margin-top: 30px; font-size: 14px; color: #94a3b8;">Si no has sido tú quien ha iniciado sesión, por favor contacta con soporte de inmediato.</p>
                    </div>
                    <div class="footer">
                        <p>&copy; 2026 Stark Cheats. Tu seguridad es nuestra prioridad.</p>
                    </div>
                </div>
            </body>
            </html>
            `;

            await transporter.sendMail({
                from: process.env.EMAIL_FROM || '"StarkCheats" <noreply@starkcheats.com>',
                to: email,
                subject: '🔥 ¡Sesión Iniciada con Éxito! - Stark Cheats',
                html: successEmailHtml,
            });
            console.log("Correo de éxito enviado a:", email);
        } catch (mailError) {
            console.error("Error al enviar correo de éxito:", mailError);
            // No bloqueamos el login si falla el correo de éxito
        }

        res.json({ token, user: { id: user.id, email: user.email, balance: user.balance } });
    } catch (error) {
        console.error("DEBUG VERIFY ERROR:", error);
        res.status(500).json({ error: 'Error del servidor (Verify): ' + (error.message || 'Error desconocido') });
    }
});

// 2.1 Verificar Token de Google
app.post('/api/auth/google', async (req, res) => {
    try {
        const { idToken } = req.body;
        if (!idToken) return res.status(400).json({ error: 'Token de Google requerido' });

        const ticket = await client.verifyIdToken({
            idToken,
            audience: GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const email = payload['email'];

        if (!email) return res.status(400).json({ error: 'No se pudo obtener el email de Google' });

        const db = await getDB();
        
        // Verificar si el usuario existe, si no, lo creamos
        let user = await db.get('SELECT * FROM Users WHERE email = ?', [email]);
        if (!user) {
            const result = await db.run('INSERT INTO Users (email) VALUES (?)', [email]);
            user = { id: result.lastID, email, balance: 0.00, role: 'user' };
        }

        // --- LÓGICA DE 2FA PARA GOOGLE ---
        const pin = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60000).toISOString();

        await db.run(
            'INSERT INTO VerificationCodes (email, code, expires_at) VALUES (?, ?, ?)',
            [email, pin, expiresAt]
        );

        // Plantilla de Correo (Notificación + PIN)
        const emailHtml = `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                .container { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; background-color: #0f172a; color: #ffffff; border-radius: 12px; overflow: hidden; border: 1px solid #1e293b; }
                .header { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); padding: 40px 20px; text-align: center; border-bottom: 2px solid #3b82f6; }
                .logo { font-size: 28px; font-weight: bold; color: #3b82f6; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 10px; }
                .content { padding: 40px 30px; line-height: 1.6; }
                .greeting { font-size: 20px; font-weight: 600; margin-bottom: 20px; color: #f8fafc; }
                .pin-container { background-color: #1e293b; border: 1px dashed #3b82f6; border-radius: 8px; padding: 20px; text-align: center; margin: 30px 0; }
                .pin-code { font-size: 36px; font-weight: 800; letter-spacing: 12px; color: #3b82f6; margin: 0; }
                .footer { background-color: #020617; padding: 20px; text-align: center; font-size: 12px; color: #64748b; }
                .warning { font-size: 13px; color: #94a3b8; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">STARK CHEATS</div>
                    <p style="margin: 0; color: #94a3b8; font-size: 14px;">Premium Gaming Solutions</p>
                </div>
                <div class="content">
                    <div class="greeting">¡Inicio de Sesión Detectado!</div>
                    <p>Has iniciado sesión correctamente utilizando tu cuenta de Google (<strong>${email}</strong>) en <strong>Stark Cheats</strong>.</p>
                    <p>Para completar el acceso y proteger tu cuenta, utiliza el siguiente código de verificación:</p>
                    
                    <div class="pin-container">
                        <p style="margin-top: 0; font-size: 12px; color: #3b82f6; text-transform: uppercase;">Tu código de seguridad</p>
                        <h1 class="pin-code">${pin}</h1>
                    </div>

                    <p class="warning">Este código es obligatorio para cada inicio de sesión con Google para garantizar la máxima seguridad.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2026 Stark Cheats. Todos los derechos reservados.</p>
                </div>
            </div>
        </body>
        </html>
        `;

        await transporter.sendMail({
            from: process.env.EMAIL_FROM || '"StarkCheats" <noreply@starkcheats.com>',
            to: email,
            subject: `🛡️ Seguridad StarkCheats: Código de Acceso ${pin}`,
            html: emailHtml,
        });

        res.json({ 
            requiresTwoFactor: true, 
            email: email,
            message: 'Código de verificación enviado al correo' 
        });
    } catch (error) {
        console.error("Error validando Google Token:", error);
        res.status(401).json({ error: 'Token de Google inválido o error en 2FA' });
    }
});

// 2.2 Autenticación con Discord
app.get('/api/auth/discord', (req, res) => {
    if (!DISCORD_CLIENT_ID) {
        return res.status(500).send('Discord Client ID no configurado en el servidor.');
    }
    const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&response_type=code&scope=identify%20email`;
    res.redirect(discordAuthUrl);
});

app.get('/api/auth/discord/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send('Código de autorización no proporcionado.');

    try {
        // Intercambiar código por token
        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                code,
                grant_type: 'authorization_code',
                redirect_uri: DISCORD_REDIRECT_URI,
                scope: 'identify email',
            }),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });

        const tokenData = await tokenResponse.json();
        if (tokenData.error) throw new Error(tokenData.error_description || tokenData.error);

        // Obtener info del usuario
        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` },
        });
        const userData = await userResponse.json();
        const email = userData.email;

        if (!email) return res.status(400).send('No se pudo obtener el email de Discord.');

        const db = await getDB();
        
        // Verificar o crear usuario
        let user = await db.get('SELECT * FROM Users WHERE email = ?', [email]);
        if (!user) {
            const result = await db.run('INSERT INTO Users (email) VALUES (?)', [email]);
            user = { id: result.lastID, email, balance: 0.00, role: 'user' };
        }

        // Check if 2FA is enabled
        if (user.two_factor_enabled) {
            // Generate PIN
            const pin = Math.floor(100000 + Math.random() * 900000).toString();
            const expiresAt = Date.now() + 10 * 60000;
            await db.run('INSERT INTO VerificationCodes (email, code, expires_at) VALUES (?, ?, ?)', [email, pin, expiresAt]);

            // Professional 2FA Email
            const emailHtml = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    .container { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; background-color: #0f172a; color: #ffffff; border-radius: 16px; overflow: hidden; border: 1px solid #1e293b; }
                    .header { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); padding: 40px 20px; text-align: center; border-bottom: 2px solid #8b5cf6; }
                    .logo { font-size: 28px; font-weight: 800; color: #ffffff; text-transform: uppercase; letter-spacing: 3px; }
                    .logo span { color: #8b5cf6; }
                    .content { padding: 40px 30px; line-height: 1.6; }
                    .greeting { font-size: 20px; font-weight: 700; margin-bottom: 20px; color: #f8fafc; }
                    .pin-container { background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; text-align: center; margin: 32px 0; }
                    .pin-code { font-size: 42px; font-weight: 800; letter-spacing: 14px; color: #a78bfa; margin: 0; }
                    .footer { background-color: #020617; padding: 24px; text-align: center; font-size: 12px; color: #64748b; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">STARK<span>CHEATS</span></div>
                        <p style="margin: 10px 0 0; color: #94a3b8; font-size: 14px; font-weight: 500;">Securing Your Experience</p>
                    </div>
                    <div class="content">
                        <div class="greeting">Security Verification</div>
                        <p>A login attempt was made using your <strong>Discord</strong> account. Since you have 2FA enabled, please use the code below to complete your access:</p>
                        
                        <div class="pin-container">
                            <h1 class="pin-code">${pin}</h1>
                        </div>

                        <p style="color: #94a3b8; font-size: 13px;">This code expires in 10 minutes. If you did not attempt this login, please contact support and change your security settings immediately.</p>
                    </div>
                    <div class="footer">
                        <p>&copy; 2026 Stark Cheats. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>`;

            await transporter.sendMail({
                from: process.env.EMAIL_FROM || '"StarkCheats Security" <security@starkcheats.com>',
                to: email,
                subject: `🛡️ Security Code: ${pin}`,
                html: emailHtml
            });

            // Redirect to 2FA verification page on frontend
            return res.redirect(`/?requires2fa=true&email=${encodeURIComponent(email)}`);
        }

        // Generar Token JWT
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        // Redirigir al frontend con el token (en una aplicación real se usaría una cookie o se pasaría por URL para que el JS lo guarde)
        // Aquí lo pasaremos por URL para simplificar y que el frontend lo capture
        res.redirect(`/?token=${token}`);

    } catch (error) {
        console.error("Error en Discord OAuth:", error);
        res.status(500).send('Error en la autenticación con Discord: ' + error.message);
    }
});

// 3. Obtener info del usuario actual
app.get('/api/user/me', authenticateToken, async (req, res) => {
    try {
        const db = await getDB();
        const user = await db.get('SELECT id, email, balance, two_factor_enabled, (password IS NOT NULL) as has_password FROM Users WHERE id = ?', [req.user.id]);
        if(!user) return res.status(404).json({error: 'Usuario no encontrado'});
        
        res.json(user);
    } catch (error) {
        console.error("DEBUG ME ERROR:", error);
        res.status(500).json({ error: 'Error del servidor: ' + (error.message || 'Error desconocido') });
    }
});

// 4. Depositar saldo (Simulación de pago)
app.post('/api/payments/deposit', authenticateToken, async (req, res) => {
    try {
        const { amount, method } = req.body;
        const depositAmount = parseFloat(amount);
        
        if (isNaN(depositAmount) || depositAmount < 5) {
            return res.status(400).json({ error: 'Monto inválido. Mínimo $5.' });
        }

        const db = await getDB();
        
        // Actualizar balance
        await db.run('UPDATE Users SET balance = balance + ? WHERE id = ?', [depositAmount, req.user.id]);
        
        // Registrar transacción
        await db.run(
            'INSERT INTO Transactions (user_id, amount, type, status) VALUES (?, ?, ?, ?)',
            [req.user.id, depositAmount, 'deposit', 'completed']
        );

        const updatedUser = await db.get('SELECT balance FROM Users WHERE id = ?', [req.user.id]);

        res.json({ message: 'Depósito exitoso', newBalance: updatedUser.balance });
    } catch (error) {
        res.status(500).json({ error: 'Error procesando depósito' });
    }
});

// 5. Comprar producto
app.post('/api/payments/purchase', authenticateToken, async (req, res) => {
    try {
        const { productId, price } = req.body;
        const db = await getDB();
        
        const user = await db.get('SELECT balance FROM Users WHERE id = ?', [req.user.id]);
        
        if(user.balance < price) {
            return res.status(400).json({ error: 'Saldo insuficiente' });
        }

        // Descontar saldo
        await db.run('UPDATE Users SET balance = balance - ? WHERE id = ?', [price, req.user.id]);
        
        // Registrar compra
        await db.run(
            'INSERT INTO Transactions (user_id, amount, type, status) VALUES (?, ?, ?, ?)',
            [req.user.id, -price, 'purchase', 'completed']
        );

        const updatedUser = await db.get('SELECT balance FROM Users WHERE id = ?', [req.user.id]);
        
        res.json({ message: 'Compra exitosa', newBalance: updatedUser.balance });
    } catch (error) {
        res.status(500).json({ error: 'Error procesando la compra' });
    }
});

// 6. Iniciar pago con Crypto (Depósito o Compra directa)
app.post('/api/payments/crypto/start', authenticateToken, async (req, res) => {
    try {
        const { amount, type, productId } = req.body; // type: 'deposit' o 'purchase'
        const db = await getDB();

        // En un entorno real, la pasarela generaría la dirección y devolvería la conversión.
        // Aquí le damos esta info al frontend para que la base de datos se encargue de saber
        // en qué divisa está esperando el pago al aprobarse.
        
        // Registrar transacción pendiente
        const result = await db.run(
            'INSERT INTO Transactions (user_id, amount, type, status) VALUES (?, ?, ?, ?)',
            [req.user.id, amount, type === 'deposit' ? 'deposit_pending' : 'purchase_pending', 'pending']
        );

        res.json({
            transactionId: result.lastID,
            usdAmount: amount, // El frontend manejará las conversiones y direcciones
            message: 'Esperando selección y pago en la red'
        });

    } catch (error) {
        res.status(500).json({ error: 'Error iniciando pago crypto' });
    }
});

// 7. Simular confirmación de blockchain (para propósitos de demostración local)
app.post('/api/payments/crypto/verify/:id', authenticateToken, async (req, res) => {
    try {
        const txId = req.params.id;
        const db = await getDB();
        
        const tx = await db.get('SELECT * FROM Transactions WHERE id = ? AND user_id = ? AND status = "pending"', [txId, req.user.id]);
        if (!tx) return res.status(404).json({ error: 'Transacción no encontrada o ya procesada' });

        // Simular que, si han pasado X segundos o si el usuario le da "Verificar", la red lo aprueba
        // En la vida real, ESTE ENDPOINT ES REEMPLAZADO POR UN WEBHOOK que llama la pasarela (ej. Stripe, Coinbase Commerce).

        if (tx.type === 'deposit_pending') {
            await db.run('UPDATE Users SET balance = balance + ? WHERE id = ?', [tx.amount, req.user.id]);
            await db.run('UPDATE Transactions SET status = "completed", type = "deposit" WHERE id = ?', [txId]);
        } else if (tx.type === 'purchase_pending') {
            // Si era compra directa y la pagó
            await db.run('UPDATE Transactions SET status = "completed", type = "purchase" WHERE id = ?', [txId]);
            // (La entrega del producto se haría aquí)
        }

        const updatedUser = await db.get('SELECT balance FROM Users WHERE id = ?', [req.user.id]);
        
        res.json({ message: 'Pago confirmado en la Blockchain', newBalance: updatedUser.balance });

    } catch (error) {
        res.status(500).json({ error: 'Error verificando pago' });
    }
});

// 8. Security - Request Change Code
app.post('/api/security/request-change', authenticateToken, async (req, res) => {
    try {
        const { type } = req.body; // 'password' or '2fa'
        const email = req.user.email;
        const db = await getDB();
        
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = Date.now() + 10 * 60000; // Unix timestamp in ms
        
        await db.run(
            'INSERT INTO VerificationCodes (email, code, expires_at) VALUES (?, ?, ?)',
            [email, code, expiresAt]
        );

        const emailHtml = `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                .container { font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background-color: #0f172a; color: #ffffff; border-radius: 16px; overflow: hidden; border: 1px solid #1e293b; }
                .header { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); padding: 40px 20px; text-align: center; border-bottom: 2px solid #8b5cf6; }
                .logo { font-size: 28px; font-weight: 800; color: #ffffff; text-transform: uppercase; letter-spacing: 2px; }
                .logo span { color: #8b5cf6; }
                .content { padding: 40px 30px; line-height: 1.6; }
                .greeting { font-size: 20px; font-weight: 700; margin-bottom: 20px; color: #f8fafc; }
                .pin-container { background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; text-align: center; margin: 32px 0; }
                .pin-code { font-size: 42px; font-weight: 800; letter-spacing: 14px; color: #a78bfa; margin: 0; }
                .footer { background-color: #020617; padding: 24px; text-align: center; font-size: 12px; color: #64748b; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">STARK<span>CHEATS</span></div>
                    <p style="margin: 10px 0 0; color: #94a3b8; font-size: 14px;">Identity Verification</p>
                </div>
                <div class="content">
                    <div class="greeting">Security Request Received</div>
                    <p>You have requested a <strong>Security Settings Update</strong> on your Stark Cheats account.</p>
                    <p>Please enter the following verification code in the settings panel:</p>
                    
                    <div class="pin-container">
                        <h1 class="pin-code">${code}</h1>
                    </div>

                    <p style="font-size: 13px; color: #94a3b8;">This code is valid for 10 minutes. If you did not make this request, please change your credentials immediately and secure your account.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2026 Stark Cheats. Professional Security Systems.</p>
                </div>
            </div>
        </body>
        </html>`;

        await transporter.sendMail({
            from: process.env.EMAIL_FROM || '"StarkCheats Security" <security@starkcheats.com>',
            to: email,
            subject: `🔒 Action Required: Verification Code ${code}`,
            html: emailHtml
        });

        res.json({ message: 'Verification code sent to email' });
    } catch (error) {
        console.error("Error sending security code:", error);
        res.status(500).json({ error: 'Error sending security code' });
    }
});

// 9. Security - Confirm Change
app.post('/api/security/confirm-change', authenticateToken, async (req, res) => {
    try {
        const { type, code, password, enabled } = req.body;
        const email = req.user.email;
        const db = await getDB();

        // Check code - Comparison with numeric timestamp
        const now = Date.now();
        const record = await db.get(
            "SELECT * FROM VerificationCodes WHERE email = ? AND code = ? AND expires_at > ? ORDER BY id DESC LIMIT 1",
            [email, code, now]
        );

        if (!record) {
            console.log(`[Security Fail] User: ${email}, Code: ${code}, Now: ${now}`);
            return res.status(401).json({ error: 'Invalid or expired code' });
        }

        // Clean up code after verification
        await db.run('DELETE FROM VerificationCodes WHERE email = ? AND code = ?', [email, code]);

        if (type === '2fa') {
            const isEnabled = enabled === true || enabled === 1;
            await db.run('UPDATE Users SET two_factor_enabled = ? WHERE id = ?', [isEnabled ? 1 : 0, req.user.id]);
            console.log(`[Security] 2FA ${isEnabled ? 'enabled' : 'disabled'} for user ${req.user.id}`);
        } else {
            return res.status(400).json({ error: 'Invalid update type' });
        }

        res.json({ message: 'Security settings updated successfully' });
    } catch (error) {
        console.error("DEBUG SECURITY ERROR:", error);
        res.status(500).json({ error: 'Error del servidor al actualizar seguridad: ' + (error.message || 'Error desconocido') });
    }
});

// ==== Iniciar Servidor ====
app.listen(PORT, async () => {
    // Inicializar BD
    await getDB();
    console.log(`Servidor StarkCheats corriendo en http://localhost:${PORT}`);
});
