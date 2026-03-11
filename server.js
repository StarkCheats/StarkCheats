const express = require('express');
require('dotenv').config();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const { getDB, Parse } = require('./database');
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

        await getDB();
        
        // Generar PIN de 6 dígitos
        const pin = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Expira en 10 minutos
        const expiresAt = Date.now() + 10 * 60000;
        
        const VerificationCode = Parse.Object.extend("VerificationCode");
        const codeObj = new VerificationCode();
        codeObj.set("email", email);
        codeObj.set("code", pin);
        codeObj.set("expires_at", expiresAt);
        await codeObj.save();

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

        await getDB();
        
        // Buscar si el código existe y es válido
        const now = Date.now();
        const query = new Parse.Query("VerificationCode");
        query.equalTo("email", email);
        query.equalTo("code", code);
        query.greaterThan("expires_at", now);
        query.descending("createdAt");
        const record = await query.first();

        if (!record) {
            console.log(`[Auth Fail] User: ${email}, Code: ${code}, Now: ${now}`);
            return res.status(401).json({ error: 'Código inválido o expirado' });
        }

        // Ya fue usado, lo borramos
        const delQuery = new Parse.Query("VerificationCode");
        delQuery.equalTo("email", email);
        const codesToDelete = await delQuery.find();
        await Parse.Object.destroyAll(codesToDelete);

        // Verificar si el usuario existe, si no, lo creamos
        const userQuery = new Parse.Query(Parse.User);
        userQuery.equalTo("email", email);
        let parseUser = await userQuery.first({ useMasterKey: true });
        
        if (!parseUser) {
            parseUser = new Parse.User();
            parseUser.set("username", email);
            parseUser.set("email", email);
            parseUser.set("password", "default_" + Math.random().toString(36).slice(-8)); 
            parseUser.set("balance", 0.00);
            parseUser.set("role", "user");
            parseUser.set("two_factor_enabled", false);
            await parseUser.signUp();
        }
        
        let user = { 
            id: parseUser.id, 
            email: parseUser.get("email"), 
            balance: parseUser.get("balance") || 0.00,
            role: parseUser.get("role") || "user"
        };

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

        await getDB();
        
        // Verificar si el usuario existe, si no, lo creamos
        const userQuery = new Parse.Query(Parse.User);
        userQuery.equalTo("email", email);
        let parseUser = await userQuery.first({ useMasterKey: true });
        
        if (!parseUser) {
            parseUser = new Parse.User();
            parseUser.set("username", email);
            parseUser.set("email", email);
            parseUser.set("password", "default_" + Math.random().toString(36).slice(-8)); 
            parseUser.set("balance", 0.00);
            parseUser.set("role", "user");
            parseUser.set("two_factor_enabled", false);
            await parseUser.signUp();
        }

        let user = { 
            id: parseUser.id, 
            email: parseUser.get("email"), 
            balance: parseUser.get("balance") || 0.00,
            role: parseUser.get("role") || "user"
        };

        // --- LÓGICA DE 2FA PARA GOOGLE ---
        const pin = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = Date.now() + 10 * 60000; // Guardamos timestamp numérico para consistencia

        const VerificationCode = Parse.Object.extend("VerificationCode");
        const codeObj = new VerificationCode();
        codeObj.set("email", email);
        codeObj.set("code", pin);
        codeObj.set("expires_at", expiresAt);
        await codeObj.save();

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

        await getDB();
        
        // Verificar o crear usuario
        const userQuery = new Parse.Query(Parse.User);
        userQuery.equalTo("email", email);
        let parseUser = await userQuery.first({ useMasterKey: true });
        
        if (!parseUser) {
            parseUser = new Parse.User();
            parseUser.set("username", email);
            parseUser.set("email", email);
            parseUser.set("password", "default_" + Math.random().toString(36).slice(-8)); 
            parseUser.set("balance", 0.00);
            parseUser.set("role", "user");
            parseUser.set("two_factor_enabled", false);
            await parseUser.signUp();
        }

        let user = { 
            id: parseUser.id, 
            email: parseUser.get("email"), 
            balance: parseUser.get("balance") || 0.00,
            role: parseUser.get("role") || "user",
            two_factor_enabled: parseUser.get("two_factor_enabled") || false
        };

        // Check if 2FA is enabled
        if (user.two_factor_enabled) {
            // Generate PIN
            const pin = Math.floor(100000 + Math.random() * 900000).toString();
            const expiresAt = Date.now() + 10 * 60000;
            const VerificationCode = Parse.Object.extend("VerificationCode");
            const codeObj = new VerificationCode();
            codeObj.set("email", email);
            codeObj.set("code", pin);
            codeObj.set("expires_at", expiresAt);
            await codeObj.save();

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
        await getDB();
        const userQuery = new Parse.Query(Parse.User);
        const parseUser = await userQuery.get(req.user.id, { useMasterKey: true });
        
        if(!parseUser) return res.status(404).json({error: 'Usuario no encontrado'});
        
        res.json({
            id: parseUser.id,
            email: parseUser.get("email"),
            balance: parseUser.get("balance") || 0.00,
            two_factor_enabled: parseUser.get("two_factor_enabled") ? 1 : 0,
            has_password: 1
        });
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

        await getDB();
        
        const userQuery = new Parse.Query(Parse.User);
        const parseUser = await userQuery.get(req.user.id, { useMasterKey: true });
        
        // Actualizar balance
        parseUser.increment("balance", depositAmount);
        await parseUser.save(null, { useMasterKey: true });
        
        // Registrar transacción
        const Transaction = Parse.Object.extend("Transaction");
        const txObj = new Transaction();
        txObj.set("user", parseUser);
        txObj.set("amount", depositAmount);
        txObj.set("type", "deposit");
        txObj.set("status", "completed");
        await txObj.save();

        res.json({ message: 'Depósito exitoso', newBalance: parseUser.get("balance") });
    } catch (error) {
        res.status(500).json({ error: 'Error procesando depósito' });
    }
});

// 5. Comprar producto
app.post('/api/payments/purchase', authenticateToken, async (req, res) => {
    try {
        const { productId, price } = req.body;
        await getDB();
        
        const userQuery = new Parse.Query(Parse.User);
        const parseUser = await userQuery.get(req.user.id, { useMasterKey: true });
        
        const currentBalance = parseUser.get("balance") || 0;
        
        if(currentBalance < price) {
            return res.status(400).json({ error: 'Saldo insuficiente' });
        }

        // Descontar saldo
        parseUser.increment("balance", -price);
        await parseUser.save(null, { useMasterKey: true });
        
        // Registrar compra
        const Transaction = Parse.Object.extend("Transaction");
        const txObj = new Transaction();
        txObj.set("user", parseUser);
        txObj.set("amount", -price);
        txObj.set("type", "purchase");
        txObj.set("status", "completed");
        await txObj.save();

        res.json({ message: 'Compra exitosa', newBalance: parseUser.get("balance") });
    } catch (error) {
        res.status(500).json({ error: 'Error procesando la compra' });
    }
});

// 6. Iniciar pago con Crypto (Depósito o Compra directa)
app.post('/api/payments/crypto/start', authenticateToken, async (req, res) => {
    try {
        const { amount, type, productId } = req.body; // type: 'deposit' o 'purchase'
        await getDB();

        const userQuery = new Parse.Query(Parse.User);
        const parseUser = await userQuery.get(req.user.id, { useMasterKey: true });
        
        const Transaction = Parse.Object.extend("Transaction");
        const txObj = new Transaction();
        txObj.set("user", parseUser);
        txObj.set("amount", amount);
        txObj.set("type", type === 'deposit' ? 'deposit_pending' : 'purchase_pending');
        txObj.set("status", "pending");
        await txObj.save();

        res.json({
            transactionId: txObj.id,
            usdAmount: amount,
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
        await getDB();
        
        const txQuery = new Parse.Query("Transaction");
        txQuery.equalTo("objectId", txId);
        txQuery.equalTo("status", "pending");
        
        const tx = await txQuery.first();
        if (!tx) return res.status(404).json({ error: 'Transacción no encontrada o ya procesada' });

        const userObj = tx.get("user");
        await userObj.fetch({ useMasterKey: true });
        
        if (userObj.id !== req.user.id) {
            return res.status(403).json({ error: 'Operación no permitida' });
        }

        if (tx.get("type") === 'deposit_pending') {
            userObj.increment("balance", tx.get("amount"));
            await userObj.save(null, { useMasterKey: true });
            
            tx.set("status", "completed");
            tx.set("type", "deposit");
            await tx.save();
        } else if (tx.get("type") === 'purchase_pending') {
            tx.set("status", "completed");
            tx.set("type", "purchase");
            await tx.save();
        }

        res.json({ message: 'Pago confirmado en la Blockchain', newBalance: userObj.get("balance") });

    } catch (error) {
        res.status(500).json({ error: 'Error verificando pago' });
    }
});

// 8. Security - Request Change Code
app.post('/api/security/request-change', authenticateToken, async (req, res) => {
    try {
        const { type } = req.body; // 'password' or '2fa'
        const email = req.user.email;
        await getDB();
        
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = Date.now() + 10 * 60000; // Unix timestamp in ms
        
        const VerificationCode = Parse.Object.extend("VerificationCode");
        const codeObj = new VerificationCode();
        codeObj.set("email", email);
        codeObj.set("code", code);
        codeObj.set("expires_at", expiresAt);
        await codeObj.save();

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
        await getDB();

        const now = Date.now();
        const query = new Parse.Query("VerificationCode");
        query.equalTo("email", email);
        query.equalTo("code", code);
        query.greaterThan("expires_at", now);
        query.descending("createdAt");
        const record = await query.first();

        if (!record) {
            console.log(`[Security Fail] User: ${email}, Code: ${code}, Now: ${now}`);
            return res.status(401).json({ error: 'Invalid or expired code' });
        }

        const delQuery = new Parse.Query("VerificationCode");
        delQuery.equalTo("email", email);
        delQuery.equalTo("code", code);
        const codesToDelete = await delQuery.find();
        await Parse.Object.destroyAll(codesToDelete);

        if (type === '2fa') {
            const isEnabled = enabled === true || enabled === 1;
            const userQuery = new Parse.Query(Parse.User);
            const parseUser = await userQuery.get(req.user.id, { useMasterKey: true });
            parseUser.set("two_factor_enabled", isEnabled);
            await parseUser.save(null, { useMasterKey: true });
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
