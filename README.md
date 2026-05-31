# Prode Mundial 2026 🏆🐓

App de prode para el Mundial 2026. Usuarios con registro, login y recuperación de contraseña por email.

## Variables de entorno (Railway)

| Variable | Descripción | Ejemplo |
|---|---|---|
| `DB_PATH` | Ruta al archivo SQLite (apuntar al volumen) | `/data/prode.db` |
| `JWT_SECRET` | Clave secreta para firmar tokens JWT | `una_clave_larga_random` |
| `SMTP_HOST` | Servidor SMTP | `smtp.gmail.com` |
| `SMTP_PORT` | Puerto SMTP | `587` |
| `SMTP_USER` | Email desde donde se envían los mails | `tuapp@gmail.com` |
| `SMTP_PASS` | Contraseña o App Password del email | `xxxx xxxx xxxx xxxx` |
| `PORT` | Puerto (Railway lo setea solo) | `3000` |

## Deploy en Railway

1. Subir esta carpeta a un repo de GitHub
2. En Railway: New Project → Deploy from GitHub
3. Agregar un **Volume** con mount path `/data`
4. Agregar las variables de entorno arriba
5. Listo 🚀

## Gmail como SMTP

Si usás Gmail, necesitás un **App Password** (no tu contraseña normal):
1. Ir a myaccount.google.com → Seguridad → Verificación en 2 pasos (activar)
2. Buscar "Contraseñas de aplicaciones"
3. Generar una para "Correo / Otro"
4. Usar esa como `SMTP_PASS`

## Sistema de puntos

- ⚽ Resultado pleno (1-0 vs 1-0): **4 pts**
- ✅ Resultado simple (ganador correcto): **2 pts**
- 📊 Posición exacta en grupo: **2 pts**
- 🏆 Grupo completo correcto: **+3 bonus**
- 🥇 Premio acertado: **3 pts**
- 🎯 Penales pleno: **+4 pts extra**
- 🎯 Penales simple (ganador correcto): **+2 pts extra**
