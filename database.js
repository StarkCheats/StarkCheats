const Parse = require('parse/node');
require('dotenv').config();

// Inicializar Parse (Back4App)
Parse.initialize(
    process.env.BACK4APP_APP_ID,
    process.env.BACK4APP_JS_KEY,
    process.env.BACK4APP_MASTER_KEY // Opcional, pero necesario para algunas operaciones admin
);
Parse.serverURL = 'https://parseapi.back4app.com/';

// Esta función ahora solo exporta Parse o funciones de utilidad de Parse
// para ser un reemplazo compatible ("drop-in") visual con el router
async function getDB() {
    // Verificar que las credenciales existen
    if (!process.env.BACK4APP_APP_ID || !process.env.BACK4APP_JS_KEY) {
        console.error("⚠️ ADVERTENCIA: Las variables de entorno de Back4App no están configuradas.");
        console.error("Por favor, configura BACK4APP_APP_ID y BACK4APP_JS_KEY en tu archivo .env");
    }

    return {
        // En lugar de devolver una instancia de SQLite,
        // devolvemos un wrapper o simplemente Parse para que el server lo use
        Parse: Parse,
        
        // Exportamos utilidades para facilitar logs o migraciones
        isParse: true
    };
}

module.exports = { getDB, Parse };
