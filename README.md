# Listado

App de asistencia escolar (profes, directores y administrador), publicada como Worker de Cloudflare.

- `public/index.html`: la app.
- `src/`: el servidor (`/api/*`), con base de datos D1 (tablas `alumnos` y `asistencias`).
- `wrangler.jsonc`: configuración. La base D1 se crea sola en el primer deploy.

## Secretos a cargar en Cloudflare (Worker > Settings > Variables and Secrets, tipo *Secret*)

- `ANTHROPIC_API_KEY`: clave de la IA que lee las fotos.
- `ADMIN_PASSWORD`: contraseña del administrador (usuario `adm`).
