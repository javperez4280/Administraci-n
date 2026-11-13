// Punto de entrada del Worker: /api/* lo atiende el servidor; lo demás son los archivos de /public.
import { manejarApi } from './api.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      return manejarApi(request, env, url.pathname.slice(5).split('/')[0]);
    }
    return env.ASSETS.fetch(request);
  },
};
