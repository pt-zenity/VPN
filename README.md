# VPN Manager

Panel web para **administrar un servidor VPN** (OpenVPN — y WireGuard próximamente)
desde una interfaz sencilla, en lugar de por línea de comandos. Pensado para que
**alguien sin conocimientos técnicos** pueda gestionar quién tiene acceso a la red:
dar de alta personas, descargar su configuración y retirarles el acceso.

## Características

- **Personas con acceso**: lista de certificados/clientes con su estado en lenguaje
  llano (*acceso activo*, *retirado*, *caducado*) y fecha de caducidad.
- **Alta de acceso**: crea un nuevo cliente y genera su fichero de configuración.
- **Descarga de configuración** (`.ovpn`) de cada acceso activo.
- **Retirar acceso**: revoca el certificado y regenera la CRL.
- **Conexiones en tiempo real**: quién está conectado, desde cuándo y su tráfico.
- **Estado del servicio** del servidor VPN.

## Seguridad

- **Autenticación obligatoria.** Login con contraseña (**PBKDF2-SHA256**, 600k
  iteraciones, comparación en tiempo constante) y sesión en **cookie firmada**
  (`HttpOnly`, `SameSite=Strict`, `Secure` configurable). Todo el panel y la API
  requieren sesión; solo `/login` y `/health` son públicos.
- **Seguro por defecto.** En producción sin `VPNM_ADMIN_PASSWORD_HASH`, la app
  **se niega a arrancar**. En sandbox usa la credencial de desarrollo `admin/admin`
  mostrando un aviso.
- **Anti–fuerza bruta**: bloqueo temporal por IP tras varios intentos fallidos.
- **Sandbox por defecto.** En desarrollo apunta a `./sandbox/`, **nunca** a un
  servidor VPN real. Apuntar a producción es una decisión explícita por
  configuración (`VPNM_SANDBOX=false` + rutas reales).
- **Validación estricta de nombres** (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`) para
  evitar inyección de comandos y *path traversal*.
- El certificado del **servidor** está protegido (no se puede crear ni revocar).
- Las operaciones reales delegan en `easy-rsa` mediante `subprocess` **sin shell**.
- El material criptográfico real está excluido del repositorio (ver `.gitignore`).

## Puesta en marcha

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m vpn_manager           # http://127.0.0.1:8200
```

En desarrollo (sandbox) entra con **admin / admin**. Para producción, copia
`.env.example` a `.env`, genera tu contraseña con `python -m vpn_manager.hashpw`
y fija `VPNM_SECRET_KEY`.

## Tests

```bash
pytest -q        # 21 pruebas (parsers, API, alta/revocación, validación)
ruff check .
```

## API

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET`  | `/` | Panel web (requiere sesión) |
| `GET`/`POST` | `/login` | Página y envío de login |
| `POST` | `/logout` | Cierra la sesión |
| `GET`  | `/health` | Estado del servicio y modo sandbox (público) |
| `GET`  | `/api/openvpn/status` | Estado del servidor OpenVPN |
| `GET`  | `/api/openvpn/clients` | Lista de clientes/certificados |
| `GET`  | `/api/openvpn/connections` | Conexiones activas |
| `POST` | `/api/openvpn/clients` | Alta de cliente `{"name": "..."}` |
| `POST` | `/api/openvpn/clients/{name}/revoke` | Retira el acceso |
| `GET`  | `/api/openvpn/clients/{name}/config` | Descarga el `.ovpn` |

## Configuración

Variables de entorno con prefijo `VPNM_` (ver `vpn_manager/config.py`):
`VPNM_SANDBOX`, `VPNM_OPENVPN_PKI_INDEX`, `VPNM_OPENVPN_STATUS_FILE`,
`VPNM_OPENVPN_SERVICE`, etc.

## Hoja de ruta

- [x] **Fase 1** — OpenVPN, solo lectura (estado, clientes, conexiones).
- [x] **Fase 2** — OpenVPN, escritura (alta, revocación, descarga de config).
- [ ] **Fase 3** — WireGuard (peers, claves, `wg show`).
- [ ] **Fase 4** — Historial y auditoría.
- [ ] **Fase 5** — Despliegue interno (auth, HTTPS, hardening).

Detalle completo en [`docs/ESPECIFICACION.md`](docs/ESPECIFICACION.md).

## Licencia

MIT — ver [`LICENSE`](LICENSE).
