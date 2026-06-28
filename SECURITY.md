# Política de seguridad

## Versiones soportadas

Se da soporte de seguridad a la **rama `main`** (última versión). VPN Manager está
pensado para **uso interno** (detrás de un proxy con HTTPS), no para exponerse a internet.

## Cómo reportar una vulnerabilidad

Si encuentras un problema de seguridad, **no abras un issue público**. Repórtalo de forma
privada al responsable del proyecto (por ejemplo, mediante un *Security Advisory* privado
de GitHub). Incluye:

- una descripción del problema y su impacto,
- pasos para reproducirlo,
- versión/commit afectado.

Intentaremos confirmar la recepción con prontitud y mantenerte al día de la corrección.

## Buenas prácticas de despliegue

- **Producción**: define `VPNM_ADMIN_PASSWORD_HASH` (genera con `python -m vpn_manager.hashpw`),
  `VPNM_SECRET_KEY` (aleatoria) y `VPNM_COOKIE_SECURE=true` tras HTTPS. Sin estos secretos
  el panel se niega a arrancar.
- **No expongas** el panel a internet; mantenlo en la red interna o tras VPN/proxy.
- **2FA**: activa la verificación en dos pasos para las cuentas administrativas.
- **Roles**: concede el mínimo privilegio (operador/solo lectura) a quien no necesite ser admin.
- **Instalación de servicios**: deja `VPNM_ALLOW_INSTALL=false` salvo cuando vayas a instalar;
  la instalación «llave en mano» exige **fijar un commit y verificar su SHA-256**.
- **Auditoría**: revisa la página *Actividad* periódicamente.

## Resumen de controles incluidos

Contraseñas PBKDF2-SHA256, sesión en cookie firmada (`HttpOnly`, `SameSite=Strict`,
`Secure` configurable, HSTS tras HTTPS), 2FA TOTP, control de acceso por roles aplicado
en el backend, *rate-limiting* anti–fuerza bruta, cabeceras de seguridad (CSP,
`X-Frame-Options`, `nosniff`…), validación estricta de entrada (anti-inyección/traversal),
auditoría persistida y contenedor sin privilegios. Más detalle en
[`docs/AUDITORIA-SEGURIDAD.md`](docs/AUDITORIA-SEGURIDAD.md).
