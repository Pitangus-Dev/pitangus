[English](SECURITY.md) · Español

# Política de seguridad

Pitangus lee el código de tus repositorios y guarda credenciales, así que tomamos los reportes en serio. Esta página dice cómo reportar una vulnerabilidad, qué versiones tienen soporte y qué esperar. Cómo protege el producto tus datos está en [docs/es/seguridad.md](../docs/es/seguridad.md); cómo se construyen, firman y verifican las versiones, en [docs/es/cadena-de-suministro.md](../docs/es/cadena-de-suministro.md).

## Reportar una vulnerabilidad

**No abras un issue, una pull request ni una discusión públicos.** Repórtala en privado con el reporte privado de vulnerabilidades de GitHub: [abre un borrador de aviso de seguridad](https://github.com/Pitangus-Dev/pitangus/security/advisories/new) (pestaña **Security → Report a vulnerability** de este repositorio). Solo lo ven los mantenedores y las personas que añadas.

Incluye, si puedes:

- versión (`/api/health` o la etiqueta del panel) y cómo lo despliegas;
- la parte afectada (archivo, ruta o componente) y desde qué punto parte quien ataca (sin cuenta, miembro, administrador);
- pasos para reproducirlo, idealmente una prueba de concepto, y el impacto que ves;
- si ya es público o está siendo explotado.

No incluyas secretos reales, tuyos ni de terceros, y prueba solo contra una instancia que sea tuya: no leas, cambies ni borres datos de otras personas y no hagas pruebas de denegación de servicio contra servidores ajenos.

## Qué esperar

Pitangus lo mantiene un equipo pequeño, así que esto son objetivos, no garantías:

- **Acuse de recibo** en 5 días hábiles.
- **Primera valoración** (si lo podemos reproducir y qué gravedad le vemos) en 10 días hábiles. Si no coincidimos en que es una vulnerabilidad, te diremos por qué.
- **Corrección:** para un problema alto o crítico confirmado, una versión de parche en cuanto esté lista y probada, con el objetivo de 30 días desde el reporte; las gravedades menores van en la siguiente versión ordinaria. Si va a tardar más, te contaremos por qué y te mantendremos al tanto.
- Los fallos que expongan credenciales o permitan ejecutar código en un servidor van primero.

## Divulgación coordinada

Mantén los detalles en privado hasta que haya una versión corregida. Cuando la haya, publicamos un aviso de seguridad de GitHub con las versiones afectadas, la corrección y cómo actualizar, y pedimos un CVE a través de GitHub cuando el problema lo justifique. Te citamos en el aviso salvo que prefieras no aparecer. Queremos publicar dentro de los 90 días siguientes al reporte; si la corrección necesita más tiempo, acordaremos una fecha contigo en lugar de dejarlo caer. La corrección queda en el [registro de cambios](../CHANGELOG.md).

## Versiones con soporte

Pitangus está en beta (0.x). Las correcciones de seguridad van en **la última línea de versión menor (ahora 0.15.x)**, como versión de parche (por ejemplo 0.15.1), y en la rama `main`. Las líneas anteriores no reciben parches: [actualiza](../docs/es/actualizar.md) a la última. Las versiones están en la [página de Releases](https://github.com/Pitangus-Dev/pitangus/releases).

## Alcance

Entra en el alcance cualquier fallo del código de este repositorio o de los artefactos que publica: autenticación, sesiones, almacén de secretos, API, panel, ejecución de motores, las imágenes de `ghcr.io/pitangus-dev` y el workflow de release que las construye y firma.

Quedan fuera:

- **Muestras vulnerables a propósito:** el código de `fixtures/` y `tests/fixtures/` (los ejemplos contra los que se prueban los motores) y los datos de la demo construidos con ellos. Sus fallos están ahí a propósito.
- **Herramientas de terceros** que ejecuta Pitangus (Trivy, OSV-Scanner, Betterleaks, Opengrep, Grype, Checkov, zizmor, ZAP, nuclei y el resto): repórtalos a sus proyectos. Una forma de hacer que Pitangus ejecute una de forma insegura sí entra.
- **Concesiones documentadas**, como usar el socket de Docker en un portátil ([concesiones conocidas](../docs/es/seguridad.md#concesiones-conocidas)), y ajustes que elegiste debilitar (por ejemplo `PITANGUS_ALLOW_INSECURE_HTTP=1`).
- Hallazgos que exigen un acceso que quien ataca ya tiene: root en el host, una clave maestra robada o las credenciales de un administrador.
- Reportes de escáneres automáticos sin impacto demostrado, cabeceras de buenas prácticas ausentes sin una forma de explotarlo, e ingeniería social o ataques físicos.

Si no estás seguro de si algo entra en el alcance, repórtalo en privado igualmente.
