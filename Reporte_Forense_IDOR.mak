# 📋 Reporte Forense: Incidente de Explotación IDOR en Endpoint de Facturación

**Fecha del Reporte:** 2026
**Preparado por:** Equipo de Respuesta ante Incidentes / Análisis Forense (SOC)  
**Severidad:** Crítica  
**Vulnerabilidad:** Insecure Direct Object Reference (IDOR)  
**Endpoint Afectado:** `www.mercadolibre.com/invoices/search?invoice_id={id}&site_id={id}&authtoken={token}`

---

## 1. Resumen Ejecutivo

El 1 de enero de 2021, el equipo de Seguridad Web detectó actividad anómala asociada a la enumeración y descarga masiva de facturas de clientes a través del endpoint `/invoices/search`. 

Mediante el análisis forense de los logs generados durante un periodo de 3 meses (`three_months.csv`), se confirmó la explotación exitosa de una vulnerabilidad de tipo **IDOR (Insecure Direct Object Reference)**. Este fallo permitió a actores maliciosos iterar sobre el parámetro `invoice_id` y extraer datos de carácter sensible (PII) de los usuarios, tales como nombres, apellidos, correos electrónicos, números telefónicos, direcciones e identificadores fiscales.

---

## 2. Cronología del Incidente (Timeline)

A partir del análisis sistemático de las marcas de tiempo (`timestamp`) registradas en los logs:

* **Inicio del Incidente:** *(Insertar fecha de inicio obtenida de los logs / p. ej. 2021-01-01 00:00:00)*
* **Cierre de Análisis:** *(Insertar fecha final registrada en los logs)*
* **Patrón de Tráfico:** Se identificaron picos de solicitudes automatizadas en intervalos cortos de tiempo, característicos de ataques de raspado de datos (*web scraping*).

---

## 3. Hallazgos Clave del Análisis

### A. Top IPs de Origen y Geolocalización
Las solicitudes que explotaron el endpoint se concentraron principalmente en las siguientes direcciones IP de origen y sus respectivos países:

| Posición | Dirección IP | Total de Solicitudes | País de Origen |
| :---: | :---: | :---: | :---: |
| **1** | *(Consultar terminal)* | *(Total de req.)* | *(País)* |
| **2** | *(Consultar terminal)* | *(Total de req.)* | *(País)* |
| **3** | *(Consultar terminal)* | *(Total de req.)* | *(País)* |
| ... | *(Top 20 IPs identificado por la herramienta)* | ... | ... |

### B. Tokens de Autenticación Utilizados (`authtoken`)
Se analizó la cabecera / parámetro de autenticación en las URI. Se identificó el uso reiterado de tokens específicos para la consulta de múltiples registros distintos, lo que confirma la falla de control de acceso:

1. `Top 1 AuthToken`: *(Token extraído)*
2. `Top 2 AuthToken`: *(Token extraído)*
3. ... *(Hasta el Top 10 de tokens)*

### C. Impacto en Datos de Usuarios
* **Faturas Únicas Consultadas / Expuestas:** *(Número total de invoice_id únicos extraídos)*
* **Dominios / Sites Afectados:** `www.mercadolibre.com` (y subdominios asociados identificados en `http_host`).

---

## 4. Arquitectura del Agente GenAI Utilizado

Para la automatización de la detección de este patrón, se desarrolló e implementó un **Agente Inteligente GenAI** utilizando **LangChain** y el modelo **Google Gemini** (`gemini-2.0-flash`). 

* **Capacidad del Agente:** 
  * Integración con la ferramenta `analisar_metricas_idor` para procesar el CSV via Pandas y geolocalizar IPs mediante API REST.
  * Mapeo dinámico de la línea de tiempo del ataque mediante la herramienta `construir_timeline_ataque`.
  * Generación automatizada de hipótesis de hallazgos y resúmenes de patrones anómalos.

---

## 5. Recomendaciones de Mitigación

1. **Corrección de Control de Acceso (Remediación del IDOR):**
   Implementar una validación estricta a nivel de backend que verifique si el `authtoken` (usuario autenticado en sesión) posee permisos explícitos para acceder al `invoice_id` solicitado antes de devolver la respuesta.
2. **Limitación de Tasa (Rate Limiting):**
   Establecer reglas en el WAF (Web Application Firewall) para limitar el número de peticiones consecutivas al endpoint `/invoices/search` por IP y por token.
3. **Monitoreo Continuo:**
   Implementar alertas automáticas en el SIEM ante incrementos inusuales de códigos HTTP 200 en endpoints con datos PII.