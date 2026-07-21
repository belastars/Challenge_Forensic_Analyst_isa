# forensic-challenge
The Forensic Challenge!

# Problema a resolver
El 1 de enero de 2021, el equipo de websec detectó una vulnerabilidad tipo IDOR (Insecure Direct Object Reference), que afecta la aplicación de facturación de MercadoLibre y requiere al equipo de respuesta ante incidentes que realice un análisis forense para detectar si hubo explotación o no.
## Escenario
El endpoint de facturación www.mercadolibre.com/invoices/search?invoice_id={id}&site_id={id}&authtoken={token}, permite descargar facturas y obtener datos personales como nombre, apellido, email, teléfono, dirección e identificador fiscal.
Un atacante podría iterar el parámetro invoice_id y obtener **datos PII** de nuestros usuarios/compradores.  

Debido al tipo de información que puede ser extraída, el equipo legal requiere un análisis de 3 meses de logs, los cuales se han disponibilizado para su evaluación.
​
## Preguntas por resolver
En caso de encontrar signos de explotación crear un reporte forense detallando:
1.	¿Cuál es el top 20 de IPs que más peticiones realizaron al endpoint /invoices/search?
2.	¿Cuál es el top de países detrás de dichas IPs?
3.	¿Cuál es el top 10 de authtokens utilizados para autenticarse?
4.	¿Cuantos invoice_id fueron consultados / cuántos usuarios pudieron ser afectados?
5.	¿Cuál es el site más afectado?
​
## Challenge
1.	Cargar en un cuaderno Jupyter el archivo de logs three_months.csv para su análisis.
2.	Desarrollar uno o varios scripts en el cuaderno para analizar los logs y que permita(n) responder las preguntas anteriores.
3. Diseñar un agente GenAI (con Langchain, OpenAI, LlamaIndex, etc.) que:
- Asista en la clasificación y resumen de patrones en los logs
- Genere propuestas de hallazgos o líneas de investigación automatizadas
- Modele un flujo de análisis que interactúe con archivos y construya el timeline
- Agregue la mayor cantidad de capacidades como parte del reto
NOTA: implemente todo lo más agentico posible (con Agentes y Tools), el desarrollo que haga tiene que ser robusto y servir para otros casos similares.
4. 	Redactar el reporte forense.  

## Extra
1. Puede dockerizar la solución para que sea más fácil revisarlo  

 Todos los archivos generados, incluidos scripts y el reporte deberán entregarse como parte del challenge.
 **Se valorará mucho el análisis e interpretación de resultados que se plasme en el reporte.**
 
Todo el exito!
