from flask import Flask, request, render_template, send_file
import os

# Importa tus clases del escáner de red
from escanerNMAP import VulnerabilityDatabase, NetworkScanner, ReportGenerator, Notifier

app = Flask(__name__)

# Ruta para mostrar la página HTML
@app.route('/')
def index():
    return render_template('index.html')

# Ruta para manejar el envío del formulario
@app.route('/scan', methods=['POST'])
def scan():
    # Obtener datos del formulario
    rango_ips = request.form['rango_ip']
    tipo_escaneo = request.form['tipo_escaneo']
    enviar_reporte = request.form['enviar_reporte']
    correo = request.form.get('correo', None)

    # Instanciar la base de datos de vulnerabilidades
    vuln_db = VulnerabilityDatabase()
    scanner = NetworkScanner(rango_ips, tipo_escaneo, vuln_db)

    # Ejecutar el escaneo
    scanner.escanear_red()

    # Generar reportes
    report_generator = ReportGenerator(scanner)
    report_generator.exportar_a_csv("reporte_vulnerabilidades.csv")
    report_generator.exportar_a_html("reporte_vulnerabilidades.html")
    report_generator.exportar_a_txt("reporte_vulnerabilidades.txt")

    # Verificar si se debe enviar el reporte por correo
    if enviar_reporte == 'si' and correo:
        notifier = Notifier(correo)
        notifier.filtrar_VulCritica(scanner)
        notifier.enviar_notificacion(report_generator)
        mensaje = f"Escaneo completado y reporte enviado al correo: {correo}."
    else:
        mensaje = "Escaneo completado. Mostrando el reporte en pantalla."

    # Mostrar el reporte HTML generado directamente
    return send_file("reporte_vulnerabilidades.html", as_attachment=False)

# Ruta para mostrar el reporte HTML
@app.route('/reporte')
def mostrar_reporte():
    return send_file("reporte_vulnerabilidades.html", as_attachment=False)

if __name__ == '__main__':
    app.run(host="0.0.0.0")
