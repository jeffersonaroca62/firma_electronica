import os
import io
import uuid
from datetime import datetime
from flask import Flask, render_template, request, send_file, session, redirect, url_for
import fitz
import qrcode
import platform
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from pyhanko.sign import signers, timestamps
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata
from pyhanko.sign.signers.pdf_byterange import BuildProps
from textwrap import wrap
from flask_bcrypt import Bcrypt
import sqlite3
from functools import wraps
from zoneinfo import ZoneInfo  # <- Para manejar la zona horaria

# ------------------ Config Flask ------------------
app = Flask(__name__)
app.secret_key = "tu_clave_secreta_aqui"
app.config['UPLOAD_FOLDER'] = "uploads"
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

bcrypt = Bcrypt(app)

# ------------------ DB ------------------
def get_db_connection():
    conn = sqlite3.connect('usuarios.db')
    conn.row_factory = sqlite3.Row
    return conn

# ------------------ Login required ------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ------------------ Registro ------------------
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        fullname = request.form['fullname']
        email = request.form['email']
        phone = request.form.get('phone', '')
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template("registro.html", error="Las contraseñas no coinciden")

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        conn = get_db_connection()
        try:
            conn.execute("""
                INSERT INTO usuarios (fullname, email, phone, username, password_hash)
                VALUES (?, ?, ?, ?, ?)
            """, (fullname, email, phone, username, password_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("registro.html", error="El usuario o correo ya existe")
        conn.close()
        return redirect(url_for('login'))
    return render_template("registro.html")

# ------------------ Login ------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM usuarios WHERE username=?", (username,)).fetchone()
        conn.close()
        if user and bcrypt.check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['fullname'] = user['fullname']
            return redirect(url_for('index'))
        else:
            return render_template("login.html", error="Usuario o contraseña incorrectos")
    return render_template("login.html")

# ------------------ Logout ------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# ------------------ Página principal ------------------
@app.route("/")
@login_required
def index():
    return render_template("index.html", username=session.get('username'))

# ------------------ Subir PDF y generar previsualización de QR ------------------
@app.route("/firmar", methods=["POST"])
@login_required
def firmar():
    pdf_file = request.files.get("pdf")
    p12_file = request.files.get("p12")
    p12_password = request.form.get("p12_password")
    user_timezone = request.form.get("zona_horaria", "UTC")  # <- capturamos zona horaria

    if not pdf_file or not p12_file or not p12_password:
        return render_template("index.html", error="Faltan archivos o contraseña", username=session.get('username'))

    try:
        p12_data = p12_file.read()
        pkcs12.load_key_and_certificates(p12_data, p12_password.encode())
        p12_file.seek(0)
    except Exception:
        return render_template("index.html", error="Contraseña del certificado incorrecta", username=session.get('username'))

    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_file.filename)
    p12_path = os.path.join(app.config['UPLOAD_FOLDER'], p12_file.filename)
    pdf_file.save(pdf_path)
    p12_file.save(p12_path)

    # Guardamos en sesión para usar después
    session['pdf_file'] = pdf_file.filename
    session['p12_file'] = p12_file.filename
    session['p12_password'] = p12_password
    session['user_timezone'] = user_timezone  # <- guardamos la zona horaria

    # Cargar certificado y extraer nombre
    _, certificate, _ = pkcs12.load_key_and_certificates(p12_data, p12_password.encode())
    nombre_titular = "DESCONOCIDO"
    try:
        given_names = certificate.subject.get_attributes_for_oid(NameOID.GIVEN_NAME)
        surnames = certificate.subject.get_attributes_for_oid(NameOID.SURNAME)
        if given_names and surnames:
            nombres = " ".join([a.value for a in given_names])
            apellidos = " ".join([a.value for a in surnames])
            nombre_titular = f"{nombres} {apellidos}"
        else:
            for attribute in certificate.subject:
                if attribute.oid.dotted_string == "2.5.4.3":
                    nombre_titular = attribute.value
                    break
    except Exception:
        nombre_titular = certificate.subject.rfc4514_string()

    # Generar hora local según zona horaria
    local_dt = datetime.now(ZoneInfo(user_timezone))
    hora_firma_str = local_dt.strftime("%d/%m/%Y %H:%M:%S")

    # Generar QR
    qr_text_preview = (
        f"FIRMADO POR: {nombre_titular}\n"
        f"RAZON: \n"
        f"LOCALIZACION: \n"
        f"FECHA: {hora_firma_str} ({user_timezone})\n"
        f"VALIDAR CON: https://www.firmadigital.gob.ec\n"
        f"Firmado digitalmente con FirmaEC 4.0.1 {platform.system()} {platform.release()}"
    )
    qr = qrcode.QRCode(version=2, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=0)
    qr.add_data(qr_text_preview)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
    qr_preview_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{pdf_file.filename}_preview_qr.png")
    img.save(qr_preview_path)

    return render_template("seleccionar_firma.html", pdf_file=pdf_file.filename, nombre=nombre_titular)

# ------------------ Seleccionar ubicación firma ------------------
@app.route("/seleccionar_firma")
@login_required
def seleccionar_firma():
    pdf_file = session.get('pdf_file')
    if not pdf_file:
        return redirect(url_for("index"))
    return render_template("seleccionar_firma.html", pdf_file=pdf_file, username=session.get('username'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

# ------------------ Generar PDF firmado ------------------
@app.route("/generar_pdf_firmado", methods=["POST"])
@login_required
def generar_pdf_firmado():
    sig_x = float(request.form.get("sig_x", 20))
    sig_y = float(request.form.get("sig_y", 20))
    sig_page = int(request.form.get("sig_page", 1)) - 1

    pdf_file = session.get('pdf_file')
    p12_file = session.get('p12_file')
    p12_password = session.get('p12_password')
    user_timezone = session.get('user_timezone', 'UTC')

    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_file)
    p12_path = os.path.join(app.config['UPLOAD_FOLDER'], p12_file)

    # ------------------ Fecha con nanosegundos y offset ------------------
    from datetime import datetime
    from zoneinfo import ZoneInfo
    import time

    local_dt = datetime.now(ZoneInfo(user_timezone))
    ns = time.time_ns() % 1_000_000_000
    offset = local_dt.utcoffset()
    hours_offset = int(offset.total_seconds() // 3600)
    minutes_offset = int((offset.total_seconds() % 3600) // 60)
    tz_str = f"{hours_offset:+03d}:{minutes_offset:02d}"
    fecha_final = f"{local_dt.strftime('%Y-%m-%dT%H:%M:%S')}.{ns:09d}{tz_str}"

    # Leer certificado
    with open(p12_path, "rb") as f:
        p12_data = f.read()
    _, certificate, _ = pkcs12.load_key_and_certificates(p12_data, p12_password.encode())

    # Obtener nombre del titular
    nombre_titular = "DESCONOCIDO"
    try:
        given_names = certificate.subject.get_attributes_for_oid(NameOID.GIVEN_NAME)
        surnames = certificate.subject.get_attributes_for_oid(NameOID.SURNAME)
        if given_names and surnames:
            nombres = " ".join([a.value for a in given_names])
            apellidos = " ".join([a.value for a in surnames])
            nombre_titular = f"{nombres} {apellidos}"
        else:
            for attribute in certificate.subject:
                if attribute.oid.dotted_string == "2.5.4.3":
                    nombre_titular = attribute.value
                    break
    except Exception:
        nombre_titular = certificate.subject.rfc4514_string()

    # ------------------ Firmante PyHanko ------------------
    base_signer = signers.SimpleSigner.load_pkcs12(
        pfx_file=p12_path,
        passphrase=p12_password.encode()
    )

    class FixedDateSigner(signers.SimpleSigner):
        def __init__(self, base, ts):
            super().__init__(
                signing_cert=base.signing_cert,
                signing_key=base.signing_key,
                cert_registry=base.cert_registry,
                signature_mechanism=base.signature_mechanism,
                prefer_pss=base.prefer_pss
            )
            self.fixed_ts = ts

        def sign(self, data_digest, digest_algorithm, timestamp=None,
                 revocation_info=None, use_pades=False, timestamper=None):
            return super().sign(
                data_digest,
                digest_algorithm,
                timestamp=self.fixed_ts,
                revocation_info=revocation_info,
                use_pades=use_pades,
                timestamper=timestamper
            )

    cms_signer = FixedDateSigner(base_signer, local_dt)

    nombre_campo = f"Signature_{uuid.uuid4().hex[:8]}"
    signature_meta = PdfSignatureMetadata(
        field_name=nombre_campo,
        name=nombre_titular,
        reason="",
        location="",
        app_build_props=BuildProps(name="Rúbrica 3.0")
    )

    # ------------------ Abrir PDF con PyMuPDF ------------------
    doc = fitz.open(pdf_path)
    if sig_page >= len(doc):
        sig_page = 0
    page = doc[sig_page]

    # ------------------ Generar QR con fecha nanosegundos ------------------
    qr = qrcode.QRCode(version=2, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=0)
    qr_text = (
        f"FIRMADO POR: {nombre_titular}\n"
        f"RAZON: {signature_meta.reason}\n"
        f"LOCALIZACION: {signature_meta.location}\n"
        f"FECHA: {fecha_final}\n"
        f"VALIDAR CON: https://www.firmadigital.gob.ec\n"
        f"Firmado digitalmente con FirmaEC 4.0.1 {platform.system()} {platform.release()}"
    )
    qr.add_data(qr_text)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
    qr_buffer = io.BytesIO()
    qr_img.save(qr_buffer, format="PNG", optimize=True)
    qr_buffer.seek(0)

    # ------------------ Insertar QR y texto en PDF ------------------
    qr_size = 40
    rect_qr = fitz.Rect(sig_x, sig_y, sig_x + qr_size, sig_y + qr_size)
    page.insert_image(rect_qr, stream=qr_buffer)

    # Insertar texto junto al QR
    fontname = "Courier"
    nombre_fontsize = 6.5
    texto_fontsize = 3.5
    partes = nombre_titular.split()
    if len(partes) > 2:
        nombres_txt = " ".join(partes[:2])
        apellidos_txt = " ".join(partes[2:])
    elif len(partes) == 2:
        nombres_txt, apellidos_txt = partes
    else:
        nombres_txt = nombre_titular
        apellidos_txt = ""

    lineas = [
        ("Firmado electrónicamente por:", texto_fontsize, False),
        (nombres_txt, nombre_fontsize, True),
        (apellidos_txt, nombre_fontsize, True),
        ("Validar únicamente con FirmaEC", texto_fontsize, False),
        (f"FECHA: {fecha_final}", texto_fontsize, False)
    ]

    def insertar_linea(page, texto, x, y, fontsize, bold, max_chars=35, spacing=0.5):
        for linea in wrap(texto, width=max_chars):
            color = (0,0,0) if bold else (0.2,0.2,0.2)
            if bold:
                page.insert_text((x, y), linea, fontsize=fontsize, fontname=fontname, color=color)
                page.insert_text((x+0.2, y), linea, fontsize=fontsize, fontname=fontname, color=color)
            else:
                page.insert_text((x, y), linea, fontsize=fontsize, fontname=fontname, color=color)
            y += fontsize + spacing + 1
        return y

    altura_total = 0
    for texto, fontsize, bold in lineas:
        n_wrap = max(1, len(wrap(texto, width=35)))
        altura_total += n_wrap * (fontsize - 1)

    y_text = sig_y + (qr_size - altura_total)/2
    x_text = sig_x + qr_size + 0.5
    for texto, fontsize, bold in lineas:
        spacing = -2 if texto in [nombres_txt, apellidos_txt] else 0.5
        y_text = insertar_linea(page, texto, x_text, y_text, fontsize, bold, spacing=spacing)

    # Guardar PDF en memoria
    pdf_buffer = io.BytesIO()
    doc.save(pdf_buffer)
    doc.close()
    pdf_buffer.seek(0)

    # ------------------ Firmar PDF con PyHanko ------------------
    w = IncrementalPdfFileWriter(pdf_buffer)
    append_signature_field(w, SigFieldSpec(sig_field_name=nombre_campo))
    out_pdf = io.BytesIO()
    signer = PdfSigner(
        signature_meta,
        signer=cms_signer,
        timestamper=timestamps.HTTPTimeStamper("http://freetsa.org/tsr")
    )
    signer.sign_pdf(w, output=out_pdf)
    out_pdf.seek(0)

    return send_file(out_pdf, download_name=f"firmado_{pdf_file}", as_attachment=True)

# ------------------ Ejecutar ------------------
if __name__ == "__main__":
    app.run(debug=True)
