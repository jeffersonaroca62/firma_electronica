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
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata
from pyhanko.sign.signers.pdf_byterange import BuildProps
from textwrap import wrap
from flask_bcrypt import Bcrypt
import sqlite3
from functools import wraps
from zoneinfo import ZoneInfo
from werkzeug.utils import secure_filename

# --- Inicializar Flask ---
app = Flask(__name__)
app.secret_key = "tu_clave_secreta_aqui"
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads")
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

bcrypt = Bcrypt(app)

# --- Inicializar DB automáticamente ---
def get_db_connection():
    if not os.path.exists("usuarios.db"):
        # tu script init_db.py debe tener una función init_db() que cree la tabla
        from init_db import init_db
        init_db()
    conn = sqlite3.connect("usuarios.db")
    conn.row_factory = sqlite3.Row
    return conn

# --- Decorador login_required ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Registro ---
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

# --- Login ---
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
            return redirect(url_for('index'))
        else:
            return render_template("login.html", error="Usuario o contraseña incorrectos")
    return render_template("login.html")

# --- Logout ---
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Página principal ---
@app.route("/")
@login_required
def index():
    return render_template("index.html", username=session.get('username'))

# --- Subir PDF y generar QR preview ---
@app.route("/firmar", methods=["POST"])
@login_required
def firmar():
    pdf_file = request.files.get("pdf")
    p12_file = request.files.get("p12")
    p12_password = request.form.get("p12_password")

    if not pdf_file or not p12_file or not p12_password:
        return render_template("index.html", error="Faltan archivos o contraseña", username=session.get('username'))

    # Sanitizar nombres de archivo para evitar problemas
    pdf_filename = secure_filename(pdf_file.filename)
    p12_filename = secure_filename(p12_file.filename)

    try:
        p12_data = p12_file.read()
        # Validamos contraseña del P12
        pkcs12.load_key_and_certificates(p12_data, p12_password.encode())
        # reset stream (aunque ya vamos a guardar el archivo)
        p12_file.seek(0)
    except Exception:
        return render_template("index.html", error="Contraseña del certificado incorrecta", username=session.get('username'))

    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
    p12_path = os.path.join(app.config['UPLOAD_FOLDER'], p12_filename)
    pdf_file.save(pdf_path)
    p12_file.save(p12_path)

    session['pdf_file'] = pdf_filename
    session['p12_file'] = p12_filename
    session['p12_password'] = p12_password

    # Extraer nombre del titular del certificado
    try:
        _, certificate, _ = pkcs12.load_key_and_certificates(p12_data, p12_password.encode())
    except Exception:
        certificate = None

    nombre_titular = "DESCONOCIDO"
    if certificate is not None:
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
            try:
                nombre_titular = certificate.subject.rfc4514_string()
            except Exception:
                nombre_titular = "DESCONOCIDO"

    # --- Generar QR preview y guardarlo en uploads ---
    try:
        qr_text_preview = (
            f"FIRMADO POR: {nombre_titular}\n"
            f"RAZON: \n"
            f"LOCALIZACION: \n"
            f"FECHA: {datetime.now().isoformat()}\n"
            f"VALIDAR CON: https://www.firmadigital.gob.ec\n"
            f"Firmado digitalmente con FirmaEC 4.0.1 {platform.system()} {platform.release()}"
        )
        qr = qrcode.QRCode(version=2, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=0)
        qr.add_data(qr_text_preview)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")

        # Guardar con el nombre que usa tu plantilla: "<archivo.pdf>_preview_qr.png"
        qr_preview_name = f"{pdf_filename}_preview_qr.png"
        qr_preview_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_preview_name)
        img.save(qr_preview_path)
    except Exception as e:
        # En caso de error con PIL o qrcode
        return render_template("index.html", error=f"Error al generar preview QR: {e}", username=session.get('username'))

    return render_template("seleccionar_firma.html",
                           pdf_file=pdf_filename,
                           nombre=nombre_titular,
                           username=session.get('username'))

# --- Seleccionar ubicación firma (GET) ---
@app.route("/seleccionar_firma")
@login_required
def seleccionar_firma():
    pdf_file = session.get('pdf_file')
    if not pdf_file:
        return redirect(url_for("index"))
    return render_template("seleccionar_firma.html", pdf_file=pdf_file, username=session.get('username'))

# --- Servir archivos subidos (PDF y QR preview) ---
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(path):
        # retornar 404 simple (puedes personalizar)
        return "Archivo no encontrado", 404
    return send_file(path)

# --- Generar PDF firmado final ---
@app.route("/generar_pdf_firmado", methods=["POST"])
@login_required
def generar_pdf_firmado():
    try:
        sig_x = float(request.form.get("sig_x", 20))
        sig_y = float(request.form.get("sig_y", 20))
        sig_page = int(request.form.get("sig_page", 1)) - 1

        pdf_file = session.get('pdf_file')
        p12_file = session.get('p12_file')
        p12_password = session.get('p12_password')

        if not pdf_file or not p12_file or not p12_password:
            return "Sesión incompleta: falta PDF o certificado", 400

        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_file)
        p12_path = os.path.join(app.config['UPLOAD_FOLDER'], p12_file)

        if not os.path.exists(pdf_path):
            return "PDF no encontrado en servidor", 404
        if not os.path.exists(p12_path):
            return "Certificado P12 no encontrado en servidor", 404

        fixed_dt = datetime.now(ZoneInfo("America/Guayaquil"))

        # Cargar certificado para extraer nombre (otra vez)
        with open(p12_path, "rb") as f:
            p12_data = f.read()
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
            try:
                nombre_titular = certificate.subject.rfc4514_string()
            except Exception:
                nombre_titular = "DESCONOCIDO"

        # Preparar firmante pyHanko con fecha fija
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

        cms_signer = FixedDateSigner(base_signer, fixed_dt)
        nombre_campo = f"Signature_{uuid.uuid4().hex[:8]}"
        signature_meta = PdfSignatureMetadata(
            field_name=nombre_campo,
            name=nombre_titular,
            reason="",
            location="",
            app_build_props=BuildProps(name="Rúbrica 3.0")
        )

        # Abrir PDF con PyMuPDF para insertar la imagen visual (QR)
        doc = fitz.open(pdf_path)
        if sig_page >= len(doc):
            sig_page = 0
        page = doc[sig_page]

        # Construir texto QR y generar imagen (la usamos si no existe preview)
        qr_text = (
            f"FIRMADO POR: {nombre_titular}\n"
            f"RAZON: {signature_meta.reason}\n"
            f"LOCALIZACION: {signature_meta.location}\n"
            f"FECHA: {fixed_dt.isoformat()}\n"
            f"VALIDAR CON: https://www.firmadigital.gob.ec\n"
            f"Firmado digitalmente con FirmaEC 4.0.1 {platform.system()} {platform.release()}"
        )

        # Ruta esperada del preview generado en /firmar (coincide con la plantilla)
        qr_preview_name = f"{pdf_file}_preview_qr.png"
        qr_preview_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_preview_name)

        temp_qr_path = None
        try:
            if os.path.exists(qr_preview_path):
                # usamos la previsualización que ya se guardó al subir
                pix = fitz.Pixmap(qr_preview_path)
            else:
                # si no existe la previsualización, la generamos temporalmente y la usamos
                qr = qrcode.QRCode(version=2, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=0)
                qr.add_data(qr_text)
                qr.make(fit=True)
                qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
                temp_qr_name = f"temp_qr_{uuid.uuid4().hex}.png"
                temp_qr_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_qr_name)
                qr_img.save(temp_qr_path)
                pix = fitz.Pixmap(temp_qr_path)

            # Insertar el QR (respetando el tamaño del pixmap)
            rect = fitz.Rect(sig_x, sig_y, sig_x + pix.width, sig_y + pix.height)
            page.insert_image(rect, pixmap=pix, overlay=True)

            # guardar incrementos visuales
            doc.saveIncr()

            # liberar pixmap (buena práctica)
            try:
                pix = None
            except Exception:
                pass

            # eliminar temporal si se creó
            if temp_qr_path and os.path.exists(temp_qr_path):
                try:
                    os.remove(temp_qr_path)
                except Exception:
                    pass

        except Exception as e_img:
            doc.close()
            return f"Error al insertar QR en PDF: {e_img}", 500

        # --- Firmar digitalmente usando pyHanko (incremental write, permitir híbridos) ---
        out_pdf = io.BytesIO()
        try:
            with open(pdf_path, "rb") as f:
                w = IncrementalPdfFileWriter(f, allow_hybrid=True)
                append_signature_field(
                    w,
                    SigFieldSpec(sig_field_name=nombre_campo, box=(sig_x, sig_y, sig_x+120, sig_y+40))
                )
                signer = PdfSigner(signature_meta, signer=cms_signer)
                signer.sign_pdf(w, output=out_pdf)
        except Exception as e_sign:
            return f"Error al firmar digitalmente el PDF: {e_sign}", 500

        out_pdf.seek(0)
        return send_file(
            out_pdf,
            as_attachment=True,
            download_name=f"firmado_{pdf_file}",
            mimetype="application/pdf"
        )

    except Exception as e:
        return f"Error al generar PDF firmado: {e}", 500

# --- Ejecutar ---
if __name__ == "__main__":
    app.run(debug=True)
