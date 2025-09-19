import os
import io
import uuid
from datetime import datetime
from flask import Flask, render_template, request, send_file, session
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
from zoneinfo import ZoneInfo

# ------------------ Config Flask ------------------
app = Flask(__name__)
app.secret_key = "tu_clave_secreta_aqui"
app.config['UPLOAD_FOLDER'] = "uploads"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ------------------ Subir PDF y generar previsualización ------------------
@app.route("/firmar", methods=["POST"])
def firmar():
    pdf_file = request.files.get("pdf")
    p12_file = request.files.get("p12")
    p12_password = request.form.get("p12_password")

    if not pdf_file or not p12_file or not p12_password:
        return "Faltan archivos o contraseña", 400

    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_file.filename)
    p12_path = os.path.join(app.config['UPLOAD_FOLDER'], p12_file.filename)
    pdf_file.save(pdf_path)
    p12_file.save(p12_path)

    # --- Cargar certificado ---
    p12_data = open(p12_path, "rb").read()
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

    # --- QR de previsualización ---
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
    qr_preview_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{pdf_file.filename}_preview_qr.png")
    img.save(qr_preview_path)

    return render_template(
        "seleccionar_firma.html",
        pdf_file=pdf_file.filename,
        nombre=nombre_titular,
        qr_preview=os.path.basename(qr_preview_path)
    )

# ------------------ Generar PDF firmado y descargar ------------------
@app.route("/generar_pdf_firmado", methods=["POST"])
def generar_pdf_firmado():
    sig_x = float(request.form.get("sig_x", 20))
    sig_y = float(request.form.get("sig_y", 20))
    sig_page = int(request.form.get("sig_page", 1)) - 1

    pdf_file = request.form.get("pdf_file")
    p12_file = request.form.get("p12_file")
    p12_password = request.form.get("p12_password")

    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_file)
    p12_path = os.path.join(app.config['UPLOAD_FOLDER'], p12_file)

    fixed_dt = datetime.now(ZoneInfo("America/Guayaquil"))

    with open(p12_path, "rb") as f:
        p12_data = f.read()
    _, certificate, _ = pkcs12.load_key_and_certificates(p12_data, p12_password.encode())
    nombre_titular = certificate.subject.rfc4514_string()

    base_signer = signers.SimpleSigner.load_pkcs12(pfx_file=p12_path, passphrase=p12_password.encode())

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

    doc = fitz.open(pdf_path)
    page = doc[sig_page if sig_page < len(doc) else 0]

    # --- Insertar QR + texto como en tu PDF final ---
    qr = qrcode.QRCode(version=2, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=0)
    qr_text = (
        f"FIRMADO POR: {nombre_titular}\n"
        f"FECHA: {fixed_dt.isoformat()}\n"
        f"VALIDAR CON: https://www.firmadigital.gob.ec\n"
        f"Firmado digitalmente con FirmaEC 4.0.1 {platform.system()} {platform.release()}"
    )
    qr.add_data(qr_text)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
    qr_buffer = io.BytesIO()
    qr_img.save(qr_buffer, format="PNG")
    qr_buffer.seek(0)
    rect_qr = fitz.Rect(sig_x, sig_y, sig_x + 40, sig_y + 40)
    page.insert_image(rect_qr, stream=qr_buffer)

    pdf_buffer = io.BytesIO()
    doc.save(pdf_buffer)
    doc.close()
    pdf_buffer.seek(0)

    # --- Firma invisible ---
    w = IncrementalPdfFileWriter(pdf_buffer)
    append_signature_field(w, SigFieldSpec(sig_field_name=nombre_campo, box=(0,0,0,0)))
    out_pdf = io.BytesIO()
    signer = PdfSigner(signature_meta, signer=cms_signer)
    signer.sign_pdf(w, output=out_pdf)
    out_pdf.seek(0)

    return send_file(out_pdf, download_name=f"firmado_{pdf_file}", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
