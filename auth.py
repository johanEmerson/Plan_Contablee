"""Usuarios, sesiones, roles y bitacora de auditoria."""
import json
import re
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlsplit

from flask import (Blueprint, abort, g, redirect, render_template, request,
                   session as flask_session, url_for)
from sqlalchemy import func, select
from werkzeug.security import check_password_hash, generate_password_hash

import tenant
from db import SessionLocal
from models import Asiento, Auditoria, Config, Empresa, Usuario

bp = Blueprint("auth", __name__)

ROLES = {
    "admin": "Administrador",
    "contador": "Contador",
    "asistente": "Asistente",
    "lectura": "Solo lectura",
}
ROLES_ESCRITURA = {"admin", "contador", "asistente"}
ROLES_CIERRE = {"admin", "contador"}

# Endpoints accesibles sin sesion
PUBLICOS = {"auth.login", "auth.logout", "auth.setup", "auth.registro", "static"}


# ---------------------------------------------------------------- Config util

def config_get(clave, default=None):
    """Valor de configuracion de la empresa del usuario conectado."""
    eid = tenant.empresa_id_actual()
    if eid is None or eid == tenant.SIN_EMPRESA:
        return default
    with SessionLocal() as s:
        row = s.get(Config, {"empresa_id": eid, "clave": clave})
        return row.valor if row and row.valor is not None else default


def config_set(s, clave, valor):
    eid = tenant.empresa_id_actual()
    row = s.get(Config, {"empresa_id": eid, "clave": clave})
    if row:
        row.valor = valor
    else:
        s.add(Config(empresa_id=eid, clave=clave, valor=valor))


def ruc_valido(ruc: str) -> bool:
    """Valida formato RUC peruano: 11 digitos + digito verificador."""
    ruc = (ruc or "").strip()
    if len(ruc) != 11 or not ruc.isdigit() or ruc[:2] not in ("10", "15", "17", "20"):
        return False
    pesos = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
    check = 11 - sum(int(ruc[i]) * pesos[i] for i in range(10)) % 11
    check = {10: 0, 11: 1}.get(check, check)
    return check == int(ruc[10])


def empresa_basica():
    if tenant.empresa_id_actual() in (None, tenant.SIN_EMPRESA):
        return {"ruc": "", "razon_social": "", "tasa_igv": "18"}
    with SessionLocal() as s:
        filas = {c.clave: c.valor for c in s.execute(
            select(Config).where(Config.clave.in_(("empresa_ruc", "empresa_razon_social", "tasa_igv")))
        ).scalars()}
    return {
        "ruc": filas.get("empresa_ruc") or "",
        "razon_social": filas.get("empresa_razon_social") or "",
        "tasa_igv": filas.get("tasa_igv") or "18",
    }


def _secret_key():
    """SECRET_KEY de entorno; si no hay, se genera una y se guarda en la BD
    para que las sesiones sobrevivan reinicios."""
    import os
    env = os.environ.get("SECRET_KEY", "").strip()
    if env:
        return env
    with SessionLocal() as s:
        with s.begin():
            row = s.get(Config, {"empresa_id": 0, "clave": "secret_key"})
            if not row:
                row = Config(empresa_id=0, clave="secret_key", valor=secrets.token_hex(32))
                s.add(row)
            return row.valor


# ---------------------------------------------------------------- Auditoria

def usuario_actual():
    u = getattr(g, "usuario", None)
    return u["username"] if u else None


def registrar(session, accion, entidad, entidad_id=None, antes=None, despues=None, motivo=None):
    """Inserta un registro en la bitacora dentro de la transaccion `session`."""
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")[:64]
    except RuntimeError:
        ip = None
    session.add(Auditoria(
        usuario=usuario_actual(),
        accion=accion,
        entidad=entidad,
        entidad_id=entidad_id,
        motivo=(motivo or None) and motivo[:500],
        antes=json.dumps(antes, default=str, ensure_ascii=False) if antes is not None else None,
        despues=json.dumps(despues, default=str, ensure_ascii=False) if despues is not None else None,
        ip=ip,
    ))


def snapshot_asiento(a):
    cols = [c.name for c in a.__table__.columns]
    data = {c: getattr(a, c) for c in cols}
    data["lineas"] = [
        {
            "orden": l.orden, "cuenta": l.cuenta_codigo, "glosa": l.glosa_linea,
            "debe": str(l.debe), "haber": str(l.haber), "importe_me": str(l.importe_me) if l.importe_me is not None else None,
            "es_titulo": l.es_titulo,
        }
        for l in a.lineas
    ]
    return data


# ---------------------------------------------------------------- Guardas

def requiere_rol(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            u = getattr(g, "usuario", None)
            if not u or u["rol"] not in roles:
                return _denegado()
            return fn(*a, **kw)
        return wrapper
    return deco


def _es_api():
    return request.method != "GET" or request.is_json or request.path.startswith(("/buscar", "/dashboard/data", "/sunat/"))


def _denegado():
    msg = "No tienes permisos para esta accion."
    if _es_api():
        return {"ok": False, "error": msg, "errores": [msg]}, 403
    abort(403)


def init_app(app):
    app.secret_key = _secret_key()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=60 * 60 * 10,
    )
    app.register_blueprint(bp)

    @app.before_request
    def _cargar_usuario():
        g.usuario = None
        g.empresa_id = None
        uid = flask_session.get("uid")
        if uid and request.endpoint != "static":
            with SessionLocal() as s:
                u = s.get(Usuario, uid)
                if u and u.activo and u.empresa_id:
                    g.usuario = _datos_sesion(u)
                    g.empresa_id = u.empresa_id
        if request.endpoint in PUBLICOS:
            return None
        if not g.usuario:
            if _es_api():
                return {"ok": False, "error": "Sesion expirada. Vuelve a iniciar sesion."}, 401
            return redirect(url_for("auth.login", next=request.full_path))
        # Usuarios de solo lectura no pueden modificar nada
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.endpoint != "auth.logout":
            if g.usuario["rol"] not in ROLES_ESCRITURA:
                return _denegado()
            # Proteccion CSRF basica: las mutaciones via fetch deben venir del mismo origen
            origin = request.headers.get("Origin")
            # Se compara solo el dominio: detras de un proxy el esquema (http/https) puede diferir.
            if origin and urlsplit(origin).netloc.lower() != request.host.lower():
                return {"ok": False, "error": "Origen no permitido."}, 403
        return None

    @app.context_processor
    def _ctx():
        return {"usuario_actual": getattr(g, "usuario", None), "ROLES": ROLES,
                "empresa_actual": empresa_basica()}


# ---------------------------------------------------------------- Rutas

def _datos_sesion(u):
    return {"id": u.id, "username": u.username, "nombre": u.nombre or u.username, "rol": u.rol,
            "es_superadmin": bool(u.es_superadmin)}


def _iniciar_sesion(u):
    flask_session.clear()
    flask_session["uid"] = u.id
    flask_session.permanent = True
    g.usuario = _datos_sesion(u)
    g.empresa_id = u.empresa_id


def _hay_usuarios():
    with SessionLocal() as s:
        return (s.execute(select(func.count(Usuario.id))).scalar() or 0) > 0


def _next_seguro(nxt):
    if nxt and nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return "/"


@bp.route("/login", methods=["GET", "POST"])
def login():
    if not _hay_usuarios():
        return redirect(url_for("auth.registro"))
    if g.usuario:
        return redirect("/")
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        with SessionLocal() as s:
            with s.begin():
                u = s.execute(select(Usuario).where(Usuario.username == username)).scalar_one_or_none()
                if u and check_password_hash(u.password_hash, password) and not (u.activo and u.empresa_id):
                    error = "Tu cuenta esta desactivada."
                elif u and check_password_hash(u.password_hash, password):
                    u.ultimo_login = datetime.utcnow()
                    _iniciar_sesion(u)
                    registrar(s, "login", "usuario", u.id)
                    destino = _next_seguro(request.args.get("next"))
                    # Primer ingreso del administrador sin empresa configurada: pedirla ahora.
                    if u.rol == "admin" and not empresa_basica()["ruc"]:
                        return redirect(url_for("auth.empresa_inicio", next=destino))
                    return redirect(destino)
        error = error or "Usuario o contrasena incorrectos."
    return render_template("login.html", error=error, modo="login")


@bp.route("/setup")
def setup():
    """Ruta antigua del primer uso: ahora cada persona crea su cuenta en /registro."""
    return redirect(url_for("auth.registro"))


USUARIO_RE = re.compile(r"^[a-z0-9._-]{3,40}$")
_intentos_registro = {}  # ip -> [timestamps]
REGISTROS_POR_HORA = 5


def _limite_registro(ip):
    """Frena la creacion masiva de cuentas desde una misma conexion."""
    ahora = time.time()
    lista = [x for x in _intentos_registro.get(ip, []) if ahora - x < 3600]
    _intentos_registro[ip] = lista
    if len(lista) >= REGISTROS_POR_HORA:
        return True
    lista.append(ahora)
    return False


@bp.route("/registro", methods=["GET", "POST"])
def registro():
    """Crear cuenta. Cada cuenta tiene su propio espacio de datos (sus asientos,
    su configuracion, sus subdivisionarias). La primera cuenta del sistema es la
    del dueno de la aplicacion."""
    if g.usuario:
        return redirect("/")
    error = None
    datos = {"nombre": "", "username": ""}
    if request.method == "POST":
        nombre = " ".join((request.form.get("nombre") or "").split())[:150]
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        datos = {"nombre": nombre, "username": username}
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
        if request.form.get("sitio_web"):  # campo trampa: solo lo llenan los robots
            error = "No se pudo crear la cuenta."
        elif len(nombre) < 3:
            error = "Escribe tu nombre completo."
        elif not USUARIO_RE.match(username):
            error = ("El usuario debe tener de 3 a 40 caracteres: letras minusculas, numeros, "
                     "punto o guiones, sin espacios.")
        elif len(password) < 8:
            error = "La contrasena debe tener al menos 8 caracteres."
        elif password != password2:
            error = "Las contrasenas no coinciden."
        else:
            with SessionLocal() as s:
                with s.begin():
                    if s.execute(select(Usuario.id).where(Usuario.username == username)).first():
                        error = "Ese usuario ya existe. Elige otro."
                    elif _limite_registro(ip):
                        error = "Se crearon demasiadas cuentas desde esta conexion. Intenta en una hora."
                    else:
                        primero = not s.execute(select(Usuario.id).limit(1)).first()
                        emp = Empresa()
                        s.add(emp)
                        s.flush()
                        u = Usuario(username=username, nombre=nombre, rol="admin", empresa_id=emp.id,
                                    es_superadmin=primero, ultimo_login=datetime.utcnow(),
                                    password_hash=generate_password_hash(password))
                        s.add(u)
                        s.flush()
                        _iniciar_sesion(u)
                        registrar(s, "crear", "usuario", u.id, despues={"username": username})
            if not error:
                return redirect(url_for("auth.empresa_inicio"))
    return render_template("login.html", error=error, modo="registro", datos=datos)


@bp.route("/empresa/inicio", methods=["GET", "POST"])
def empresa_inicio():
    """Paso de inicio: datos de la empresa (RUC, razon social, IGV) en la pantalla de acceso."""
    nxt = _next_seguro(request.args.get("next"))
    if nxt.startswith("/empresa/inicio"):
        nxt = "/"
    if g.usuario["rol"] != "admin":
        return redirect(nxt)
    emp = empresa_basica()
    error = None
    if request.method == "POST":
        if request.form.get("omitir"):
            return redirect(nxt)
        ruc = (request.form.get("ruc") or "").strip()
        razon = " ".join((request.form.get("razon_social") or "").split())[:300]
        tasa = (request.form.get("tasa_igv") or "18").strip()
        emp = {"ruc": ruc, "razon_social": razon, "tasa_igv": tasa}
        if not ruc_valido(ruc):
            error = "RUC invalido: deben ser 11 digitos con digito verificador correcto."
        elif len(razon) < 3:
            error = "Escribe la razon social de la empresa."
        elif tasa not in ("18", "10.5"):
            error = "Tasa de IGV invalida."
        else:
            antes = empresa_basica()
            with SessionLocal() as s:
                with s.begin():
                    config_set(s, "empresa_ruc", ruc)
                    config_set(s, "empresa_razon_social", razon)
                    config_set(s, "tasa_igv", tasa)
                    registrar(s, "editar", "config", None, antes=antes, despues=emp)
            return redirect(nxt)
    return render_template("login.html", error=error, modo="empresa", emp=emp, nxt=nxt)


@bp.route("/logout", methods=["POST", "GET"])
def logout():
    flask_session.clear()
    return redirect(url_for("auth.login"))


def requiere_dueno(fn):
    """Solo el dueno de la aplicacion (es_superadmin)."""
    @wraps(fn)
    def wrapper(*a, **kw):
        u = getattr(g, "usuario", None)
        if not u or not u.get("es_superadmin"):
            return _denegado()
        return fn(*a, **kw)
    return wrapper


@bp.route("/usuarios")
@requiere_dueno
def usuarios():
    """Cuentas registradas en la aplicacion. No muestra datos contables de nadie."""
    ahora = datetime.utcnow()
    with tenant.sesion_global() as s:
        rows = s.execute(select(Usuario).order_by(Usuario.created_at.desc(), Usuario.id.desc())).scalars().all()
        datos_emp = {}
        for c in s.execute(select(Config).where(
                Config.clave.in_(("empresa_ruc", "empresa_razon_social")))).scalars():
            datos_emp.setdefault(c.empresa_id, {})[c.clave] = c.valor or ""
        asientos = dict(s.execute(select(Asiento.empresa_id, func.count(Asiento.id))
                                  .group_by(Asiento.empresa_id)).all())
    lista = []
    for u in rows:
        info = datos_emp.get(u.empresa_id, {})
        lista.append({
            "id": u.id, "username": u.username, "nombre": u.nombre, "activo": u.activo,
            "es_superadmin": u.es_superadmin, "creado": u.created_at, "ultimo_login": u.ultimo_login,
            "razon_social": info.get("empresa_razon_social") or "", "ruc": info.get("empresa_ruc") or "",
            "asientos": asientos.get(u.empresa_id, 0),
        })
    hace7, hace30 = ahora - timedelta(days=7), ahora - timedelta(days=30)
    resumen = {
        "total": len(lista),
        "activos_7": sum(1 for u in lista if u["ultimo_login"] and u["ultimo_login"] >= hace7),
        "activos_30": sum(1 for u in lista if u["ultimo_login"] and u["ultimo_login"] >= hace30),
        "nuevos_30": sum(1 for u in lista if u["creado"] and u["creado"] >= hace30),
        "sin_empresa": sum(1 for u in lista if not u["ruc"]),
        "asientos": sum(asientos.values()),
    }
    return render_template("usuarios.html", usuarios=lista, resumen=resumen)


@bp.route("/usuarios/<int:uid>", methods=["PUT"])
@requiere_dueno
def usuarios_editar(uid):
    """Activar / desactivar una cuenta o cambiarle la contrasena."""
    d = request.get_json(silent=True) or {}
    with tenant.sesion_global() as s:
        with s.begin():
            u = s.get(Usuario, uid)
            if not u:
                return {"ok": False, "error": "No existe."}, 404
            if "activo" in d:
                if u.id == g.usuario["id"] and not d["activo"]:
                    return {"ok": False, "error": "No puedes desactivar tu propia cuenta."}, 400
                u.activo = bool(d["activo"])
            if d.get("password"):
                if len(d["password"]) < 8:
                    return {"ok": False, "error": "La contrasena debe tener al menos 8 caracteres."}, 400
                u.password_hash = generate_password_hash(d["password"])
    return {"ok": True}


@bp.route("/auditoria")
@requiere_rol("admin", "contador")
def auditoria():
    entidad = request.args.get("entidad", "").strip()
    entidad_id = request.args.get("id", type=int)
    usuario = request.args.get("usuario", "").strip()
    with SessionLocal() as s:
        stmt = select(Auditoria).order_by(Auditoria.id.desc())
        if entidad:
            stmt = stmt.where(Auditoria.entidad == entidad)
        if entidad_id:
            stmt = stmt.where(Auditoria.entidad_id == entidad_id)
        if usuario:
            stmt = stmt.where(Auditoria.usuario == usuario)
        rows = s.execute(stmt.limit(500)).scalars().all()
        eventos = [{
            "id": r.id, "fecha": r.fecha, "usuario": r.usuario or "", "accion": r.accion,
            "entidad": r.entidad, "entidad_id": r.entidad_id, "motivo": r.motivo or "",
            "antes": r.antes, "despues": r.despues, "ip": r.ip or "",
        } for r in rows]
    return render_template("auditoria.html", eventos=eventos, entidad=entidad,
                           entidad_id=entidad_id or "", usuario_f=usuario)
