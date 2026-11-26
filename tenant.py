"""Multiempresa: cada usuario ve y guarda solo los datos de su empresa.

Todas las tablas que heredan de models.DeEmpresa se filtran solas:
- Al consultar (SELECT, UPDATE y DELETE del ORM) se agrega
  "empresa_id = <empresa del usuario conectado>".
- Al guardar un registro nuevo se le pone la empresa del usuario.

Dentro de una peticion sin usuario conectado no se ve ningun dato.
Fuera de una peticion (arranque, migraciones, scripts) no se filtra.
El panel de la plataforma usa sesion_global() para contar entre empresas.
"""
from flask import g, has_request_context
from sqlalchemy import event
from sqlalchemy.orm import Session, with_loader_criteria

from db import SessionLocal
from models import DeEmpresa

SIN_EMPRESA = -1  # no coincide con ninguna fila


def empresa_id_actual():
    """Empresa del usuario conectado; SIN_EMPRESA si no hay; None fuera de una peticion."""
    if not has_request_context():
        return None
    return getattr(g, "empresa_id", None) or SIN_EMPRESA


def sesion_global():
    """Sesion sin filtro de empresa (solo para el panel del dueno de la plataforma)."""
    s = SessionLocal()
    s.info["todas_empresas"] = True
    return s


@event.listens_for(Session, "do_orm_execute")
def _filtrar_por_empresa(state):
    if state.session.info.get("todas_empresas"):
        return
    if not (state.is_select or state.is_update or state.is_delete):
        return
    if state.is_column_load or state.is_relationship_load:
        return
    eid = empresa_id_actual()
    if eid is None:
        return
    state.statement = state.statement.options(
        with_loader_criteria(DeEmpresa, lambda cls: cls.empresa_id == eid, include_aliases=True)
    )


@event.listens_for(Session, "before_flush")
def _asignar_empresa(session, flush_context, instances):
    for obj in session.new:
        if not isinstance(obj, DeEmpresa) or obj.empresa_id is not None:
            continue
        eid = empresa_id_actual()
        if eid is None or eid == SIN_EMPRESA:
            raise RuntimeError(f"No se puede guardar {type(obj).__name__} sin empresa.")
        obj.empresa_id = eid
