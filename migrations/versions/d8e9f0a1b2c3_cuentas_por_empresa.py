"""Cuentas por empresa: cada usuario registrado tiene sus propios datos.

- Tabla empresa.
- empresa_id en asiento, asiento_linea, entidad, cierre_mes, auditoria, config y usuario.
- Los numeros de asiento, RUC de entidades y cierres pasan a ser unicos por empresa.
- config pasa a tener clave primaria (empresa_id, clave); empresa_id = 0 para valores globales.
- Los datos existentes quedan en una empresa nueva, junto con los usuarios existentes.
  El administrador mas antiguo queda como dueno de la aplicacion.

Revision ID: d8e9f0a1b2c3
Revises: c7d8e9f0a1b2
Create Date: 2026-11-25
"""
from datetime import datetime
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d8e9f0a1b2c3"
down_revision: Union[str, None] = "c7d8e9f0a1b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLAS = ("asiento", "asiento_linea", "entidad", "cierre_mes", "auditoria")
# En SQLite los UNIQUE sin nombre se reflejan sin nombre: esta convencion les da uno.
NC = {"uq": "uq_%(table_name)s_%(column_0_name)s"}


def _quitar_unique(tabla, columnas):
    insp = sa.inspect(op.get_bind())
    for uc in insp.get_unique_constraints(tabla):
        if list(uc["column_names"]) == columnas:
            nombre = uc["name"] or f"uq_{tabla}_{columnas[0]}"
            with op.batch_alter_table(tabla, naming_convention=NC) as b:
                b.drop_constraint(nombre, type_="unique")


def upgrade() -> None:
    conn = op.get_bind()
    op.create_table(
        "empresa",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("activo", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    hay_datos = any(
        conn.execute(sa.text(f"SELECT 1 FROM {t} LIMIT 1")).first()
        for t in ("usuario", "asiento", "entidad", "cierre_mes")
    ) or conn.execute(sa.text("SELECT 1 FROM config WHERE clave <> 'secret_key' LIMIT 1")).first()
    eid = None
    if hay_datos:
        conn.execute(sa.text("INSERT INTO empresa (activo, created_at) VALUES (:a, :c)"),
                     {"a": True, "c": datetime.utcnow()})
        eid = conn.execute(sa.text("SELECT MAX(id) FROM empresa")).scalar()

    # empresa_id en las tablas de datos
    for t in TABLAS:
        with op.batch_alter_table(t) as b:
            b.add_column(sa.Column("empresa_id", sa.Integer, nullable=True))
        if eid is not None:
            conn.execute(sa.text(f"UPDATE {t} SET empresa_id = :e"), {"e": eid})
        with op.batch_alter_table(t) as b:
            b.alter_column("empresa_id", existing_type=sa.Integer, nullable=False)
        op.create_index(f"ix_{t}_empresa_id", t, ["empresa_id"])

    # Unicos por empresa
    _quitar_unique("asiento", ["numero"])
    _quitar_unique("entidad", ["ruc"])
    with op.batch_alter_table("cierre_mes") as b:
        b.drop_constraint("uq_cierre_year_month", type_="unique")
    with op.batch_alter_table("asiento") as b:
        b.create_unique_constraint("uq_asiento_empresa_numero", ["empresa_id", "numero"])
    with op.batch_alter_table("entidad") as b:
        b.create_unique_constraint("uq_entidad_empresa_ruc", ["empresa_id", "ruc"])
    with op.batch_alter_table("cierre_mes") as b:
        b.create_unique_constraint("uq_cierre_empresa_year_month", ["empresa_id", "year", "month"])

    # Usuarios: empresa y dueno de la aplicacion
    with op.batch_alter_table("usuario") as b:
        b.add_column(sa.Column("empresa_id", sa.Integer, nullable=True))
        b.add_column(sa.Column("es_superadmin", sa.Boolean, nullable=False, server_default=sa.false()))
        b.create_foreign_key("fk_usuario_empresa", "empresa", ["empresa_id"], ["id"])
    op.create_index("ix_usuario_empresa_id", "usuario", ["empresa_id"])
    if eid is not None:
        conn.execute(sa.text("UPDATE usuario SET empresa_id = :e"), {"e": eid})
        dueno = conn.execute(sa.text(
            "SELECT id FROM usuario WHERE rol = 'admin' AND activo = :t ORDER BY id LIMIT 1"), {"t": True}).scalar()
        if dueno is None:
            dueno = conn.execute(sa.text("SELECT MIN(id) FROM usuario")).scalar()
        if dueno is not None:
            conn.execute(sa.text("UPDATE usuario SET es_superadmin = :t WHERE id = :i"), {"t": True, "i": dueno})

    # config: clave primaria (empresa_id, clave)
    filas = conn.execute(sa.text("SELECT clave, valor FROM config")).fetchall()
    op.drop_table("config")
    config = op.create_table(
        "config",
        sa.Column("empresa_id", sa.Integer, primary_key=True),
        sa.Column("clave", sa.String(60), primary_key=True),
        sa.Column("valor", sa.Text, nullable=True),
    )
    op.create_index("ix_config_empresa_id", "config", ["empresa_id"])
    nuevas = [{"empresa_id": 0 if c == "secret_key" else eid, "clave": c, "valor": v}
              for c, v in filas if c == "secret_key" or eid is not None]
    if nuevas:
        op.bulk_insert(config, nuevas)


def downgrade() -> None:
    raise NotImplementedError("Restaura un respaldo: esta migracion separa los datos por empresa.")
