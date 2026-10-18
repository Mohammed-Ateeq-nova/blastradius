import re
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.config import settings
from app.db.falkordb import create_redis_client, probe_falkordb
from app.db.graph import FalkorGraph
from app.services.fixture_loader import load_demo_fixture
from app.services.graph_builder import upsert_fixture_graph
from app.services.graph_queries import (
    finding_paths,
    list_findings,
    list_upgrade_candidates,
)
from app.services.project_scanner import ProjectScanError, scan_local_project

router = APIRouter()

GRAPH_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def _get_validated_graph_name() -> str:
    name = settings.falkordb_graph
    if not name or not GRAPH_NAME_RE.match(name):
        raise HTTPException(
            status_code=500,
            detail={"error": "invalid_graph_name", "message": f"Configured graph name '{name}' is invalid."},
        )
    return name


class ScanRequest(BaseModel):
    source: str = Field(description="'fixture' or 'local'")
    path: str | None = Field(default=None, description="Path to local repository when source='local'")


def _require_graph():
    client = create_redis_client()
    probe = probe_falkordb(client)
    if not probe.connected:
        client.close()
        raise HTTPException(
            status_code=503,
            detail={"error": "falkordb_unavailable", "mcp_required": False},
        )
    return client


def _scan_coverage(graph: FalkorGraph) -> dict:
    project_rows = graph.query("MATCH (pr:Project) RETURN pr.name AS name, pr.root_label AS root_label LIMIT 1")
    project_name = project_rows[0].get("name", "demo-app") if project_rows else "demo-app"
    root_label = project_rows[0].get("root_label", "demo-app") if project_rows else "demo-app"

    pkg_rows = graph.query("MATCH (p:Package) RETURN count(p) AS n")
    packages_count = int(pkg_rows[0].get("n") or 0) if pkg_rows else 0

    file_rows = graph.query("MATCH (f:File) RETURN count(f) AS n")
    files_count = int(file_rows[0].get("n") or 0) if file_rows else 0

    entry_rows = graph.query("MATCH (e:EntryPoint) RETURN count(e) AS n")
    entries_count = int(entry_rows[0].get("n") or 0) if entry_rows else 0

    return {
        "project_name": project_name,
        "root_label": root_label,
        "packages_scanned": packages_count,
        "files_scanned": files_count,
        "entry_points_scanned": entries_count,
    }


@router.post("/api/scans")
def create_scan(body: ScanRequest):
    if body.source not in ("fixture", "local"):
        raise HTTPException(
            status_code=400,
            detail={"error": "unsupported_source", "allowed": ["fixture", "local"]},
        )

    if body.source == "local" and not (body.path and str(body.path).strip()):
        raise HTTPException(
            status_code=400,
            detail={"error": "missing_path", "message": "path is required when source='local'"},
        )

    graph_name = _get_validated_graph_name()
    client = _require_graph()
    try:
        if body.source == "fixture":
            model = load_demo_fixture()
            scan_id = "scan-demo-fixture"
        else:
            try:
                model = scan_local_project(body.path)
            except ProjectScanError as exc:
                raise HTTPException(
                    status_code=400,
                    detail={"error": exc.code, "message": exc.message},
                ) from exc
            scan_id = f"scan-local-{uuid4().hex[:12]}"

        # Clear prior scan graph data to isolate each scan session cleanly
        FalkorGraph(client, graph_name).delete()

        upsert_fixture_graph(client, graph_name, model, scan_id=scan_id)
        graph = FalkorGraph(client, graph_name)
        findings = list_findings(graph)
        coverage = _scan_coverage(graph)

        osv_warnings = []
        osv_errors = model.get("osv_errors") or []
        if isinstance(osv_errors, dict):
            error_items = osv_errors.items()
        elif isinstance(osv_errors, list):
            error_items = [(e.get("key", "unknown"), e.get("message", str(e))) for e in osv_errors if isinstance(e, dict)]
        else:
            error_items = []
        for pkg_key, err_msg in error_items:
            osv_warnings.append(f"Advisory lookup warning for {pkg_key}: {err_msg}")

        return {
            "scan_id": scan_id,
            "status": "complete",
            "fixture": bool(model.get("fixture", False)),
            "label": model["label"],
            "graph": graph_name,
            "finding_count": len(findings),
            "coverage": coverage,
            "warnings": osv_warnings,
        }
    finally:
        client.close()


def _is_true(val: Any) -> bool:
    if val is True:
        return True
    if val is False or val is None:
        return False
    return str(val).lower() in ("true", "1")


@router.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    graph_name = _get_validated_graph_name()
    client = _require_graph()
    try:
        graph = FalkorGraph(client, graph_name)
        rows = graph.query(
            "MATCH (s:Scan {scan_id: $scan_id}) RETURN s.scan_id AS scan_id, s.status AS status, s.fixture AS fixture, s.label AS label",
            {"scan_id": scan_id},
        )
        if not rows:
            raise HTTPException(status_code=404, detail={"error": "scan_not_found"})
        row = rows[0]
        findings = list_findings(graph)
        coverage = _scan_coverage(graph)
        return {
            "scan_id": row.get("scan_id"),
            "status": row.get("status"),
            "fixture": _is_true(row.get("fixture")),
            "label": row.get("label"),
            "finding_count": len(findings),
            "coverage": coverage,
        }
    finally:
        client.close()


@router.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str):
    graph_name = _get_validated_graph_name()
    client = _require_graph()
    try:
        graph = FalkorGraph(client, graph_name)
        rows = graph.query(
            "MATCH (s:Scan {scan_id: $scan_id}) RETURN s.scan_id AS scan_id, s.fixture AS fixture",
            {"scan_id": scan_id},
        )
        if not rows:
            raise HTTPException(status_code=404, detail={"error": "scan_not_found"})
        is_fixture = _is_true(rows[0].get("fixture"))
        return {"scan_id": scan_id, "fixture": is_fixture, "findings": list_findings(graph)}
    finally:
        client.close()


@router.get("/api/findings/{finding_id}/paths")
def get_paths(finding_id: str):
    graph_name = _get_validated_graph_name()
    client = _require_graph()
    try:
        graph = FalkorGraph(client, graph_name)
        paths = finding_paths(graph, finding_id)
        return {
            "finding_id": finding_id,
            "paths": paths,
            "path_count": len(paths),
            "evidence_note": "no_path_found is not the same as safe.",
        }
    finally:
        client.close()


@router.get("/api/scans/{scan_id}/remediations")
def get_remediations(scan_id: str):
    graph_name = _get_validated_graph_name()
    client = _require_graph()
    try:
        graph = FalkorGraph(client, graph_name)
        rows = graph.query(
            "MATCH (s:Scan {scan_id: $scan_id}) RETURN s.scan_id AS scan_id",
            {"scan_id": scan_id},
        )
        if not rows:
            raise HTTPException(status_code=404, detail={"error": "scan_not_found"})
        candidates = list_upgrade_candidates(graph)
        return {
            "scan_id": scan_id,
            "remediation_candidates": candidates,
            "candidate_count": len(candidates),
        }
    finally:
        client.close()

