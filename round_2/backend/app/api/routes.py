"""API routes for PyShield."""
from fastapi import APIRouter, HTTPException, BackgroundTasks, Request, Depends
from datetime import datetime, timezone
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
import uuid
import json

from app.logging_config import get_logger
from app.utils.errors import sanitize_error_message, get_safe_error_detail
from app.api.schemas import (
    AuditRequest,
    AuditStartResponse,
    AuditStatusResponse,
    AuditReport,
    AuditStatus,
    HealthResponse,
    PackageMetadata,
)
from app.config import settings
from app.services.orchestrator import AuditOrchestrator
from app.services.pypi_client import PyPIClient
from app.utils.validation import validate_package_name, validate_version, ValidationError
from app.db.database import get_db, async_session
from app.db.models import Audit

logger = get_logger(__name__)

router = APIRouter()

# Import limiter from main (will be set via app.state)
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        timestamp=datetime.now(timezone.utc),
    )


@router.post("/audit", response_model=AuditStartResponse)
@limiter.limit("10/hour")
async def start_audit(request: Request, audit_request: AuditRequest, background_tasks: BackgroundTasks):
    """Start a security audit for a PyPI package.

    Rate limit: 10 audits per IP per hour.
    """
    # Validate inputs
    try:
        package_name = validate_package_name(audit_request.package_name)
        version = validate_version(audit_request.version)
    except ValidationError as e:
        logger.warning(f"Invalid audit request: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    audit_id = str(uuid.uuid4())

    # Create audit record in database
    async with async_session() as db:
        audit = Audit(
            id=audit_id,
            package_name=package_name,
            package_version=version,
            status=AuditStatus.QUEUED.value,
            progress=0,
        )
        db.add(audit)
        await db.commit()
        logger.info(f"Created audit {audit_id} for {package_name}@{version or 'latest'}")

    # Run audit in background
    background_tasks.add_task(run_audit, audit_id, package_name, version)

    return AuditStartResponse(
        audit_id=audit_id,
        status=AuditStatus.QUEUED,
        message=f"Audit queued for package: {package_name}",
    )


async def run_audit(audit_id: str, package_name: str, version: str = None):
    """Run the audit in the background."""
    try:
        # Update status to processing
        async with async_session() as db:
            result = await db.execute(select(Audit).where(Audit.id == audit_id))
            audit = result.scalar_one_or_none()
            if not audit:
                logger.error(f"Audit {audit_id} not found in database")
                return

            audit.status = AuditStatus.PROCESSING.value
            audit.started_at = datetime.now(timezone.utc)
            await db.commit()
            logger.info(f"Started processing audit {audit_id}")

        # Create orchestrator and run audit
        orchestrator = AuditOrchestrator()

        # Update progress callback (synchronous wrapper for async DB operations)
        def on_progress(analyzer_name: str, completed: list, progress: int):
            # Schedule async DB update without blocking
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Create task but don't await (fire and forget)
                    asyncio.create_task(update_progress_in_db(audit_id, analyzer_name, progress))
            except RuntimeError:
                # If no event loop, skip progress update
                pass

        async def update_progress_in_db(aid: str, analyzer: str, prog: int):
            """Update progress in database asynchronously."""
            async with async_session() as db:
                result = await db.execute(select(Audit).where(Audit.id == aid))
                audit = result.scalar_one_or_none()
                if audit:
                    audit.current_analyzer = analyzer
                    audit.progress = prog
                    await db.commit()

        report = await orchestrator.run_audit(
            package_name=package_name,
            version=version,
            on_progress=on_progress,
        )

        # Store completed audit
        async with async_session() as db:
            result = await db.execute(select(Audit).where(Audit.id == audit_id))
            audit = result.scalar_one_or_none()
            if audit:
                audit.status = AuditStatus.COMPLETED.value
                audit.progress = 100
                audit.overall_score = report.overall_score
                audit.risk_level = report.risk_level.value
                audit.report_data = json.loads(report.model_dump_json())  # Serialize report to JSON
                audit.completed_at = datetime.now(timezone.utc)
                await db.commit()
                logger.info(f"Completed audit {audit_id}: score={report.overall_score}, risk={report.risk_level.value}")

    except Exception as e:
        logger.error(f"Audit {audit_id} failed: {e}", exc_info=True)
        async with async_session() as db:
            result = await db.execute(select(Audit).where(Audit.id == audit_id))
            audit = result.scalar_one_or_none()
            if audit:
                audit.status = AuditStatus.FAILED.value
                audit.error_message = str(e)
                audit.completed_at = datetime.now(timezone.utc)
                await db.commit()


@router.get("/audit/{audit_id}", response_model=AuditStatusResponse)
async def get_audit_status(audit_id: str):
    """Get the status of an audit."""
    async with async_session() as db:
        result = await db.execute(select(Audit).where(Audit.id == audit_id))
        audit = result.scalar_one_or_none()

        if not audit:
            logger.warning(f"Audit {audit_id} not found")
            raise HTTPException(status_code=404, detail="Audit not found")

        return AuditStatusResponse(
            audit_id=audit_id,
            status=AuditStatus(audit.status),
            progress=audit.progress,
            current_analyzer=audit.current_analyzer,
            completed_analyzers=[],  # Not tracking this in DB currently
            error_message=audit.error_message,
        )


@router.get("/audit/{audit_id}/report", response_model=AuditReport)
async def get_audit_report(audit_id: str):
    """Get the full audit report."""
    async with async_session() as db:
        result = await db.execute(select(Audit).where(Audit.id == audit_id))
        audit = result.scalar_one_or_none()

        if not audit:
            logger.warning(f"Report requested for non-existent audit {audit_id}")
            raise HTTPException(status_code=404, detail="Audit not found")

        if audit.status != AuditStatus.COMPLETED.value:
            raise HTTPException(
                status_code=400,
                detail=f"Audit not completed. Current status: {audit.status}",
            )

        if not audit.report_data:
            logger.error(f"Audit {audit_id} completed but report_data is missing")
            raise HTTPException(status_code=404, detail="Report not available")

        # Deserialize report from JSON
        return AuditReport(**audit.report_data)


@router.get("/audit/{audit_id}/sbom")
async def get_audit_sbom(audit_id: str):
    """Get SBOM (CycloneDX format) for completed audit."""
    from fastapi.responses import JSONResponse

    async with async_session() as db:
        result = await db.execute(select(Audit).where(Audit.id == audit_id))
        audit = result.scalar_one_or_none()

        if not audit:
            logger.warning(f"SBOM requested for non-existent audit {audit_id}")
            raise HTTPException(status_code=404, detail="Audit not found")

        if audit.status != AuditStatus.COMPLETED.value:
            raise HTTPException(
                status_code=400,
                detail=f"Audit not completed. Current status: {audit.status}",
            )

        if not audit.report_data:
            raise HTTPException(status_code=404, detail="Report not available")

        # Deserialize report
        report = AuditReport(**audit.report_data)

        # Generate SBOM
        from app.services.sbom_generator import SBOMGenerator

        try:
            logger.debug(f"Generating SBOM for audit {audit_id}")
            generator = SBOMGenerator()
            sbom_dict = generator.generate_sbom(report)

            package_name = report.package_name
            package_version = report.package_version
            filename = f"pyshield-sbom-{package_name}-{package_version}.cdx.json"

            return JSONResponse(
                content=sbom_dict,
                media_type="application/vnd.cyclonedx+json",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                }
            )
        except Exception as e:
            logger.error(f"Failed to generate SBOM for audit {audit_id}: {e}", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=sanitize_error_message(e, "Failed to generate SBOM")
            )


@router.get("/package/{package_name}", response_model=PackageMetadata)
async def get_package_info(package_name: str, version: str = None):
    """Get package metadata from PyPI."""
    # Validate inputs
    try:
        package_name = validate_package_name(package_name)
        version = validate_version(version)
    except ValidationError as e:
        # Validation errors are safe to expose
        raise HTTPException(status_code=400, detail=str(e))

    client = PyPIClient()
    try:
        metadata = await client.get_package_metadata(package_name, version)
        return metadata
    except Exception as e:
        logger.error(f"Failed to fetch package info for {package_name}: {e}")
        raise HTTPException(
            status_code=404,
            detail=get_safe_error_detail(e, "package fetch")
        )


@router.get("/audits")
async def list_audits(limit: int = 20):
    """List recent audits."""
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 100")

    async with async_session() as db:
        result = await db.execute(
            select(Audit)
            .order_by(desc(Audit.created_at))
            .limit(limit)
        )
        audits = result.scalars().all()

        return [
            {
                "id": audit.id,
                "package_name": audit.package_name,
                "version": audit.package_version,
                "status": audit.status,
                "progress": audit.progress,
                "overall_score": audit.overall_score,
                "risk_level": audit.risk_level,
                "created_at": audit.created_at,
                "completed_at": audit.completed_at,
            }
            for audit in audits
        ]
