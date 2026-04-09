"""
Public API v1 Search endpoint.

Provides semantic search functionality.
Uses API key authentication.
"""
from typing import Any, Dict, Optional

from fastapi import Depends
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from utils.logging_config import get_logger
from utils.opensearch_utils import OpenSearchDiskSpaceError, DISK_SPACE_ERROR_MESSAGE
from dependencies import get_search_service, get_api_key_user_async
from session_manager import User

logger = get_logger(__name__)


class SearchV1Body(BaseModel):
    query: str
    filters: Optional[Dict[str, Any]] = None
    limit: int = 10
    score_threshold: float = 0


async def search_endpoint(
    body: SearchV1Body,
    search_service=Depends(get_search_service),
    user: User = Depends(get_api_key_user_async),
):
    """Perform semantic search on documents. POST /v1/search"""
    query = body.query.strip()
    if not query:
        return JSONResponse({"error": "Query is required"}, status_code=400)

    logger.debug(
        "Public API search request",
        user_id=user.user_id,
        query=query,
        filters=body.filters,
        limit=body.limit,
        score_threshold=body.score_threshold,
    )

    # ----- Server-side tenant scoping (DLS) ---------------------------------
    #
    # Force-inject `allowed_users = [user.user_id]` so the calling API key
    # can ONLY retrieve chunks tagged with its own user_id. This is the
    # security boundary for multi-tenant deployments — the caller cannot
    # widen this filter (we overwrite anything they sent), and they cannot
    # remove it (we always set it).
    #
    # Anonymous keys (user_id == "anonymous") are exempt: they keep the
    # legacy "see everything that wasn't tenant-tagged" behavior so single-
    # user deployments are unaffected.
    enforced_filters = dict(body.filters or {})
    if user.user_id and user.user_id != "anonymous":
        enforced_filters["allowed_users"] = [user.user_id]
        logger.debug(
            "DLS: forcing allowed_users filter from API key user_id",
            user_id=user.user_id,
        )

    try:
        result = await search_service.search(
            query,
            user_id=user.user_id,
            jwt_token=None,  # API key auth has no JWT
            filters=enforced_filters,
            limit=body.limit,
            score_threshold=body.score_threshold,
        )

        results = [
            {
                "filename": item.get("filename"),
                "text": item.get("text"),
                "score": item.get("score"),
                "page": item.get("page"),
                "mimetype": item.get("mimetype"),
            }
            for item in result.get("results", [])
        ]

        return JSONResponse({"results": results})

    except OpenSearchDiskSpaceError as e:
        logger.error("Search blocked by disk space constraint", error=str(e), user_id=user.user_id)
        return JSONResponse({"error": DISK_SPACE_ERROR_MESSAGE}, status_code=507)
    except Exception as e:
        error_msg = str(e)
        logger.error("Search failed", error=error_msg, user_id=user.user_id)
        if "AuthenticationException" in error_msg or "access denied" in error_msg.lower():
            return JSONResponse({"error": error_msg}, status_code=403)
        else:
            return JSONResponse({"error": error_msg}, status_code=500)
