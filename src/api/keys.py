"""
API Key management endpoints.

These endpoints use JWT cookie authentication (for the UI) and allow users
to create, list, and revoke their API keys for use with the public API.
"""
from typing import Optional

from fastapi import Depends
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse
from utils.logging_config import get_logger

from dependencies import get_api_key_service, get_current_user
from session_manager import User

logger = get_logger(__name__)


class CreateKeyBody(BaseModel):
    name: str = Field(..., max_length=100, description="Name for the API key")
    # Optional override of the user_id stored on the key. When set, the
    # minted key will resolve (via get_api_key_user_async) to a User with
    # this user_id rather than the user who minted it. Used by recall to
    # mint per-agent keys whose identity matches the agent slug, so the
    # /v1/search endpoint can enforce per-tenant scoping (DLS) without
    # the model needing to inject filters.
    key_user_id: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Override the user_id stored on the key (multi-tenant)",
    )
    key_user_email: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Override the email stored on the key",
    )


async def list_keys_endpoint(
    api_key_service=Depends(get_api_key_service),
    user: User = Depends(get_current_user),
):
    """
    List all API keys for the authenticated user.

    GET /keys
    """
    result = await api_key_service.list_keys(user.user_id, user.jwt_token)
    return JSONResponse(result)


async def create_key_endpoint(
    body: CreateKeyBody,
    api_key_service=Depends(get_api_key_service),
    user: User = Depends(get_current_user),
):
    """
    Create a new API key for the authenticated user.

    POST /keys
    Body: {"name": "My API Key"}
    """
    try:
        name = body.name.strip()
        if not name:
            return JSONResponse(
                {"success": False, "error": "Name is required"},
                status_code=400,
            )

        # If the caller supplied an override (key_user_id), the minted key
        # will carry that as its identity instead of the minter's. The
        # minter still has to be authenticated — we just relabel what the
        # key resolves to. JWT for OpenSearch indexing stays the minter's.
        effective_user_id = body.key_user_id or user.user_id
        effective_user_email = body.key_user_email or user.email

        result = await api_key_service.create_key(
            user_id=effective_user_id,
            user_email=effective_user_email,
            name=name,
            jwt_token=user.jwt_token,
        )

        if result.get("success"):
            return JSONResponse(result)
        else:
            return JSONResponse(result, status_code=500)

    except Exception as e:
        logger.error("Failed to create API key", error=str(e), user_id=user.user_id)
        return JSONResponse(
            {"success": False, "error": str(e)},
            status_code=500,
        )


async def revoke_key_endpoint(
    key_id: str,
    api_key_service=Depends(get_api_key_service),
    user: User = Depends(get_current_user),
):
    """
    Revoke an API key.

    DELETE /keys/{key_id}
    """
    result = await api_key_service.revoke_key(
        user_id=user.user_id,
        key_id=key_id,
        jwt_token=user.jwt_token,
    )

    if result.get("success"):
        return JSONResponse(result)
    elif result.get("error") == "Not authorized to revoke this key":
        return JSONResponse(result, status_code=403)
    elif result.get("error") == "Key not found":
        return JSONResponse(result, status_code=404)
    else:
        return JSONResponse(result, status_code=500)


async def delete_key_endpoint(
    key_id: str,
    api_key_service=Depends(get_api_key_service),
    user: User = Depends(get_current_user),
):
    """
    Permanently delete an API key.

    DELETE /keys/{key_id}/permanent
    """
    result = await api_key_service.delete_key(
        user_id=user.user_id,
        key_id=key_id,
        jwt_token=user.jwt_token,
    )

    if result.get("success"):
        return JSONResponse(result)
    elif result.get("error") == "Not authorized to delete this key":
        return JSONResponse(result, status_code=403)
    elif result.get("error") == "Key not found":
        return JSONResponse(result, status_code=404)
    else:
        return JSONResponse(result, status_code=500)
