from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.effectiveness import build_detection_effectiveness

router = APIRouter(prefix="/api/v1/detection-effectiveness", tags=["detection effectiveness"])


@router.get("")
def detection_effectiveness(db: Annotated[Session, Depends(get_db, scope="function")]) -> dict:
    return build_detection_effectiveness(db)
