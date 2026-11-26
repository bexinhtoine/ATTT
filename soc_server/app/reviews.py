"""Analyst decisions are versioned independently from generated suggestions."""
from .extensions import db
from .models import Alert, AlertReview, KnowledgeReview, dumps, utcnow


def claim_alert_revision(alert):
    """Acquire the write revision before editing; fail if another writer won."""
    changed = Alert.query.filter(Alert.id == alert.id, Alert.updated_at == alert.updated_at).update(
        {"updated_at": utcnow()}, synchronize_session=False)
    if changed:
        db.session.refresh(alert)
    return bool(changed)


def record_alert_review(alert, username):
    review = db.session.get(AlertReview, alert.id)
    if review is None:
        review = AlertReview(alert_id=alert.id)
        db.session.add(review)
        review.revision = 0
    review.revision += 1
    review.reviewed_by, review.reviewed_at = username, utcnow()
    review.decision = dumps({"status": alert.status, "severity": alert.severity,
                             "priority": alert.priority, "note": alert.resolution_note,
                             "assigned_to": alert.assigned_to})
    return review


def edit_knowledge_review(article, username, approve=False):
    review = article.review
    if review is None:
        review = KnowledgeReview(article=article, revision=0)
        db.session.add(review)
    review.revision += 1
    review.status = "approved" if approve else "draft"
    review.reviewed_by = username if approve else None
    review.reviewed_at = utcnow() if approve else None
    return review
