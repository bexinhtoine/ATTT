"""Incident integration checks: membership, evidence, RBAC, CSRF and stale writes."""
from datetime import timedelta
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "soc_server"))
from config import Config
from app import create_app
from app.extensions import db
from app.incidents import correlation_reason
from app.models import (Alert, AlertEvent, AuditLog, Incident, IncidentAlert, IncidentActivity,
                        LogEvent, User, utcnow)


class IncidentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="soc_incident_")
        class C(Config):
            TESTING = True
            ANTHROPIC_API_KEY = None
            OPENAI_API_KEY = None
            SQLALCHEMY_DATABASE_URI = "sqlite:///" + (Path(cls.temp.name) / "test.db").as_posix()
        cls.app = create_app(C, start_background=False)

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.session.remove()
            db.engine.dispose()
        cls.temp.cleanup()

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        for model in (IncidentActivity, IncidentAlert, Incident, AlertEvent, Alert, LogEvent):
            model.query.delete()
        now = utcnow()
        self.alerts = []
        for i in range(4):
            a = Alert(title="Alert %s" % i, host="lab01", user_name="alice", src_ip="203.0.113.10",
                      first_event_time=now + timedelta(seconds=i), last_event_time=now + timedelta(seconds=i),
                      severity="high", status="new")
            db.session.add(a)
            db.session.flush()
            self.alerts.append(a.id)
        event = LogEvent(event_time=now, action="logon_failed", host="lab01", message="<script>unsafe</script>")
        db.session.add(event)
        db.session.flush()
        for aid in self.alerts[:2]:
            db.session.add(AlertEvent(alert_id=aid, event_id=event.id))
        self.event_id = event.id
        db.session.commit()
        self.client = self.as_role("analyst")

    def tearDown(self):
        db.session.remove()
        self.ctx.pop()

    def as_role(self, role):
        client = self.app.test_client()
        user = User.query.filter_by(role=role).first()
        with client.session_transaction() as session:
            session["user_id"] = user.id
            session["_csrf_token"] = "test-csrf"
        return client

    def post(self, path, data=None, client=None):
        return (client or self.client).post(path, data={"_csrf_token": "test-csrf", **(data or {})})

    def create(self, ids):
        result = self.post("/incidents/create", {"alert_ids": ids, "title": "Điều tra", "reason": "Xác minh chuỗi"})
        self.assertEqual(result.status_code, 302, result.data)
        return int(result.location.rsplit("/", 1)[-1])

    def test_create_timeline_suggestions_and_escaped_content(self):
        iid = self.create(self.alerts[:2])
        page = self.client.get("/incidents/%s" % iid)
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.data.count(('>#%s logon_failed' % self.event_id).encode()), 1)
        self.assertNotIn(b"<script>unsafe</script>", page.data)
        self.assertIn(b"&lt;script&gt;unsafe&lt;/script&gt;", page.data)
        self.assertIn(b"X\xc3\xa1c nh\xe1\xba\xadn li\xc3\xaan k\xe1\xba\xbft", page.data)
        self.assertEqual(self.client.get("/incidents").status_code, 200)
        self.assertEqual(self.client.get("/alerts/%s" % self.alerts[0]).status_code, 200)
        self.assertEqual(db.session.get(Alert, self.alerts[0]).status, "new")

    def test_shared_ip_and_conflicting_entities_not_suggested(self):
        left, right = [db.session.get(Alert, aid) for aid in self.alerts[:2]]
        self.assertTrue(correlation_reason(left, right))
        right.host = "other-host"
        self.assertIsNone(correlation_reason(left, right))
        right.host, right.user_name = left.host, "bob"
        self.assertIsNone(correlation_reason(left, right))
        right.user_name, right.src_ip = left.user_name, "203.0.113.99"
        self.assertIsNone(correlation_reason(left, right))
        right.src_ip = left.src_ip
        right.last_event_time = left.first_event_time + timedelta(minutes=31)
        self.assertIsNone(correlation_reason(left, right))
        right.last_event_time, right.user_name = left.last_event_time, None
        self.assertIsNone(correlation_reason(right, left))

    def test_link_split_merge_and_audit(self):
        iid = self.create(self.alerts[:1])
        self.assertEqual(self.post("/incidents/%s/link" % iid, {"alert_ids": self.alerts[1:3], "reason": "Cùng chuỗi", "version": 1}).status_code, 302)
        result = self.post("/incidents/%s/split" % iid, {"alert_ids": [self.alerts[2]], "title": "Nhánh riêng", "reason": "Khác sự cố", "version": 2})
        self.assertEqual(result.status_code, 302, result.data)
        target = int(result.location.rsplit("/", 1)[-1])
        self.assertEqual(db.session.get(IncidentAlert, self.alerts[2]).incident_id, target)
        result = self.post("/incidents/%s/merge" % target, {"target_id": iid, "version": 1, "target_version": 3, "reason": "Đã xác minh cùng vụ"})
        self.assertEqual(result.status_code, 302, result.data)
        db.session.expire_all()
        self.assertEqual(db.session.get(Incident, target).merged_into_id, iid)
        self.assertEqual(IncidentAlert.query.filter_by(incident_id=iid).count(), 3)
        self.assertEqual(IncidentActivity.query.filter_by(action="merge").count(), 2)
        self.assertGreaterEqual(AuditLog.query.filter(AuditLog.action.like("incident_%")).count(), 1)

    def test_duplicate_membership_and_stale_changes(self):
        iid = self.create(self.alerts[:1])
        self.assertEqual(self.post("/incidents/create", {"alert_ids": self.alerts[:1], "reason": "duplicate"}).status_code, 409)
        self.assertEqual(self.post("/incidents/%s/note" % iid, {"version": 1, "note": "Lần 1"}).status_code, 302)
        self.assertEqual(self.post("/incidents/%s/note" % iid, {"version": 1, "note": "Ghi đè cũ"}).status_code, 409)
        self.assertEqual(IncidentActivity.query.filter_by(action="note").count(), 1)

    def test_validation_and_closed_incident(self):
        iid = self.create(self.alerts[:1])
        self.assertEqual(self.post("/incidents/%s/update" % iid, {"version": 1, "title": "Done", "status": "closed", "severity": "high", "assigned_to": "invalid"}).status_code, 400)
        analyst = User.query.filter_by(role="analyst").first()
        result = self.post("/incidents/%s/update" % iid, {"version": 1, "title": "Done", "status": "closed", "severity": "high", "assigned_to": analyst.id, "summary": "Đã kiểm tra"})
        self.assertEqual(result.status_code, 302)
        self.assertEqual(self.post("/incidents/%s/link" % iid, {"version": 2, "alert_ids": self.alerts[1:2], "reason": "late"}).status_code, 409)
        self.assertEqual(IncidentAlert.query.filter_by(incident_id=iid).count(), 1)

    def test_viewer_csrf_and_anonymous(self):
        iid = self.create(self.alerts[:1])
        viewer = self.as_role("viewer")
        self.assertEqual(viewer.get("/incidents/%s" % iid).status_code, 200)
        for action in ("create", "%s/link" % iid, "%s/split" % iid, "%s/merge" % iid, "%s/update" % iid, "%s/note" % iid):
            self.assertEqual(self.post("/incidents/" + action, client=viewer).status_code, 403)
        self.assertEqual(self.client.post("/incidents/create", data={"alert_ids": self.alerts[:1], "reason": "CSRF"}).status_code, 403)
        self.assertEqual(self.app.test_client().get("/incidents").status_code, 302)


if __name__ == "__main__":
    unittest.main(verbosity=2)
