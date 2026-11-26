"""Open read-only backups of available legacy databases with the new factory.

Only temporary copies are modified. If no runtime database exists, reports skip.
"""
from pathlib import Path
import sqlite3
from contextlib import closing
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "soc_server"))
from config import Config
from app import create_app
from app.extensions import db
from app.models import User, Alert, KnowledgeArticle


class UpgradeCompatibilityTests(unittest.TestCase):
    def test_existing_database_copies_keep_data_and_render(self):
        sources = list((ROOT / "soc_server" / "instance").glob("*.db"))
        if not sources:
            self.skipTest("No legacy runtime database available")
        for source in sources:
            with self.subTest(database=source.name), tempfile.TemporaryDirectory(prefix="soc_upgrade_") as directory:
                target = Path(directory) / "copy.db"
                with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as old, closing(sqlite3.connect(target)) as copy:
                    old.backup(copy)
                    counts = {table: copy.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                              for table in ("users", "log_events", "alerts", "knowledge_articles")}
                class C(Config):
                    TESTING = True
                    ANTHROPIC_API_KEY = None
                    SQLALCHEMY_DATABASE_URI = "sqlite:///" + target.as_posix()
                app = create_app(C, start_background=False)
                with app.app_context():
                    for table, expected in counts.items():
                        actual = db.session.execute(db.text("SELECT COUNT(*) FROM " + table)).scalar()
                        self.assertEqual(actual, expected, table)
                    self.assertIsNotNone(db.inspect(db.engine).get_columns("work_jobs"))
                    admin = User.query.filter_by(role="admin").first()
                    with app.test_client() as client:
                        with client.session_transaction() as session:
                            session["user_id"] = admin.id
                        paths = ["/", "/operations", "/kb", "/reports", "/api/v1/health"]
                        alert = Alert.query.first()
                        article = KnowledgeArticle.query.first()
                        if alert:
                            paths.append("/alerts/%d" % alert.id)
                        if article:
                            paths.append("/kb/%d" % article.id)
                        for path in paths:
                            self.assertEqual(client.get(path).status_code, 200, path)
                    print("Legacy copy verified:", source.name, counts)
                    db.session.remove()
                    db.engine.dispose()


if __name__ == "__main__":
    unittest.main(verbosity=2)
