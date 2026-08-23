"""Deterministic validation for the Butian catalog and URL prefilter pipeline."""
from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# ============================ Configuration zone ============================
ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "projects" / "butian-welfare-20260803"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "butian-src"
# ============================================================================

SPEC = importlib.util.spec_from_file_location(
    "butian_src_pipeline", PROJECT / "butian_src_pipeline.py"
)
assert SPEC and SPEC.loader
PIPELINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PIPELINE)


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.status_code = 200
        self.headers = {"content-type": "application/json; charset=utf-8"}

    def json(self) -> dict:
        return self.payload

    def close(self) -> None:
        return None


class FakeCatalogSession:
    def __init__(self, pages: dict[int, dict]) -> None:
        self.pages = pages
        self.headers: dict[str, str] = {}
        self.calls: list[int] = []

    def get(self, _url: str, *, params: dict, **_kwargs: object) -> FakeResponse:
        page = int(params["p"])
        self.calls.append(page)
        return FakeResponse(self.pages[page])


def fixture_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def root_probe(**overrides: object) -> dict:
    probe = {
        "requested_url": "https://example.com/",
        "final_url": "https://example.com/",
        "status_code": 200,
        "content_type": "text/html; charset=utf-8",
        "server": "",
        "set_cookie": False,
        "redirect_chain": ["https://example.com/"],
        "body": "",
        "error": None,
    }
    probe.update(overrides)
    return probe


class ButianPipelineTests(unittest.TestCase):
    def test_catalog_checkpoint_and_resume(self) -> None:
        pages = {
            1: fixture_json("catalog-page-1.json"),
            2: fixture_json("catalog-page-2.json"),
        }
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            args = argparse.Namespace(
                dry_run=False,
                run_dir=str(run_dir),
                db=None,
                min_interval=0.0,
                start_page=1,
                page_limit=2,
                resume=False,
                timeout=1.0,
            )
            session = FakeCatalogSession(pages)
            with patch.object(PIPELINE, "make_http_session", return_value=session):
                self.assertEqual(PIPELINE.command_catalog(args), 0)
            self.assertEqual(session.calls, [1, 2])
            rows = [
                json.loads(line)
                for line in (run_dir / "catalog.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(row["source"] == "butian_public_catalog" for row in rows))

            resumed_session = FakeCatalogSession(pages)
            args.resume = True
            with patch.object(PIPELINE, "make_http_session", return_value=resumed_session):
                self.assertEqual(PIPELINE.command_catalog(args), 0)
            self.assertEqual(resumed_session.calls, [])

    def test_catalog_stops_when_server_repeats_last_page(self) -> None:
        first = fixture_json("catalog-page-1.json")
        second = fixture_json("catalog-page-2.json")
        first["data"]["count"] = 3
        second["data"]["count"] = 3
        repeated = json.loads(json.dumps(second))
        repeated["data"]["current"] = 3
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            args = argparse.Namespace(
                dry_run=False,
                run_dir=str(run_dir),
                db=None,
                min_interval=0.0,
                start_page=1,
                page_limit=3,
                resume=False,
                timeout=1.0,
            )
            session = FakeCatalogSession({1: first, 2: second, 3: repeated})
            with patch.object(PIPELINE, "make_http_session", return_value=session):
                self.assertEqual(PIPELINE.command_catalog(args), 0)
            self.assertEqual(session.calls, [1, 2, 3])
            self.assertEqual(
                len((run_dir / "catalog.jsonl").read_text(encoding="utf-8").splitlines()),
                3,
            )

    def test_official_scope_extraction_keeps_include_and_exclude_separate(self) -> None:
        html = (FIXTURES / "submit-scope.html").read_text(encoding="utf-8")
        candidates = PIPELINE.extract_scoped_text_candidates(html, "fixture")
        by_url = {item["normalized_url"]: item["scope"] for item in candidates}
        self.assertEqual(by_url["https://portal.example.com/"], "include")
        self.assertEqual(by_url["https://api.example.com/v1"], "include")
        self.assertEqual(by_url["https://legacy.example.com/"], "exclude")

        json_candidates = PIPELINE.extract_scoped_json_candidates(
            {
                "assets": [
                    {"scope": "include", "url": "https://inside.example.com"},
                    {"scope": "exclude", "url": "https://outside.example.com"},
                ]
            }
        )
        json_by_url = {item["normalized_url"]: item["scope"] for item in json_candidates}
        self.assertEqual(json_by_url["https://inside.example.com/"], "include")
        self.assertEqual(json_by_url["https://outside.example.com/"], "exclude")

    def test_scope_text_ignores_scripts_navigation_and_unlabelled_links(self) -> None:
        html = (FIXTURES / "submit-page-noise.html").read_text(encoding="utf-8")
        candidates = PIPELINE.extract_scoped_text_candidates(html, "fixture")
        self.assertEqual(
            {(item["normalized_url"], item["scope"]) for item in candidates},
            {("https://lingdayun.cn/", "include")},
        )
        self.assertEqual(
            PIPELINE.extract_scoped_json_candidates(
                {"domain": "https://unscoped.example.com"}
            ),
            [],
        )

    def test_prefilter_static_and_dynamic_decisions(self) -> None:
        static_metrics = PIPELINE.analyse_html(
            "https://example.com/",
            (FIXTURES / "static.html").read_text(encoding="utf-8"),
        )
        static_result = PIPELINE.classify_prefilter(
            root_probe(server="Netlify"), [static_metrics], 0
        )
        self.assertEqual(static_result["decision"], "drop")

        dynamic_metrics = PIPELINE.analyse_html(
            "https://example.com/",
            (FIXTURES / "dynamic.html").read_text(encoding="utf-8"),
        )
        dynamic_result = PIPELINE.classify_prefilter(
            root_probe(set_cookie=True), [dynamic_metrics], 0
        )
        self.assertEqual(dynamic_result["decision"], "keep")
        self.assertGreaterEqual(
            dynamic_result["functional_score"], PIPELINE.KEEP_FUNCTIONAL_SCORE
        )

        blocked = PIPELINE.classify_prefilter(root_probe(status_code=403), [], 0)
        self.assertEqual(blocked["decision"], "review")
        non_html = PIPELINE.classify_prefilter(
            root_probe(content_type="application/pdf"), [], 0
        )
        self.assertEqual(non_html["decision"], "drop")
        external = PIPELINE.classify_prefilter(
            root_probe(final_url="https://other.example/"), [], 0
        )
        self.assertEqual(external["decision"], "review")

    def test_feature_parser_ignores_script_source_text(self) -> None:
        metrics = PIPELINE.analyse_html(
            "https://example.com/",
            "<html><body><p>Small brochure.</p></body>"
            "<script>const words = '登录 订单 后台 api endpoint';</script></html>",
        )
        self.assertEqual(metrics["script_count"], 1)
        self.assertEqual(metrics["business_hits"], 0)
        self.assertLess(metrics["text_chars"], 100)

    def test_input_requires_official_source_and_normalizes_urls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "urls.txt"
            path.write_text("portal.example.com\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                PIPELINE.records_from_input(path, None)
            records = PIPELINE.records_from_input(path, "official_submit_page")
            self.assertEqual(records[0]["source"], "official_submit_page")
            self.assertEqual(
                PIPELINE.normalize_target_url("HTTPS://EXAMPLE.COM/?utm_source=x"),
                "https://example.com/",
            )
            self.assertFalse(PIPELINE.is_public_target("http://127.0.0.1/"))
            self.assertIsNone(PIPELINE.normalize_target_url("https://example.com:bad/"))

    def test_extract_without_session_is_explicitly_login_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = argparse.Namespace(
                run_dir=str(Path(temporary) / "run"),
                db=None,
                dry_run=False,
                auth_state=str(Path(temporary) / "missing-state.json"),
            )
            self.assertEqual(PIPELINE.command_extract(args), 3)

    def test_vnc_environment_uses_explicit_xauthority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cookie = Path(temporary) / "Xauthority"
            cookie.write_bytes(b"fixture-cookie")
            environment = PIPELINE.vnc_browser_environment(
                ":9", str(cookie), require_xauthority=True
            )
            self.assertEqual(environment["DISPLAY"], ":9")
            self.assertEqual(environment["XAUTHORITY"], str(cookie))
            with self.assertRaises(RuntimeError):
                PIPELINE.vnc_browser_environment(
                    ":9", str(cookie.parent / "missing"), require_xauthority=True
                )
        login_args = PIPELINE.build_parser().parse_args(["login", "--dry-run"])
        self.assertEqual(login_args.xauthority, PIPELINE.DEFAULT_XAUTHORITY)

    def test_catalog_page_mapping_hydrates_missing_cached_page(self) -> None:
        pages = {
            1: fixture_json("catalog-page-1.json"),
            2: fixture_json("catalog-page-2.json"),
        }
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            args = argparse.Namespace(
                dry_run=False, run_dir=str(run_dir), db=None, min_interval=0.0,
                start_page=1, page_limit=2, resume=False, timeout=1.0,
            )
            with patch.object(
                PIPELINE, "make_http_session", return_value=FakeCatalogSession(pages)
            ):
                self.assertEqual(PIPELINE.command_catalog(args), 0)
            connection = PIPELINE.open_database(run_dir / "state.sqlite")
            mappings = list(
                connection.execute(
                    "SELECT page_number, item_index, project_id FROM catalog_project_pages "
                    "ORDER BY page_number, item_index"
                )
            )
            self.assertEqual([(row["page_number"], row["item_index"]) for row in mappings], [(1, 1), (1, 2), (2, 1)])
            connection.execute("DELETE FROM catalog_project_pages WHERE page_number=1")
            connection.commit()
            connection.close()

            args.resume = True
            resumed = FakeCatalogSession(pages)
            with patch.object(PIPELINE, "make_http_session", return_value=resumed):
                self.assertEqual(PIPELINE.command_catalog(args), 0)
            self.assertEqual(resumed.calls, [1])

    def test_batch_tracks_pages_reuses_all_decisions_and_force_rechecks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            database = run_dir / "state.sqlite"
            auth_state = root / "state.json"
            auth_state.write_text("{}", encoding="utf-8")
            wiki_dir = root / "wiki" / "projects" / "butian-welfare-src-prefilter"
            connection = PIPELINE.open_database(database)
            now = PIPELINE.utc_now()
            for page in range(1, 7):
                project_id = str(9000 + page)
                fingerprint = f"fixture-{page}"
                connection.execute(
                    "INSERT INTO catalog_pages VALUES (?, ?, ?, ?, ?, ?, NULL)",
                    (page, 6, fingerprint, 1, "ok", now),
                )
                connection.execute(
                    "INSERT INTO catalog_projects VALUES (?, ?, ?, ?, ?, ?)",
                    (project_id, f"Company {page}", None, "{}", now, now),
                )
                connection.execute(
                    "INSERT INTO catalog_project_pages VALUES (?, ?, ?, ?, ?)",
                    (page, 1, project_id, fingerprint, now),
                )
                connection.execute(
                    "INSERT INTO extraction_results VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (project_id, f"Company {page}", "ok", "", 1, "", now),
                )
                connection.execute(
                    "INSERT INTO official_assets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        project_id,
                        f"https://page{page}.example.com/",
                        f"page{page}.example.com",
                        "url_or_domain",
                        "include",
                        "official_submit_page",
                        "high",
                        "fixture",
                        now,
                    ),
                )
            connection.commit()
            connection.close()

            calls: list[str] = []

            def fake_prefilter(_args: argparse.Namespace, url: str, _session: object, _limiter: object) -> dict:
                calls.append(url)
                decision = {2: "review", 3: "drop"}.get(int(url.split("page")[1].split(".")[0]), "keep")
                return {
                    "url": url,
                    "normalized_url": url,
                    "decision": decision,
                    "functional_score": 5 if decision == "keep" else 0,
                    "static_score": 4 if decision == "drop" else 0,
                    "complexity_score": 0,
                    "reasons": [f"fixture_{decision}"],
                    "analyzed_at": PIPELINE.utc_now(),
                    "root_status": 200,
                }

            base = [
                "batch", "--run-dir", str(run_dir), "--auth-state", str(auth_state),
                "--wiki-dir", str(wiki_dir), "--target-kept", "4", "--page-span", "3", "--resume",
                "--no-subdomain-discovery",
            ]
            with patch.object(PIPELINE, "command_catalog", return_value=0), patch.object(
                PIPELINE, "command_extract", return_value=0
            ), patch.object(PIPELINE, "prefilter_one_url", side_effect=fake_prefilter):
                self.assertEqual(PIPELINE.command_batch(PIPELINE.build_parser().parse_args(base)), 0)
            self.assertEqual(len(calls), 6)

            connection = PIPELINE.open_database(database)
            batch = connection.execute("SELECT * FROM batch_runs WHERE batch_id='batch-0001'").fetchone()
            self.assertEqual((batch["page_start"], batch["page_end"], batch["keep_count"]), (1, 6, 4))
            cursor = connection.execute("SELECT * FROM pipeline_cursor").fetchone()
            self.assertEqual(cursor["status"], "exhausted")
            decisions = {
                row["decision"] for row in connection.execute(
                    "SELECT decision FROM batch_url_records WHERE batch_id='batch-0001'"
                )
            }
            self.assertEqual(decisions, {"keep", "review", "drop"})
            connection.close()
            self.assertTrue((wiki_dir / "url-registry.csv").is_file())
            self.assertTrue((wiki_dir / "batch-0001-results.csv").is_file())
            self.assertTrue((wiki_dir / "batch-0001.md").is_file())

            repeat = base + ["--start-page", "1"]
            with patch.object(PIPELINE, "command_catalog", return_value=0), patch.object(
                PIPELINE, "command_extract", return_value=0
            ), patch.object(PIPELINE, "prefilter_one_url", side_effect=AssertionError("must reuse")):
                self.assertEqual(PIPELINE.command_batch(PIPELINE.build_parser().parse_args(repeat)), 0)
            self.assertEqual(len(calls), 6)

            forced = repeat + ["--force-recheck"]
            with patch.object(PIPELINE, "command_catalog", return_value=0), patch.object(
                PIPELINE, "command_extract", return_value=0
            ), patch.object(PIPELINE, "prefilter_one_url", side_effect=fake_prefilter):
                self.assertEqual(PIPELINE.command_batch(PIPELINE.build_parser().parse_args(forced)), 0)
            self.assertEqual(len(calls), 12)

    def test_batch_login_interruption_does_not_advance_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            database = run_dir / "state.sqlite"
            auth_state = root / "state.json"
            auth_state.write_text("{}", encoding="utf-8")
            connection = PIPELINE.open_database(database)
            now = PIPELINE.utc_now()
            connection.execute("INSERT INTO catalog_pages VALUES (?, ?, ?, ?, ?, ?, NULL)", (1, 1, "fixture", 1, "ok", now))
            connection.execute("INSERT INTO catalog_projects VALUES (?, ?, ?, ?, ?, ?)", ("1", "Company", None, "{}", now, now))
            connection.execute("INSERT INTO catalog_project_pages VALUES (?, ?, ?, ?, ?)", (1, 1, "1", "fixture", now))
            connection.execute("INSERT INTO extraction_results VALUES (?, ?, ?, ?, ?, ?, ?)", ("1", "Company", "login_required", "", 0, "expired", now))
            connection.commit()
            connection.close()
            args = PIPELINE.build_parser().parse_args(
                [
                    "batch", "--run-dir", str(run_dir), "--auth-state", str(auth_state),
                    "--wiki-dir", str(root / "wiki" / "projects" / "butian-welfare-src-prefilter"),
                ]
            )
            with patch.object(PIPELINE, "command_catalog", return_value=0), patch.object(
                PIPELINE, "command_extract", return_value=3
            ):
                self.assertEqual(PIPELINE.command_batch(args), 3)
            connection = PIPELINE.open_database(database)
            batch = connection.execute("SELECT status, page_end FROM batch_runs").fetchone()
            self.assertEqual((batch["status"], batch["page_end"]), ("interrupted", None))
            self.assertIsNone(
                connection.execute("SELECT * FROM pipeline_cursor").fetchone()
            )
            connection.close()

    def test_subdomain_weight_thresholds_and_types(self) -> None:
        base = {
            "normalized_url": "https://portal.example.com/",
            "decision": "review",
            "functional_score": 2,
            "static_score": 0,
            "complexity_score": 0,
            "reasons": ["authentication_signal"],
        }
        nineteen = PIPELINE.attach_subdomain_weight(
            dict(base), {"root_domain": "example.com", "subdomain_count": 19, "subdomain_bonus": PIPELINE.subdomain_bonus_for_count(19), "footprint": PIPELINE.subdomain_footprint_label(19), "type_counts": {}, "source_counts": {}, "status": "ok"}
        )
        self.assertEqual(nineteen["subdomain_bonus"], 2)
        self.assertFalse(nineteen["initial_passed"])
        twenty = PIPELINE.attach_subdomain_weight(
            dict(base), {"root_domain": "example.com", "subdomain_count": 20, "subdomain_bonus": PIPELINE.subdomain_bonus_for_count(20), "footprint": PIPELINE.subdomain_footprint_label(20), "type_counts": {"api": 1}, "source_counts": {"nmap_dns_brute": 20}, "status": "ok"}
        )
        self.assertEqual(twenty["subdomain_bonus"], 3)
        self.assertTrue(twenty["initial_passed"])
        self.assertEqual(twenty["initial_tier"], "conditional_candidate")
        self.assertEqual(PIPELINE.classify_subdomain_type("api.example.com", "example.com"), "api")
        self.assertEqual(PIPELINE.classify_subdomain_type("stage.example.com", "example.com"), "dev_test")
        xml = "<nmaprun><script output='api.example.com dev.example.com'/></nmaprun>"
        self.assertEqual(PIPELINE.parse_nmap_dns_xml(xml, "example.com"), {"api.example.com", "dev.example.com"})

    def test_nmap_dns_wrapper_and_deepseek_response_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_nmap = root / "fake-nmap"
            fake_nmap.write_text(
                "#!/bin/sh\nprintf '<nmaprun><script output=\"api.example.com dev.example.com\"/></nmaprun>\n'\n",
                encoding="utf-8",
            )
            fake_nmap.chmod(0o755)
            wordlist = root / "words.txt"
            wordlist.write_text("api\ndev\n", encoding="utf-8")
            hosts, _xml, status = PIPELINE.run_nmap_dns_brute(
                "example.com",
                argparse.Namespace(
                    nmap_path=str(fake_nmap), subdomain_wordlist=str(wordlist),
                    subdomain_nmap_threads=1, subdomain_nmap_timeout=5,
                ),
            )
            self.assertEqual(status, "ok")
            self.assertEqual(hosts, {"api.example.com", "dev.example.com"})

        class Response:
            def raise_for_status(self) -> None:
                return None
            def json(self) -> dict:
                return {"choices": [{"message": {"content": json.dumps({
                    "decision": "priority_keep", "confidence": "high",
                    "subdomain_assessment": "broad", "business_evidence": ["login"],
                    "scope_risk": "low", "contradicting_evidence": [], "reason": "fixture",
                })}}]}

        with patch.object(PIPELINE, "load_deepseek_api_key", return_value="fixture"), patch.object(
            PIPELINE.requests, "post", return_value=Response()
        ):
            reply = PIPELINE.call_deepseek_middle({"url": "https://example.com/"}, ai_enabled=True)
        self.assertEqual((reply["status"], reply["decision"]), ("ok", "priority_keep"))
        with patch.object(PIPELINE, "load_deepseek_api_key", return_value=""):
            failed = PIPELINE.call_deepseek_middle({"url": "https://example.com/"}, ai_enabled=True)
        self.assertEqual((failed["status"], failed["reason"]), ("failed", "deepseek_api_key_missing"))

    def test_initial_archive_and_middle_failure_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            connection = PIPELINE.open_database(run_dir / "state.sqlite")
            result = {
                "url": "https://portal.example.com/",
                "normalized_url": "https://portal.example.com/",
                "decision": "keep", "base_decision": "keep", "initial_tier": "priority_candidate",
                "initial_passed": True, "functional_score": 5, "static_score": 0,
                "complexity_score": 0, "subdomain_count": 20, "subdomain_bonus": 3,
                "subdomain_root": "example.com", "subdomain_footprint": "large_footprint",
                "subdomain_type_counts": {"api": 1}, "subdomain_source_counts": {"nmap_dns_brute": 20},
                "subdomain_status": "ok", "combined_functional_score": 8,
                "reasons": ["authentication_signal"], "root_status": 200,
                "root_final_url": "https://portal.example.com/", "root_content_type": "text/html",
                "redirect_chain": ["https://portal.example.com/"], "page_summary": {}, "page_metrics": [],
                "pages_followed": [], "analyzed_at": PIPELINE.utc_now(), "source": "official_submit_page", "project_id": "fixture",
            }
            PIPELINE.save_prefilter_result(connection, result)
            target = PIPELINE.archive_initial_target(connection, run_dir, result, {"project_id": "fixture", "company_name": "Fixture", "source": "official_submit_page", "scope": "include"}, "batch-0001")
            self.assertIsNotNone(target)
            assert target is not None
            self.assertTrue((target / "subdomains" / "subdomains.csv").is_file())
            review = PIPELINE.middle_review_one(
                connection, run_dir, result["normalized_url"], argparse.Namespace(ai=False), batch_id="batch-0001"
            )
            self.assertEqual(review["final_tier"], "review")
            self.assertTrue((target / "middle" / "middle-report.md").is_file())
            connection.close()

    def test_run_parser_has_prefilter_input_fields(self) -> None:
        args = PIPELINE.build_parser().parse_args(["run", "--dry-run"])
        self.assertTrue(hasattr(args, "input"))
        self.assertTrue(hasattr(args, "input_source"))
        batch_args = PIPELINE.build_parser().parse_args(["batch", "--dry-run"])
        self.assertEqual(batch_args.target_kept, PIPELINE.BATCH_TARGET_KEEP)
        self.assertEqual(batch_args.page_span, PIPELINE.BATCH_PAGE_SPAN)
        self.assertTrue(hasattr(batch_args, "force_recheck"))
        self.assertTrue(hasattr(batch_args, "subdomain_discovery"))
        self.assertTrue(hasattr(batch_args, "middle_ai"))
        middle_args = PIPELINE.build_parser().parse_args(["middle", "--batch-id", "batch-0001", "--dry-run"])
        self.assertEqual(middle_args.batch_id, "batch-0001")


if __name__ == "__main__":
    unittest.main(verbosity=2)
