from app.worker import celery_app


def test_daily_intelligence_schedules_are_registered():
    schedule = celery_app.conf.beat_schedule
    cisa = schedule["sync-cisa-kev-daily"]
    nvd = schedule["sync-nvd-cves-daily"]
    attack = schedule["sync-mitre-attack-daily"]
    assert cisa["task"] == "app.tasks.intelligence.sync_cisa_kev"
    assert nvd["task"] == "app.tasks.intelligence.sync_nvd_cves"
    assert attack["task"] == "app.tasks.intelligence.sync_mitre_attack"
    assert cisa["schedule"].hour == {2}
    assert nvd["schedule"].hour == {3}
    assert attack["schedule"].hour == {4}
    assert cisa["schedule"].minute == {0}
    assert nvd["schedule"].minute == {0}
    assert attack["schedule"].minute == {0}



def test_daily_pipeline_runs_after_feed_sync_windows():
    pipeline = celery_app.conf.beat_schedule["run-intelligence-pipeline-daily"]
    assert pipeline["task"] == "app.tasks.pipeline.run_pipeline"
    assert pipeline["schedule"].hour == {5}
    assert pipeline["schedule"].minute == {0}
    assert pipeline["kwargs"] == {"trigger": "scheduled", "sync_feeds": False}
