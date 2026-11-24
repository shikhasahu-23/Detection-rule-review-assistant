from app.worker import celery_app


def test_daily_intelligence_schedules_are_registered():
    schedule = celery_app.conf.beat_schedule
    cisa = schedule["sync-cisa-kev-daily"]
    nvd = schedule["sync-nvd-cves-daily"]
    assert cisa["task"] == "app.tasks.intelligence.sync_cisa_kev"
    assert nvd["task"] == "app.tasks.intelligence.sync_nvd_cves"
    assert cisa["schedule"].hour == {2}
    assert nvd["schedule"].hour == {3}
    assert cisa["schedule"].minute == {0}
    assert nvd["schedule"].minute == {0}
