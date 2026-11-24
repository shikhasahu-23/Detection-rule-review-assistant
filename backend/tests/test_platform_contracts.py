from app.schemas.detection import TargetPlatform
from app.services.platforms import CONTRACTS, get_platform_contract


def test_every_supported_platform_has_a_versioned_contract():
    assert set(CONTRACTS) == set(TargetPlatform)
    for platform in TargetPlatform:
        contract = get_platform_contract(platform)
        assert contract.platform is platform
        assert contract.prompt_version
        assert contract.instructions
        assert contract.validation_scope


def test_crowdstrike_contract_does_not_claim_verified_query_grammar():
    contract = get_platform_contract(TargetPlatform.CROWDSTRIKE)
    assert "do not fabricate" in contract.instructions.lower()
    assert "pending" in contract.validation_scope
