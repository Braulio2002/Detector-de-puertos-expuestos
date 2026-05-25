from app.application.services.recommendation_service import RecommendationService


def test_recommendation_known_port():
    service = RecommendationService()
    rec = service.get_recommendation(22)
    assert "Restringir por IP" in rec
    assert "fail2ban" in rec


def test_recommendation_unknown_port():
    service = RecommendationService()
    rec = service.get_recommendation(43210)
    assert "Restringir acceso" in rec
    assert "43210" in rec
