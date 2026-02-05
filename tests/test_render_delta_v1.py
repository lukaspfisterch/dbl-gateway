from dbl_gateway.rendering.renderer import render_provider_payload


def test_render_delta_v1_digest_changes():
    result1 = render_provider_payload(
        assembled_context={"model_messages": [{"role": "user", "content": "hi"}]},
        task=None,
        spec="render.delta_v1",
    )
    result2 = render_provider_payload(
        assembled_context={"model_messages": [{"role": "user", "content": "hi"}]},
        task=None,
        spec="render.delta_v1",
    )
    result3 = render_provider_payload(
        assembled_context={"model_messages": [{"role": "user", "content": "hi there"}]},
        task=None,
        spec="render.delta_v1",
    )
    assert result1.render_digest == result2.render_digest
    assert result1.render_digest != result3.render_digest
