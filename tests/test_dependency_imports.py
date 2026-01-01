def test_dependency_imports() -> None:
    try:
        import dbl_core  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"import dbl_core failed: {exc}") from exc

    try:
        import dbl_policy  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"import dbl_policy failed: {exc}") from exc

    try:
        import dbl_main  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"import dbl_main failed: {exc}") from exc

    try:
        import kl_kernel_logic  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"import kl_kernel_logic failed: {exc}") from exc
