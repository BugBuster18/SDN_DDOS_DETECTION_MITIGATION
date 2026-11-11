"""Shared preprocessing, training, and inference package.

Heavy ML dependencies are imported only when their symbols are requested.
This allows lightweight SDN helpers to run in the Ryu environment.
"""

__all__ = ["FEATURE_COLUMNS", "canonicalize_frame", "live_flow_features"]


def __getattr__(name):
    if name in __all__:
        from importlib import import_module
        features = import_module(".features", __name__)
        return getattr(features, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
