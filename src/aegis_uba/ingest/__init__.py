"""Data collectors that normalize raw activity into :class:`Event` objects."""
from aegis_uba.ingest.loaders import load_events_from_file, sniff_format
from aegis_uba.ingest.synthetic import generate_synthetic

__all__ = ["generate_synthetic", "load_events_from_file", "sniff_format"]
