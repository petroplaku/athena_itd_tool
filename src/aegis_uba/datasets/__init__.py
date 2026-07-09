"""Real-world dataset adapters for training and live assessment.

Aegis normalizes public UEBA / insider-threat datasets into its own
:class:`~aegis_uba.models.Event` schema so the same detection engine can be
trained and evaluated on realistic enterprise telemetry.

The flagship supported source is the **CMU CERT Insider Threat Test Dataset** —
the standard benchmark for this problem, containing months of synthetic-but-
realistic logon, removable-device, email, file and web telemetry for a modelled
organization, with labelled insider-threat scenarios.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aegis_uba.datasets.cert import detect_cert_release, load_cert
from aegis_uba.models import Event


@dataclass
class DatasetInfo:
    key: str
    name: str
    source: str
    url: str
    citation: str
    description: str
    loader: str  # human hint of the adapter used


REGISTRY: dict[str, DatasetInfo] = {
    "cert": DatasetInfo(
        key="cert",
        name="CMU CERT Insider Threat Test Dataset",
        source="Carnegie Mellon University / DoD",
        url="https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247",
        citation=(
            "Lindauer, B. (2020). Insider Threat Test Dataset. CMU. "
            "https://doi.org/10.1184/R1/12841247"
        ),
        description=(
            "Months of enterprise telemetry (logon, device/USB, email, file, http) "
            "for a modelled org with labelled insider scenarios. Releases r4.2, r5.2, "
            "r6.2. Point Aegis at an extracted release directory."
        ),
        loader="datasets.cert.load_cert",
    ),
    "synthetic": DatasetInfo(
        key="synthetic",
        name="Aegis Synthetic Enterprise",
        source="Built-in generator",
        url="(bundled)",
        citation="Aegis UBA synthetic generator",
        description=(
            "Realistic on-the-fly org telemetry with five planted insider scenarios. "
            "Deterministic by seed; ideal for demos, tests and calibration."
        ),
        loader="ingest.synthetic.generate_synthetic",
    ),
}


def list_datasets() -> list[DatasetInfo]:
    return list(REGISTRY.values())


def load_dataset(key: str, path: str | Path | None = None, **kwargs) -> list[Event]:
    """Load a registered dataset into normalized events.

    ``cert`` requires ``path`` (an extracted release directory). ``synthetic``
    is generated in-process.
    """
    key = key.lower()
    if key == "cert":
        if path is None:
            raise ValueError("the 'cert' dataset requires a path to an extracted release dir")
        return load_cert(path, **kwargs)
    if key == "synthetic":
        from aegis_uba.ingest.synthetic import generate_synthetic

        events, _ = generate_synthetic(**kwargs)
        return events
    raise KeyError(f"unknown dataset '{key}'. Available: {', '.join(REGISTRY)}")


__all__ = ["DatasetInfo", "REGISTRY", "list_datasets", "load_dataset",
           "load_cert", "detect_cert_release"]
