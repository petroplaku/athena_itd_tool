"""Geolocation, travel-velocity and network reputation intelligence.

Impossible-travel detection is only meaningful if it is grounded in real
distance and time: "logged in from two countries" is a weak signal, whereas
"moved 8,400 km in 41 minutes — 12,300 km/h" is an assertion an analyst can act
on. This module supplies the country centroids, great-circle maths and network
reputation needed to make that claim, with no external service calls (the tool
stays air-gap friendly).

Reputation data is a curated static set: RFC1918/CGNAT space, documented Tor
exit-relay ranges, well-known commercial VPN and bulletproof-hosting prefixes,
and cloud provider egress. It is deliberately small and auditable rather than a
stale bundled feed; :func:`load_intel_file` lets an operator layer their own
threat-intel export on top.
"""
from __future__ import annotations

import ipaddress
import json
import math
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# Commercial-aviation cruise speed. Anything materially above this between two
# authentications cannot be explained by the human physically travelling.
MAX_PLAUSIBLE_KMH = 900.0
# Below this, two logins are close enough that clock skew dominates the maths.
MIN_TRAVEL_SECONDS = 60.0


@dataclass(frozen=True)
class Location:
    """Approximate centroid of a country, used for travel-velocity maths."""

    code: str
    name: str
    lat: float
    lon: float
    region: str


# Country centroids (populated-area weighted, not geometric) for the countries a
# corporate identity realistically authenticates from, plus the ones that most
# often appear in account-takeover casework.
COUNTRIES: dict[str, Location] = {
    loc.code: loc
    for loc in [
        Location("US", "United States", 39.83, -98.58, "Americas"),
        Location("CA", "Canada", 56.13, -106.35, "Americas"),
        Location("MX", "Mexico", 23.63, -102.55, "Americas"),
        Location("BR", "Brazil", -14.24, -51.93, "Americas"),
        Location("AR", "Argentina", -38.42, -63.62, "Americas"),
        Location("GB", "United Kingdom", 55.38, -3.44, "Europe"),
        Location("IE", "Ireland", 53.41, -8.24, "Europe"),
        Location("FR", "France", 46.23, 2.21, "Europe"),
        Location("DE", "Germany", 51.17, 10.45, "Europe"),
        Location("NL", "Netherlands", 52.13, 5.29, "Europe"),
        Location("BE", "Belgium", 50.50, 4.47, "Europe"),
        Location("ES", "Spain", 40.46, -3.75, "Europe"),
        Location("PT", "Portugal", 39.40, -8.22, "Europe"),
        Location("IT", "Italy", 41.87, 12.57, "Europe"),
        Location("CH", "Switzerland", 46.82, 8.23, "Europe"),
        Location("AT", "Austria", 47.52, 14.55, "Europe"),
        Location("SE", "Sweden", 60.13, 18.64, "Europe"),
        Location("NO", "Norway", 60.47, 8.47, "Europe"),
        Location("DK", "Denmark", 56.26, 9.50, "Europe"),
        Location("FI", "Finland", 61.92, 25.75, "Europe"),
        Location("PL", "Poland", 51.92, 19.15, "Europe"),
        Location("CZ", "Czechia", 49.82, 15.47, "Europe"),
        Location("RO", "Romania", 45.94, 24.97, "Europe"),
        Location("GR", "Greece", 39.07, 21.82, "Europe"),
        Location("AL", "Albania", 41.15, 20.17, "Europe"),
        Location("RS", "Serbia", 44.02, 21.01, "Europe"),
        Location("UA", "Ukraine", 48.38, 31.17, "Europe"),
        Location("RU", "Russia", 61.52, 105.32, "Europe"),
        Location("BY", "Belarus", 53.71, 27.95, "Europe"),
        Location("TR", "Turkey", 38.96, 35.24, "Europe"),
        Location("IL", "Israel", 31.05, 34.85, "Middle East"),
        Location("AE", "United Arab Emirates", 23.42, 53.85, "Middle East"),
        Location("SA", "Saudi Arabia", 23.89, 45.08, "Middle East"),
        Location("IR", "Iran", 32.43, 53.69, "Middle East"),
        Location("EG", "Egypt", 26.82, 30.80, "Africa"),
        Location("ZA", "South Africa", -30.56, 22.94, "Africa"),
        Location("NG", "Nigeria", 9.08, 8.68, "Africa"),
        Location("KE", "Kenya", -0.02, 37.91, "Africa"),
        Location("IN", "India", 20.59, 78.96, "Asia"),
        Location("PK", "Pakistan", 30.38, 69.35, "Asia"),
        Location("CN", "China", 35.86, 104.20, "Asia"),
        Location("HK", "Hong Kong", 22.32, 114.17, "Asia"),
        Location("TW", "Taiwan", 23.70, 120.96, "Asia"),
        Location("JP", "Japan", 36.20, 138.25, "Asia"),
        Location("KR", "South Korea", 35.91, 127.77, "Asia"),
        Location("KP", "North Korea", 40.34, 127.51, "Asia"),
        Location("SG", "Singapore", 1.35, 103.82, "Asia"),
        Location("MY", "Malaysia", 4.21, 101.98, "Asia"),
        Location("ID", "Indonesia", -0.79, 113.92, "Asia"),
        Location("TH", "Thailand", 15.87, 100.99, "Asia"),
        Location("VN", "Vietnam", 14.06, 108.28, "Asia"),
        Location("PH", "Philippines", 12.88, 121.77, "Asia"),
        Location("AU", "Australia", -25.27, 133.78, "Oceania"),
        Location("NZ", "New Zealand", -40.90, 174.89, "Oceania"),
    ]
}

# Jurisdictions that materially raise the risk of an authentication for most
# Western enterprises — sanctions exposure, state-actor prevalence, or both.
HIGH_RISK_COUNTRIES: set[str] = {"RU", "CN", "KP", "IR", "BY", "SY", "VE", "CU"}

# Curated network reputation. Each entry is (CIDR, category, label).
_INTEL_SEED: list[tuple[str, str, str]] = [
    # Documentation / test ranges — common in synthetic and lab telemetry.
    ("192.0.2.0/24", "documentation", "RFC5737 TEST-NET-1"),
    ("198.51.100.0/24", "documentation", "RFC5737 TEST-NET-2"),
    ("203.0.113.0/24", "documentation", "RFC5737 TEST-NET-3"),
    # Tor exit-relay concentrations.
    ("185.220.100.0/22", "tor", "Tor exit relay cluster (Zwiebelfreunde)"),
    ("199.249.230.0/24", "tor", "Tor exit relay cluster (Quintex)"),
    ("204.85.191.0/24", "tor", "Tor exit relay cluster"),
    ("171.25.193.0/24", "tor", "Tor exit relay cluster (DFRI)"),
    ("162.247.74.0/24", "tor", "Tor exit relay cluster (Calyx)"),
    # Anonymising VPN / hosting egress frequently seen in ATO casework.
    ("45.83.104.0/22", "vpn", "Commercial VPN egress"),
    ("146.70.0.0/16", "vpn", "Commercial VPN egress (M247)"),
    ("138.199.0.0/16", "vpn", "Commercial VPN egress (Datapacket)"),
    ("31.13.191.0/24", "hosting", "Bulletproof hosting"),
    # Cloud egress — not malicious, but a human should not "log in" from it.
    ("13.104.0.0/14", "cloud", "Microsoft Azure"),
    ("34.64.0.0/10", "cloud", "Google Cloud"),
    ("52.0.0.0/11", "cloud", "AWS EC2"),
]

_CATEGORY_RISK: dict[str, float] = {
    "tor": 1.0,
    "hosting": 0.85,
    "vpn": 0.6,
    "cloud": 0.45,
    "documentation": 0.1,
    "private": 0.0,
    "unknown": 0.0,
}


def _build_intel() -> list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, str]]:
    nets = []
    for cidr, category, label in _INTEL_SEED:
        try:
            nets.append((ipaddress.ip_network(cidr, strict=False), category, label))
        except ValueError:
            continue  # a malformed seed entry must never break startup
    return nets


_INTEL = _build_intel()


def load_intel_file(path: str | Path) -> int:
    """Layer an operator-supplied intel file over the built-in seed.

    Expects JSON: ``[{"cidr": "...", "category": "tor|vpn|hosting|cloud",
    "label": "..."}, ...]``. Returns the number of ranges added.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    added = 0
    for row in data:
        try:
            net = ipaddress.ip_network(str(row["cidr"]), strict=False)
        except (KeyError, ValueError):
            continue
        _INTEL.append((net, str(row.get("category", "unknown")), str(row.get("label", ""))))
        added += 1
    classify_ip.cache_clear()
    return added


@lru_cache(maxsize=8192)
def classify_ip(ip: str) -> dict:
    """Classify an address: private, documentation, Tor, VPN, hosting or unknown."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "category": "unknown", "label": "unparseable",
                "risk": 0.0, "private": False}

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return {"ip": ip, "category": "private", "label": "internal/RFC1918",
                "risk": 0.0, "private": True}

    for net, category, label in _INTEL:
        if addr in net:
            return {"ip": ip, "category": category, "label": label,
                    "risk": _CATEGORY_RISK.get(category, 0.0), "private": False}

    return {"ip": ip, "category": "unknown", "label": "no reputation data",
            "risk": 0.0, "private": False}


def is_anonymised(ip: str) -> bool:
    """True when the address belongs to Tor, a commercial VPN or bulletproof hosting."""
    return classify_ip(ip)["category"] in {"tor", "vpn", "hosting"}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres."""
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def country_distance_km(a: str, b: str) -> float | None:
    """Distance between two country centroids, or ``None`` if either is unknown."""
    la, lb = COUNTRIES.get((a or "").upper()), COUNTRIES.get((b or "").upper())
    if not la or not lb:
        return None
    return haversine_km(la.lat, la.lon, lb.lat, lb.lon)


@dataclass
class TravelLeg:
    """A pair of authentications evaluated for physical plausibility."""

    from_country: str
    to_country: str
    distance_km: float
    seconds: float
    speed_kmh: float
    impossible: bool

    @property
    def summary(self) -> str:
        return (
            f"{self.from_country}→{self.to_country}: {self.distance_km:,.0f} km in "
            f"{self.seconds / 60:.0f} min ({self.speed_kmh:,.0f} km/h)"
        )

    def as_dict(self) -> dict:
        return {
            "from": self.from_country, "to": self.to_country,
            "distance_km": round(self.distance_km, 1),
            "seconds": round(self.seconds, 1),
            "speed_kmh": round(self.speed_kmh, 1),
            "impossible": self.impossible,
            "summary": self.summary,
        }


def evaluate_travel(from_country: str, to_country: str, seconds: float) -> TravelLeg | None:
    """Assess whether moving between two countries in ``seconds`` is physically possible."""
    if not from_country or not to_country:
        return None
    from_country, to_country = from_country.upper(), to_country.upper()
    if from_country == to_country:
        return None
    distance = country_distance_km(from_country, to_country)
    if distance is None:
        return None
    elapsed = max(seconds, MIN_TRAVEL_SECONDS)
    speed = distance / (elapsed / 3600.0)
    return TravelLeg(
        from_country=from_country, to_country=to_country, distance_km=distance,
        seconds=seconds, speed_kmh=speed, impossible=speed > MAX_PLAUSIBLE_KMH,
    )


def worst_travel_leg(sightings: list[tuple[str, float]]) -> TravelLeg | None:
    """Return the fastest (most implausible) leg across ordered ``(country, epoch)`` sightings."""
    worst: TravelLeg | None = None
    ordered = sorted(sightings, key=lambda s: s[1])
    for (c1, t1), (c2, t2) in zip(ordered, ordered[1:]):
        leg = evaluate_travel(c1, c2, t2 - t1)
        if leg and (worst is None or leg.speed_kmh > worst.speed_kmh):
            worst = leg
    return worst


def country_name(code: str) -> str:
    loc = COUNTRIES.get((code or "").upper())
    return loc.name if loc else (code or "unknown")


def geo_points(counts: dict[str, int]) -> list[dict]:
    """Map country→event-count onto plottable points for the console's world map."""
    points = []
    for code, count in counts.items():
        loc = COUNTRIES.get((code or "").upper())
        if not loc:
            continue
        points.append({
            "code": loc.code, "name": loc.name, "lat": loc.lat, "lon": loc.lon,
            "region": loc.region, "count": count,
            "high_risk": loc.code in HIGH_RISK_COUNTRIES,
        })
    points.sort(key=lambda p: -p["count"])
    return points
