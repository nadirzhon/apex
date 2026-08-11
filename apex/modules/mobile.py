"""Статический анализ APK (офлайн, безопасно): состав пакета, разрешения,
cleartext-трафик, зашитые секреты. Никакой динамики/запуска — только чтение
локального файла. Пакет должен быть в scope (com.example.app)."""
from __future__ import annotations

import re
import zipfile
from pathlib import Path

from ..models import Finding
from ..scope import Scope
from ..store import Store
from . import secrets as secrets_mod

_PKG = re.compile(rb'package="([a-zA-Z0-9_.]+)"')
_PERM = re.compile(rb'android\.permission\.[A-Z_]+')
DANGEROUS_PERMS = {
    b"android.permission.READ_SMS", b"android.permission.SEND_SMS",
    b"android.permission.READ_CONTACTS", b"android.permission.ACCESS_FINE_LOCATION",
    b"android.permission.RECORD_AUDIO", b"android.permission.READ_EXTERNAL_STORAGE",
    b"android.permission.CAMERA", b"android.permission.READ_PHONE_STATE",
}


def run(scope: Scope, store: Store, apk_path: str, authorized: bool,
        package_hint: str = "") -> list[Finding]:
    scope.assert_ready(authorized)
    findings: list[Finding] = []
    p = Path(apk_path)
    if not p.exists() or not zipfile.is_zipfile(p):
        raise ValueError(f"не APK/не найден: {apk_path}")

    with zipfile.ZipFile(p) as z:
        names = z.namelist()
        manifest = b""
        if "AndroidManifest.xml" in names:
            manifest = z.read("AndroidManifest.xml")

        # пакет (из бинарного манифеста строки читаются частично)
        pkg = package_hint
        mp = _PKG.search(manifest)
        if mp:
            pkg = mp.group(1).decode()
        if pkg and not scope.is_apk_in_scope(pkg):
            raise PermissionError(
                f"пакет '{pkg}' вне scope программы «{scope.program}» — отказ"
            )

        target = pkg or p.name

        # разрешения
        perms = sorted({m.decode() for m in _PERM.findall(manifest)})
        dangerous = [pm for pm in perms if pm.encode() in DANGEROUS_PERMS]
        if dangerous:
            findings.append(Finding(
                title="Опасные разрешения в манифесте", severity="info",
                target=target, module="mobile",
                description="Приложение запрашивает чувствительные разрешения.",
                evidence=", ".join(dangerous),
                remediation="Проверьте необходимость каждого разрешения (мин. привилегии).",
            ))

        # cleartext-трафик: в манифесте или в network_security_config
        cleartext = b'usesCleartextTraffic="true"' in manifest
        for n in names:
            if n.endswith("network_security_config.xml"):
                if b'cleartextTrafficPermitted="true"' in z.read(n):
                    cleartext = True
                    break
        if cleartext:
            findings.append(Finding(
                title="Разрешён cleartext-трафик (HTTP)", severity="medium",
                target=target, module="mobile",
                description="Приложение допускает незашифрованный HTTP-трафик.",
                evidence="usesCleartextTraffic=true / cleartextTrafficPermitted=true",
                remediation="Запретите cleartext; используйте только HTTPS.",
                cvss_vector="AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            ))

        # секреты в текстовых ресурсах/коде
        scanned = 0
        for n in names:
            if scanned >= 200:
                break
            if n.endswith((".xml", ".json", ".txt", ".properties", ".js", ".smali")):
                try:
                    text = z.read(n).decode("utf-8", "replace")
                except KeyError:
                    continue
                scanned += 1
                for f in secrets_mod._scan_text(text, f"{target}:{n}"):
                    f.module = "mobile"
                    findings.append(f)

    store.add_asset  # noqa (asset тип apk можно добавить отдельно)
    for f in findings:
        store.add_finding(f)
    return findings
