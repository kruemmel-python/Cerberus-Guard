# CAPE Sandbox Setup fuer NetGuard AI

Diese Anleitung beschreibt die Server-Seite der Sandbox-Integration fuer NetGuard AI. Ziel ist eine saubere, produktionsnahe Einbindung einer echten CAPE-Sandbox, so dass verdaechtige lokale Dateien direkt aus NetGuard heraus analysiert werden koennen.

Die Anleitung ist absichtlich auf das aktuelle Projekt abgestimmt:

- NetGuard-Frontend: `http://localhost:5173`
- NetGuard-Backend: `http://localhost:8081`
- LM Studio: `http://localhost:1234/v1`
- CAPE-Beispiel: `http://localhost:8090`

## Zielbild

Empfohlene Topologie:

1. NetGuard laeuft auf dem zu ueberwachenden Rechner oder Server.
2. CAPE laeuft auf einem getrennten Analyse-Host.
3. NetGuard sendet nur die lokale Datei an CAPE.
4. CAPE analysiert die Datei isoliert.
5. NetGuard pollt den Task und speichert Verdict, Score und Signaturen im Backend.

Warum diese Trennung sinnvoll ist:

- Malware-Analyse gehoert nicht auf den normalen Arbeitsplatzrechner.
- Die Sandbox kann mehr CPU, RAM und Netzwerkzugriff brauchen als NetGuard selbst.
- Eine Trennung reduziert das Risiko fuer Seiteneffekte im Produktivsystem.

## Was NetGuard technisch erwartet

Die aktuelle Integration in NetGuard verwendet fuer `CAPE Sandbox` genau diese API-Aufrufe:

```text
POST {Sandbox Base URL}/apiv2/tasks/create/file/
GET  {Sandbox Base URL}/apiv2/tasks/view/{taskId}/
GET  {Sandbox Base URL}/apiv2/tasks/get/report/{taskId}/
```

Wichtig:

- In NetGuard traegst du nur die Basis-URL ein, zum Beispiel `http://localhost:8090`
- Das Suffix `/apiv2/...` haengt NetGuard selbst an
- Die Datei wird als `multipart/form-data` mit Feldname `file` gesendet

## Voraussetzungen fuer CAPE

Vor der Inbetriebnahme sollte folgendes vorhanden sein:

1. Eine laufende CAPE-Instanz mit aktivem Web/API-Zugriff
2. Ein Analyse-Setup mit funktionierenden CAPE-Workern
3. Ausreichend Speicher, CPU und Disk fuer Malware-Artefakte
4. Ein klar definierter Netzwerkpfad vom NetGuard-Backend zur CAPE-API
5. Optional ein API-Token

Empfehlung:

- CAPE auf einem dedizierten Linux-System oder in einem isolierten Lab-Netz betreiben
- Keine direkte Internet-Freigabe der CAPE-Oberflaeche ohne Reverse Proxy und TLS

## Empfohlene Netzwerk- und Sicherheitsarchitektur

Fuer einen professionellen Betrieb:

1. CAPE nur im internen Admin- oder Lab-Netz exponieren
2. Zugriff auf die API nur vom NetGuard-Backend oder Admin-Systemen erlauben
3. Reverse Proxy mit TLS vor CAPE schalten
4. API mit Token absichern
5. Upload-Groessen, Logs und Retention bewusst begrenzen

Ein einfaches Zielbild:

```text
NetGuard Host                Reverse Proxy / TLS              CAPE Host
http://localhost:8081   ->   https://cape.internal.example -> http://127.0.0.1:8090
```

## Ports und Erreichbarkeit

Fuer die Beispielkonfiguration gilt:

- NetGuard-Backend: `8081`
- LM Studio: `1234`
- CAPE intern: `8090`

Pruefe vom NetGuard-Rechner aus zuerst nur die reine Erreichbarkeit:

```powershell
Test-NetConnection localhost -Port 8090
```

oder gegen einen Remote-Host:

```powershell
Test-NetConnection cape.internal.example -Port 443
```

## Token und Authentifizierung

NetGuard unterstuetzt im Feld `Sandbox API Key` zwei Modi:

1. Du traegst nur den Tokenwert ein
   Dann sendet NetGuard:

```text
Authorization: Token <dein-token>
```

2. Du traegst den kompletten Headerwert ein, zum Beispiel:

```text
Bearer abcdef...
```

Dann uebernimmt NetGuard diesen Wert unveraendert.

Empfehlung:

- Wenn CAPE klassisch `Token <wert>` erwartet, trage nur den Rohwert ein
- Wenn dein Reverse Proxy eigene Authentifizierung verlangt, trage den vollen Headerwert ein

## Reverse Proxy mit TLS

Wenn CAPE nicht lokal auf `localhost` laeuft, solltest du die API nicht ungeschuetzt per reinem HTTP freigeben. Ein Reverse Proxy mit TLS ist der bessere Standard.

Beispiel fuer `nginx`:

```nginx
server {
    listen 443 ssl http2;
    server_name cape.internal.example;

    ssl_certificate     /etc/letsencrypt/live/cape.internal.example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cape.internal.example/privkey.pem;

    client_max_body_size 100m;

    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Dann waere in NetGuard die passende Einstellung:

```text
Sandbox Base URL: https://cape.internal.example
```

## Manuelle API-Pruefung vor NetGuard

Bevor du NetGuard aktivierst, teste CAPE einmal direkt.

### Test 1: API grundsaetzlich erreichbar

```powershell
Invoke-WebRequest http://localhost:8090/apiv2/tasks/view/1/
```

Moegliche Ergebnisse:

- `401` oder `403`: API lebt, aber Auth fehlt
- `404`: Host lebt, Route oder CAPE-Version passt nicht
- `200`: Route ist erreichbar

### Test 2: Dateiupload mit `curl.exe`

Ohne Token:

```powershell
curl.exe -X POST ^
  -F "file=@C:\Windows\System32\notepad.exe" ^
  http://localhost:8090/apiv2/tasks/create/file/
```

Mit Token:

```powershell
curl.exe -X POST ^
  -H "Authorization: Token MEIN_TOKEN" ^
  -F "file=@C:\Windows\System32\notepad.exe" ^
  http://localhost:8090/apiv2/tasks/create/file/
```

Erwartung:

- Die API liefert eine Task-ID oder eine aehnliche Erfolgsantwort
- Wenn kein Task erzeugt wird, muss erst CAPE selbst sauber funktionieren

## NetGuard-Einstellungen fuer CAPE

Sobald CAPE extern getestet ist, setze in NetGuard unter `Settings -> Sandbox Integration`:

```text
Enable sandbox integration:      an
Auto-submit suspicious:          aus
Sandbox Provider:                CAPE Sandbox
Sandbox Base URL:                http://localhost:8090
Sandbox API Key:                 leer oder dein Token
Polling Interval (ms):           5000
Timeout (seconds):               300
```

Empfohlene Gesamtkonfiguration fuer den Ersttest:

```text
Backend Base URL:                http://localhost:8081
LLM Provider:                    LM Studio
Model ID:                        local-model
LM Studio Base URL:              http://localhost:1234/v1

Sandbox Enabled:                 an
Sandbox Provider:                CAPE Sandbox
Sandbox Base URL:                http://localhost:8090
Sandbox API Key:                 leer oder Token
Sandbox Polling Interval:        5000
Sandbox Timeout:                 300
Sandbox Auto-submit suspicious:  aus

Auto-block threats:              aus
OS firewall integration:         aus
```

## Erster echter End-to-End-Test

Sobald CAPE und NetGuard beide laufen:

1. Starte `npm run dev`
2. Oeffne `http://localhost:5173`
3. Stelle sicher, dass `Backend Sensor` auf `Connected` steht
4. Starte die Ueberwachung
5. Erzeuge normalen lokalen Verkehr
6. Suche im `Analyzed Traffic Feed` eine Zeile mit lokalem Prozesspfad
7. Klicke `In Sandbox analysieren`

Dann sollte NetGuard:

1. Die Datei lokal pruefen
2. Die Datei an CAPE senden
3. Den Task pollend beobachten
4. Im Dashboard einen Sandbox-Eintrag anzeigen

## Was im Dashboard erscheinen sollte

Im Bereich `Sandbox-Analysen` siehst du typischerweise:

- Dateiname
- Sensorname
- Provider `CAPE`
- Status `Queued`, `Running`, `Completed` oder `Failed`
- Verdict `Malicious`, `Suspicious`, `Clean` oder `Unknown`
- Score
- Signaturen
- Summary
- PDF-Bericht zum direkten Export fuer SOC-Dokumentation

Zusatz:

- Im Live-Feed wird beim zugehoerigen Prozess ebenfalls der letzte bekannte Sandbox-Status angezeigt

## Automatisches Einsenden spaeter aktivieren

Wenn der manuelle Test stabil funktioniert, kannst du spaeter einschalten:

```text
Auto-submit suspicious processes: an
```

Dann gilt:

- NetGuard sendet verdaechtige lokale Dateien automatisch an CAPE
- Voraussetzung ist ein bekannter lokaler Prozesspfad

Empfehlung fuer den Produktivbetrieb:

- Erst mehrere manuelle Tests erfolgreich durchfuehren
- Erst danach Auto-Submit aktivieren
- Zunaechst auf begrenzten Sensoren testen

## Grenzwerte und bekannte Rahmenbedingungen

Aktuell in NetGuard:

- nur lokale Dateien, keine URL-Analysen
- Dateigroesse bis `100 MB`
- Sandbox-Task wird aktiv gepollt
- Ergebnis wird im SQLite-Backend gespeichert
- bei gleichem `SHA-256` wird eine vorhandene Analyse bevorzugt wiederverwendet

## Troubleshooting

### Problem: `Sandbox analysis failed`

Pruefe:

1. Ist die Basis-URL korrekt?
2. Ist die CAPE-API vom NetGuard-Backend aus erreichbar?
3. Stimmt der Token?
4. Existiert die lokale Datei noch?
5. Ist die Datei groesser als `100 MB`?
6. Ist der Timeout zu niedrig?

### Problem: Upload funktioniert, aber kein Report kommt zurueck

Pruefe:

1. Haben CAPE-Worker wirklich freie Kapazitaet?
2. Bleibt der Task in `pending` oder `running` haengen?
3. Ist das Polling-Intervall sinnvoll?
4. Ist `Timeout (seconds)` zu kurz?

Empfohlene Testwerte:

- `Polling Interval (ms)`: `5000`
- `Timeout (seconds)`: `300`

### Problem: `401` oder `403`

Dann lebt die API meist schon, aber die Authentifizierung ist falsch.

Pruefe:

- Rohwert vs. kompletter Headerwert
- ob dein Proxy den `Authorization`-Header weiterreicht

### Problem: `404`

Dann ist meist eines davon falsch:

- falscher Host
- falscher Port
- anderes CAPE-API-Layout
- Reverse Proxy routet nicht auf CAPE durch

## Harter Produktionsstandard

Wenn du das professionell betreiben willst, ist diese Reihenfolge sinnvoll:

1. CAPE isoliert bereitstellen
2. API per Reverse Proxy und TLS schuetzen
3. Token-Auth aktivieren
4. Upload und Polling manuell testen
5. NetGuard mit manuellem Sandbox-Submit testen
6. Logs und Verdicts beobachten
7. Erst dann Auto-Submit aktivieren

## Kurzfassung

Wenn du nur den schnellsten Pfad willst:

1. CAPE API erreichbar machen
2. In NetGuard setzen:
   - `Sandbox Enabled = an`
   - `Sandbox Provider = CAPE Sandbox`
   - `Sandbox Base URL = http://localhost:8090`
   - `Sandbox API Key = dein Token oder leer`
3. Monitoring starten
4. Im Live-Feed bei einem lokalen Prozess `In Sandbox analysieren` klicken

Dann laeuft die Dateianalyse direkt aus NetGuard in eine echte CAPE-Sandbox.
