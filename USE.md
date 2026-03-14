# Cerberus Guard AI mit LM Studio nutzen

Diese Anleitung zeigt eine komplette Beispiel-Konfiguration, mit der du eine echte Ueberwachung mit einem lokalen LM-Studio-Modell einrichtest und startest.

## Ziel des Beispiels

Wir bauen eine lokale Ueberwachung mit:

- Frontend unter `http://localhost:5173`
- Cerberus Guard-Backend unter `http://localhost:8081`
- LM Studio als lokaler LLM-Provider unter `http://localhost:1234/v1`
- echtem Netzwerk-Capture ueber Npcap/libpcap

Das Beispiel ist so ausgelegt, dass du zuerst sicher testen kannst, ohne sofort automatische Firewall-Blocks zu aktivieren.

Dabei nutzen wir die neuen erweiterten Funktionen bewusst konservativ:

- `Deployment Mode`: `standalone`
- `Payload Privacy Mode`: `Raw payload for local LLMs only`
- `Threat Intelligence`: zuerst `aus`
- `Global block propagation`: zuerst `aus`
- `Threat Hunting`: erst nach den ersten echten Traffic-Daten

## Voraussetzungen

Vor dem Start muss folgendes vorhanden sein:

1. `Node.js` ist installiert.
2. Unter Windows ist `Npcap` installiert, inklusive `WinPcap compatibility mode`.
3. LM Studio ist installiert.
4. In LM Studio ist ein Modell heruntergeladen.
5. Der lokale OpenAI-kompatible Server in LM Studio ist aktiv.

Hinweis:
Cerberus Guard startet bewusst mit der LM-Studio-Standard-Modell-ID `local-model`.
Diese Default-ID bleibt so gesetzt. Wenn LM Studio bei dir eine andere Modell-ID anzeigt, kannst du sie spaeter in `Settings` manuell ersetzen.

## 1. LM Studio vorbereiten

1. Starte LM Studio.
2. Lade ein lokales Modell.
3. Oeffne in LM Studio den Bereich fuer den lokalen Server.
4. Starte den lokalen OpenAI-kompatiblen Server.
5. Pruefe die URL. Fuer dieses Beispiel verwenden wir:

```text
http://localhost:1234/v1
```

6. Pruefe die Modell-ID.

Standard in Cerberus Guard:

```text
local-model
```

Wenn LM Studio bei dir exakt `local-model` bereitstellt, musst du nichts aendern.

Wenn du `local-model` unveraendert laesst, verwendet Cerberus Guard zur Laufzeit automatisch ein bereits in LM Studio geladenes Modell. Ist noch kein Modell im Speicher geladen, meldet NetGuard das jetzt explizit und verweist auf `lms load <model>`.

Cerberus Guard behandelt Payloads, extrahierte Strings, Pseudocode und andere Datei-Inhalte grundsaetzlich als `untrusted evidence`. Eingebettete Anweisungen wie `ignore previous instructions` werden vor dem LLM-Prompt neutralisiert und als verdachtige Inhalte markiert, statt als echte Modellanweisung weitergegeben.
Wenn LM Studio eine andere Modell-ID liefert, uebernimm exakt diesen Wert spaeter in `Settings`.

Hinweis:
Cerberus Guard erwartet bei LM Studio keine API-Keys. Wichtig sind nur `Base URL` und `Model ID`.

## 2. Cerberus Guard starten

Im Projektordner:

```powershell
npm install
npm run dev
```

Danach:

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8081`

## 3. Beispiel-Konfiguration in Cerberus Guard

Oeffne `http://localhost:5173` und gehe in den Tab `Settings`.

Verwende fuer den ersten echten Test diese Werte.

### Sensor & Backend

- `Deployment Mode`: `standalone`
- `Sensor ID`: `desktop-lab-01`
- `Sensor Name`: `Windows Lab Sensor`
- `Hub URL`: leer
- `Shared Fleet Token`: leer
- `Global block propagation`: `aus`
- `Backend Base URL`: `http://localhost:8081`
- `Capture Interface`: dein echtes Netzwerk-Interface
- `Capture Filter`: `ip and (tcp or udp)`
- `Live raw feed`: `aus` fuer den ersten Test

Wichtig:
Waehle nicht blind irgendein Interface. Nimm das Interface, ueber das dein Rechner wirklich online ist, zum Beispiel WLAN oder Ethernet.

Wenn du unsicher bist:

1. Klicke `Refresh Interfaces`
2. Suche das Interface mit deiner lokalen IP
3. Waehle dieses Interface aus

### LLM Configuration

- `LLM Provider`: `LM Studio`
- `Model ID`: `local-model`
- `Base URL`: `http://localhost:1234/v1`
- `Payload Privacy Mode`: `Raw payload for local LLMs only`

Wenn deine Modell-ID in LM Studio anders heisst, trage exakt diesen Namen ein.
Die Startkonfiguration von Cerberus Guard bleibt trotzdem absichtlich `local-model`.

Warum genau diese Einstellung?

- `LM Studio` ist lokal, deshalb darf die rohe Payload auf deinem Rechner bleiben.
- Mit `Raw payload for local LLMs only` wird nichts fuer Cloud-Provider freigegeben.
- Falls du spaeter auf OpenAI, Anthropic oder einen anderen Cloud-Provider wechselst, stelle auf `Strict masking` um.

### Threat Intelligence

Fuer den ersten Test:

- `Enable threat intelligence`: `aus`
- `Auto-block threat intel matches`: `aus`
- `Refresh Interval (hours)`: `24`

So pruefst du zuerst sauber Capture, L7-Decoding und LM-Studio-Analyse ohne vorgeschaltete Feed-Entscheidungen.

### Analysis Pipeline

Empfohlene Startwerte:

- `Cache TTL (seconds)`: `60`
- `Batch Window (ms)`: `2000`
- `Batch Size`: `20`
- `Secure Redirect Port`: `9999`
- `PCAP Buffer Size`: `10`
- `Monitoring Ports`: `22, 80, 443, 8080, 3389`
- `Detection Threshold`: `0.75`
- `Auto-block detected threats`: `aus`
- `Enable OS firewall integration`: `aus`

Warum diese Werte?

- `Auto-block` ist fuer den Ersttest deaktiviert, damit du keine echte Verbindung versehentlich sperrst.
- `Firewall integration` bleibt zunaechst aus, bis die Erkennung sauber geprueft ist.

### Integrations

Fuer den ersten Test:

- keine Webhooks notwendig

### Blocklists / Exempt Ports

Fuer den ersten Test:

- `Blocked IPs`: leer
- `Blocked Ports`: leer
- `Exempt Ports`: leer

## 4. Beispiel fuer eine komplette Test-Konfiguration

Wenn alles korrekt gesetzt ist, sieht dein praktisches Beispiel so aus:

```text
Backend Base URL:        http://localhost:8081
Capture Interface:       Dein WLAN- oder Ethernet-Adapter
Capture Filter:          ip and (tcp or udp)

LLM Provider:            LM Studio
Model ID:                local-model
Base URL:                http://localhost:1234/v1

Cache TTL:               60
Batch Window:            2000
Batch Size:              20
Secure Redirect Port:    9999
PCAP Buffer Size:        10
Monitoring Ports:        22, 80, 443, 8080, 3389
Detection Threshold:     0.75
Auto-block:              aus
Firewall integration:    aus
Live raw feed:           aus
Deployment Mode:         standalone
Sensor ID:               desktop-lab-01
Sensor Name:             Windows Lab Sensor
Payload Privacy Mode:    Raw payload for local LLMs only
Threat Intelligence:     aus
Fleet Propagation:       aus
```

## 5. Ueberwachung starten

Wechsle jetzt in den Tab `Dashboard`.

Dort:

1. Pruefe, ob `Backend Sensor` auf `Connected` steht.
2. Pruefe, ob beim LLM-Status dein LM-Studio-Modell angezeigt wird.
3. Klicke auf `Start Monitoring`.

Wenn alles korrekt ist:

- `Monitoring Status` wechselt auf `Active`
- das Capture-Interface wird angezeigt
- die Metriken beginnen zu steigen
- bei Verkehr erscheinen Eintraege im `Analyzed Traffic Feed`

In diesem Beispiel bleibt der Sensor absichtlich `standalone`. Den Fleet-Modus richtest du erst ein, wenn der Einzelknoten stabil laeuft.

## 6. Funktion testen

Erzeuge jetzt echten Traffic auf deinem Rechner, zum Beispiel:

1. Oeffne einige Webseiten
2. Fuehre einen `ping` aus
3. Starte einen Download
4. Rufe lokal einen Dienst auf, falls vorhanden

Beispiel:

```powershell
ping 8.8.8.8
```

oder im Browser:

- `https://example.com`
- `https://openai.com`

Danach solltest du im Dashboard neue Daten sehen.

Wenn du dabei Verkehr auf typischen Ports erzeugst, siehst du jetzt oft auch neue Layer-7-Metadaten im Backend, zum Beispiel fuer:

- `HTTP`
- `TLS`
- `SSH`
- `RDP`
- `SMB`
- `SQL`

## 7. Woran du erkennst, dass es funktioniert

Eine funktionierende Ueberwachung erkennst du an diesen Punkten:

1. `Packets Processed` steigt an
2. Im `Analyzed Traffic Feed` erscheinen neue Zeilen
3. Im Diagramm `Traffic vs. Threats` entstehen Werte
4. Im Tab `Logs` erscheinen Backend- und Analyse-Ereignisse

## 8. Threat Hunting mit LM Studio testen

Sobald einige Pakete gespeichert wurden, kannst du die neue Forensik-Funktion pruefen:

1. Oeffne den Tab `Threat Hunt`
2. Lass `All Sensors` aktiv, weil wir in diesem Beispiel nur einen Sensor haben
3. Stelle eine Frage wie:

```text
Zeige mir alle Quell-IPs der letzten 24 Stunden, die Port 22 angesprochen haben und als brute_force oder port_scan bewertet wurden.
```

4. Klicke `Run Hunt`

Das Backend fuehrt dann real aus:

- Text-zu-SQL ueber dein konfiguriertes LM-Studio-Modell
- schreibgeschuetzte SQL-Ausfuehrung auf SQLite
- Rueckgabe von Zusammenfassung, SQL und Ergebniszeilen

## 9. Wenn beim Start nichts passiert

Pruefe in dieser Reihenfolge:

1. Laeuft LM Studio wirklich und ist der Server gestartet?
2. Stimmt die `Base URL` genau: `http://localhost:1234/v1`?
3. Stimmt die `Model ID` exakt mit LM Studio ueberein?
4. Ist das richtige `Capture Interface` ausgewaehlt?
5. Ist `Npcap` korrekt installiert?
6. Zeigt `Backend Sensor` im Dashboard `Connected`?
7. Ist der `Capture Filter` zu streng? Testweise:

```text
ip
```

statt:

```text
ip and (tcp or udp)
```

## 10. Empfohlener naechster Schritt nach dem Ersttest

Wenn die Ueberwachung stabil laeuft, kannst du schrittweise erweitern:

1. `Live raw feed` aktivieren, wenn du Layer-7-Metadaten sehen willst
2. Webhooks konfigurieren
3. Custom Rules im Tab `Rules` bauen
4. Erst danach `Auto-block` aktivieren
5. Ganz zuletzt `OS firewall integration` aktivieren

## 11. Threat Intelligence spaeter aktivieren

Wenn der Grundbetrieb stabil laeuft, kannst du die neuen TI-Feeds aktivieren:

Empfohlene Startwerte:

- `Enable threat intelligence`: `an`
- `Auto-block threat intel matches`: `an`
- `Refresh Interval (hours)`: `24`

Dann:

1. Gehe zu `Settings -> Threat Intelligence`
2. Klicke `Refresh Feeds`
3. Pruefe, ob `indicators loaded` groesser als `0` ist

Damit blockt Cerberus Guard bekannte boesartige IPs bereits vor Heuristik und vor LLM-Analyse.

## 12. Fleet-Modus spaeter erweitern

Wenn du weitere Sensoren anbinden willst, nutze diese Grundaufteilung:

### Hub-Beispiel

- `Deployment Mode`: `hub`
- `Sensor ID`: `hq-hub-01`
- `Sensor Name`: `Central Hub`
- `Shared Fleet Token`: eigener geheimer Wert

### Agent-Beispiel

- `Deployment Mode`: `agent`
- `Sensor ID`: `branch-01`
- `Sensor Name`: `Branch Office Sensor`
- `Hub URL`: `http://IP-DES-HUBS:8080`
- `Shared Fleet Token`: derselbe Wert wie auf dem Hub
- `Global block propagation`: `an`

Dann gilt:

- der Agent analysiert lokal weiter
- Events werden an den Hub gespiegelt
- Block-Entscheidungen koennen global propagiert werden

## 13. Sichere Produktiv-Empfehlung fuer LM Studio

Fuer den produktiven Betrieb mit einem lokalen Modell:

- zuerst ohne Firewall-Automation testen
- Detection Threshold nicht zu niedrig setzen
- Custom Rules fuer bekannte interne Ausnahmen definieren
- PCAP-Exports aktiv nutzen, wenn Bedrohungen erkannt werden
- nur dann echtes Blocking aktivieren, wenn die Erkennung verifiziert ist

## 14. Sandbox-Integration mit CAPE einrichten

Fuer die komplette Server-Seite mit Token, Reverse Proxy, Netztrennung und API-Tests siehe auch `CAPE_SETUP.md`.

Wenn du keinen externen Sandbox-Server betreiben willst, kannst du stattdessen in `Einstellungen -> Sandbox` den Provider `Cerberus Lab (lokale Reverse-Analyse)` auswaehlen. Dann fuehrt NetGuard die Datei lokal ueber seine eingebaute Reverse-Analysis-Pipeline aus: Quarantaene-Kopie, Hashing, Strings, PE-Imports, Entropie, decompiler-aehnlicher Pseudocode und optionaler LLM-Analystenbericht.

### Cerberus Lab nutzen

Standard auf einem frischen Start:

- `Enable sandbox integration`: `an`
- `Sandbox Provider`: `Cerberus Lab (lokale Reverse-Analyse)`
- `Windows-Sandbox-Detonation aktivieren`: `an`
- `Windows-Sandbox-Laufzeit (Sekunden)`: `45`

Beispiel:

- `Enable sandbox integration`: `an`
- `Auto-submit suspicious processes`: `an` oder `aus`, je nach Geschmack
- `Sandbox Provider`: `Cerberus Lab (lokale Reverse-Analyse)`
- `LLM Provider`: z.B. `LM Studio`, wenn du zusaetzlich einen lokalen Analysten-Kurzbericht moechtest

Danach kannst du im Live-Verkehrs-Feed beim lokalen Prozess auf `In Sandbox analysieren` klicken. Der erzeugte Bericht enthaelt dann:

- Quarantaene-Pfad der eingesandten Datei
- `SHA-256`, `SHA-1`, `MD5`
- extrahierte Strings und IoCs
- PE-Metadaten, Import-Tabelle und Entropie
- decompiler-aehnliche Pseudocode-Zusammenfassung
- PDF-Export direkt aus dem Dashboard

### Datei direkt aus der Web-UI pruefen

Wenn du eine Datei bereits heruntergeladen hast und sie vor der Ausfuehrung erst in Cerberus pruefen willst, geht das jetzt direkt im Dashboard ohne laufenden Live-Traffic:

1. Oeffne `Dashboard`
2. Scrolle zum Bereich `Sandbox-Analysen`
3. Ziehe die Datei oder ein kleines Dateibuendel auf die Upload-Flaeche oder klicke `Dateien auswaehlen`
4. Pruefe in der Vorschau:
   - Dateiname
   - Groesse
   - Typ
   - lokal berechneter `SHA-256`
5. Klicke `Hochgeladenes Buendel analysieren`

Dann passiert real:

1. Der Browser sendet die Datei an das NetGuard-Backend
2. Das Backend legt sie kurz in `data/sandbox-uploads` ab
3. Cerberus Lab oder CAPE analysiert das Sample
4. Bei Cerberus Lab werden mitgelieferte Sidecars wie lokale DLLs oder Manifest-Dateien im selben Quarantaene-Bundle mitgestaged
5. Die temporaeren Upload-Dateien werden wieder entfernt
6. Das Ergebnis erscheint unter `Sandbox-Analysen`

Wichtig:

- Der Browser uebergibt aus Sicherheitsgruenden keinen echten lokalen Windows-Pfad, sondern nur Dateiname und Inhalt.
- Wenn du fuer Dynamic-Analysen lokale DLLs oder Manifest-Dateien brauchst, lade sie im selben Upload direkt mit hoch.
- Die Hash-Vorschau wird lokal im Browser berechnet, bevor die Datei an das Backend uebertragen wird.
- Die eigentliche Analyse bleibt trotzdem serverseitig und wird wie alle anderen Sandbox-Ergebnisse persistent gespeichert.

### Sidecars bei lokalen Prozessdateien

Wenn du keine hochgeladene Datei, sondern einen lokal gefundenen Prozess aus dem Live-Feed in Cerberus Lab analysierst, versucht NetGuard jetzt automatisch benachbarte Sidecars mitzunehmen:

- importierte DLLs aus dem gleichen Verzeichnis, wenn sie dort real vorhanden sind
- `.manifest`-Dateien neben dem Sample

Das verbessert Dynamic-Analysen bei Desktop-Programmen deutlich, weil EXEs wie Browser oder Launcher oft nicht ohne ihre lokalen DLLs starten.

### Cerberus Lab mit Windows Sandbox erweitern

Wenn dein Host `Windows Sandbox` unterstuetzt, kannst du Cerberus Lab um eine echte Gast-Ausfuehrung erweitern:

- `Sandbox Provider`: `Cerberus Lab (lokale Reverse-Analyse)`
- `Windows-Sandbox-Detonation aktivieren`: `an`
- `Windows-Sandbox-Laufzeit (Sekunden)`: z.B. `45`

Wichtig:

- Der Host muss `Windows Sandbox` als Windows-Feature aktiviert haben.
- Die Analyse braucht eine interaktive Desktop-Sitzung, weil Windows Sandbox als GUI-Gast gestartet wird.
- NetGuard fuehrt die Datei zuerst statisch aus und startet danach einen ephemeren Windows-Sandbox-Gast fuer die Dynamic-Analyse.
- Gerade bei groesseren Windows-Binaerdateien kann der komplette Gastlauf inklusive Start des Sandbox-Fensters mehrere Minuten dauern.

Zusatznutzen der Dynamic-Analyse:

- neue Prozesse und Kindprozesse
- TCP-/UDP-Aktivitaet des gestarteten Samples
- Datei-Aenderungen in typischen Benutzerpfaden
- Autorun-Registry-Aenderungen
- neu angelegte Windows-Dienste

Diese Befunde landen ebenfalls im gespeicherten Sandbox-Eintrag und im PDF-Bericht.

### Lokale LLM-Priorisierung fuer Sandbox-Analysen

Wenn du `LM Studio` oder `Ollama` verwendest, aktiviere in `Einstellungen -> Sandbox` die Option `Sandbox vor Traffic-LLM priorisieren`.

Dann gilt:

- waehrend Cerberus Lab aktiv eine Datei analysiert, werden neue Traffic-Deep-Inspections voruebergehend nicht mehr an das lokale LLM geschickt
- der Sandbox-Review bekommt Vorrang
- dadurch kommen Analyst Review und PDF-Bericht stabiler durch, auch wenn parallel viel Live-Verkehr anliegt

Wenn du verdaechtige lokale Prozesse direkt aus Cerberus Guard heraus analysieren willst, kannst du jetzt eine echte CAPE-Sandbox anbinden. Das Backend uebernimmt dabei den Dateiupload, das Polling des Tasks und die persistente Speicherung des Urteils.

Wichtig:

- Die Sandbox sollte auf einem getrennten Analyse-System laufen, nicht auf deinem normalen Arbeitsrechner.
- Cerberus Guard sendet nur lokale Dateien, keine URLs.
- Die aktuelle Dateigroessen-Grenze fuer Uploads liegt bei `100 MB`.

### Voraussetzungen fuer CAPE

Vor der Aktivierung sollte folgendes vorhanden sein:

1. Eine laufende CAPE-Instanz mit erreichbarer REST-API
2. Die API ist vom Cerberus-Backend aus erreichbar
3. Optional ein API-Token, falls deine CAPE-Instanz Authentifizierung verlangt

Cerberus Guard verwendet fuer CAPE diese Endpunkte:

```text
POST http://localhost:8090/apiv2/tasks/create/file/
GET  http://localhost:8090/apiv2/tasks/view/{taskId}/
GET  http://localhost:8090/apiv2/tasks/get/report/{taskId}/
```

Die `Sandbox Base URL` in Cerberus Guard ist deshalb nur:

```text
http://localhost:8090
```

### Beispiel-Einstellungen fuer CAPE

Gehe in `Settings -> Sandbox Integration` und setze fuer den ersten echten Test:

- `Enable sandbox integration`: `an`
- `Auto-submit suspicious processes`: `aus`
- `Sandbox Provider`: `CAPE Sandbox`
- `Sandbox Base URL`: `http://localhost:8090`
- `Sandbox API Key`: leer, wenn CAPE ohne Token laeuft
- `Polling Interval (ms)`: `5000`
- `Timeout (seconds)`: `300`

Wenn deine CAPE-Instanz einen Token erwartet:

- trage ihn in `Sandbox API Key` ein
- Cerberus Guard sendet ihn als `Authorization`-Header

### Empfohlene erste Test-Konfiguration

Fuer einen vorsichtigen Ersttest mit LM Studio plus CAPE:

```text
Backend Base URL:             http://localhost:8081
LLM Provider:                 LM Studio
Model ID:                     local-model
LM Studio Base URL:           http://localhost:1234/v1

Sandbox Enabled:              an
Sandbox Provider:             CAPE Sandbox
Sandbox Base URL:             http://localhost:8090
Sandbox API Key:              leer oder dein CAPE-Token
Sandbox Polling Interval:     5000
Sandbox Timeout:              300
Auto-submit suspicious:       aus
Auto-block threats:           aus
Firewall integration:         aus
```

Warum zuerst `Auto-submit suspicious = aus`?

- Du pruefst damit zuerst sauber, ob CAPE erreichbar ist.
- Du steuerst bewusst, welche Datei hochgeladen wird.
- Du vermeidest unnoetige automatische Sandbox-Last beim ersten Test.

### Manuelle Sandbox-Analyse aus dem Live-Feed

Sobald Live-Verkehr erscheint und ein lokaler Prozesspfad aufgeloest wurde:

1. Gehe in `Dashboard`
2. Suche im `Analyzed Traffic Feed` eine Zeile mit einem lokalen Prozess
3. Pruefe, ob unter `Lokaler Prozess` ein echter Dateipfad angezeigt wird
4. Klicke `In Sandbox analysieren`

Dann passiert im Backend real:

1. Die Datei wird lokal geprueft
2. Die Datei wird per REST an CAPE hochgeladen
3. Cerberus Guard pollt den CAPE-Task
4. Das Ergebnis wird im Dashboard unter `Sandbox-Analysen` gespeichert

Im UI siehst du danach je nach Ergebnis:

- `Queued`
- `Running`
- `Completed`
- `Failed`

und ein Verdict wie:

- `Malicious`
- `Suspicious`
- `Clean`
- `Unknown`

Zusaetzlich kannst du jeden gespeicherten Sandbox-Eintrag jetzt als `PDF-Bericht` direkt aus dem Bereich `Sandbox-Analysen` herunterladen.

### Auto-Submit spaeter aktivieren

Wenn der manuelle Test stabil funktioniert, kannst du spaeter aktivieren:

- `Auto-submit suspicious processes`: `an`

Dann gilt:

- Erkennt Cerberus Guard ein verdaechtiges Verkehrsereignis
- und es ist ein lokaler `Executable Path` bekannt
- dann wird diese Datei automatisch an CAPE uebergeben

Empfehlung:

- Erst nach erfolgreichem manuellem Test einschalten
- Nur aktivieren, wenn deine CAPE-Instanz genug Kapazitaet hat

### Woran du erkennst, dass die Sandbox funktioniert

Eine funktionierende Sandbox-Integration erkennst du an diesen Punkten:

1. Im Dashboard erscheint der Bereich `Sandbox-Analysen`
2. Nach dem Klick auf `In Sandbox analysieren` wechselt der Status auf `Queued` oder `Running`
3. Spaeter erscheint `Completed` mit Summary, Score und Signaturen
4. Im Tab `Logs` erscheinen Backend-Ereignisse zur Sandbox-Ausfuehrung

### Wenn die Sandbox-Analyse fehlschlaegt

Pruefe in dieser Reihenfolge:

1. Laeuft CAPE wirklich und ist die API erreichbar?
2. Stimmt die `Sandbox Base URL` exakt, zum Beispiel `http://localhost:8090`?
3. Erreicht das Cerberus-Backend die CAPE-API vom selben Rechner aus?
4. Braucht CAPE einen Token und ist er korrekt gesetzt?
5. Ist die lokale Datei noch vorhanden?
6. Ist die Datei groesser als `100 MB`?
7. Ist der `Timeout` zu niedrig?

Wenn du den CAPE-Endpunkt manuell pruefen willst:

```powershell
Invoke-WebRequest http://localhost:8090/apiv2/tasks/create/file/
```

Ein `404` oder `401` zeigt meist, dass zwar der Host erreichbar ist, aber Route oder Authentifizierung nicht zur CAPE-Konfiguration passen.

### Sichere Empfehlung fuer den Betrieb mit Sandbox

Fuer einen produktionsnahen Einsatz:

- CAPE auf getrenntem Analyse-System betreiben
- Auto-Submit nicht sofort global aktivieren
- zuerst manuell mit normalen lokalen EXE-Dateien testen
- Logs und Verdicts mehrere Tage beobachten
- erst danach Auto-Submit fuer verdaechtige Prozesse zuschalten

## Kurzfassung

Wenn du nur die Minimalversion willst:

1. LM Studio starten
2. Modell laden
3. LM-Studio-Server starten
4. `npm run dev`
5. In Cerberus Guard:
   - Backend: `http://localhost:8081`
   - Provider: `LM Studio`
   - Modell: `local-model`
   - Base URL: `http://localhost:1234/v1`
   - optional Sandbox: `http://localhost:8090`
   - richtiges Netzwerk-Interface waehlen
6. `Start Monitoring`

Dann laeuft die Ueberwachung mit echtem Capture und lokalem LLM. Wenn CAPE aktiv ist, kannst du lokale Prozessdateien direkt aus dem Dashboard in die Sandbox senden.
