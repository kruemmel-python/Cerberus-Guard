# NetGuard AI mit LM Studio nutzen

Diese Anleitung zeigt eine komplette Beispiel-Konfiguration, mit der du eine echte Ueberwachung mit einem lokalen LM-Studio-Modell einrichtest und startest.

## Ziel des Beispiels

Wir bauen eine lokale Ueberwachung mit:

- Frontend unter `http://localhost:5173`
- NetGuard-Backend unter `http://localhost:8080`
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
4. In LM Studio ist ein Modell heruntergeladen, zum Beispiel:
   - `qwen2.5-7b-instruct`
   - `llama-3.1-8b-instruct`
   - ein anderes chatfaehiges lokales Modell

## 1. LM Studio vorbereiten

1. Starte LM Studio.
2. Lade ein lokales Modell.
3. Oeffne in LM Studio den Bereich fuer den lokalen Server.
4. Starte den lokalen OpenAI-kompatiblen Server.
5. Pruefe die URL. Fuer dieses Beispiel verwenden wir:

```text
http://localhost:1234/v1
```

6. Merke dir die Modell-ID genau so, wie LM Studio sie anzeigt.

Beispiel:

```text
qwen2.5-7b-instruct
```

Hinweis:
NetGuard erwartet bei LM Studio keine API-Keys. Wichtig sind nur `Base URL` und `Model ID`.

## 2. NetGuard starten

Im Projektordner:

```powershell
npm install
npm run dev
```

Danach:

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8080`

## 3. Beispiel-Konfiguration in NetGuard

Oeffne `http://localhost:5173` und gehe in den Tab `Settings`.

Verwende fuer den ersten echten Test diese Werte.

### Sensor & Backend

- `Deployment Mode`: `standalone`
- `Sensor ID`: `desktop-lab-01`
- `Sensor Name`: `Windows Lab Sensor`
- `Hub URL`: leer
- `Shared Fleet Token`: leer
- `Global block propagation`: `aus`
- `Backend Base URL`: `http://localhost:8080`
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
- `Model ID`: `qwen2.5-7b-instruct`
- `Base URL`: `http://localhost:1234/v1`
- `Payload Privacy Mode`: `Raw payload for local LLMs only`

Wenn deine Modell-ID in LM Studio anders heisst, trage exakt diesen Namen ein.

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
Backend Base URL:        http://localhost:8080
Capture Interface:       Dein WLAN- oder Ethernet-Adapter
Capture Filter:          ip and (tcp or udp)

LLM Provider:            LM Studio
Model ID:                qwen2.5-7b-instruct
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

Damit blockt NetGuard bekannte boesartige IPs bereits vor Heuristik und vor LLM-Analyse.

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

## Kurzfassung

Wenn du nur die Minimalversion willst:

1. LM Studio starten
2. Modell laden
3. LM-Studio-Server starten
4. `npm run dev`
5. In NetGuard:
   - Backend: `http://localhost:8080`
   - Provider: `LM Studio`
   - Modell: deine LM-Studio-Modell-ID
   - Base URL: `http://localhost:1234/v1`
   - richtiges Netzwerk-Interface waehlen
6. `Start Monitoring`

Dann laeuft die Ueberwachung mit echtem Capture und lokalem LLM.
