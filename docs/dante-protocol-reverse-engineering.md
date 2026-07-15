# Dante AES67 – Reverse Engineering der Empfangs-Seite (RX)

Analyse der Capture `Dante.pcapng` (875 Pakete). Ziel: das Kommando finden, mit dem
Dante Controller ein Dante-Gerät dazu bringt, einen **AES67-Flow zu empfangen**.

## Setup in der Capture

| Rolle | Adresse | Bemerkung |
|-------|---------|-----------|
| Dante Controller (Software) | `192.168.97.100`, Quellport `64445` | schickt die Steuerkommandos |
| **Ziel-Gerät (Empfänger)** | `192.168.97.101` | unser Gerät |
| weitere Geräte | `.196`, `192.168.99.93` | im Netz sichtbar |
| PTP-Grandmaster / Clock | `192.168.99.1` | 542 Pakete, v.a. PTP (319/320) |

Beobachtete Ports: **319/320** (PTP), **8700/8702/8708** (ConMon-Status, Multicast an
224.0.0.23x), **4440** (ARC / Audio-Control – hier laufen die Kommandos), **5353** (mDNS).

Wichtig: **Kein SAP-Traffic (Port 9875)** und **keine 239.x-AES67-Multicast-Adressen**
in der Capture. Das ist also die **Dante-interne AES67-Steuerung** über das proprietäre
Control-Protokoll — nicht der SAP/SDP-Weg, über den ein *Fremd*-AES67-Sender entdeckt würde.

## Protokoll-Framing (bestätigt, wie netaudio-Core)

Alle Kommandos auf Port 4440 folgen dem `protocol_packet`-Layout:

```
Offset  Feld
0:2     Protokoll-ID   (0x2809 = AES67-Config, Antworten teils 0x2801)
2:4     Länge (Bytes gesamt)
4:6     Transaction-ID (pro Request hochgezählt)
6:8     Opcode
8:10    0x0000 (Trenner)
10:     Body
```

## Die RX-relevanten Opcodes (ctrl -> Gerät, Port 4440)

| Opcode | Länge | Rolle |
|--------|-------|-------|
| `0x3410` | 28 B | **Flow-Bindung** (einmalig): bindet den Flow an einen Ziel-Dante-RX-Kanal. Nur in Capture 2 (neue Flow-Anlage). |
| `0x3201` | 112 B | **Quellkanal mappen** (je Aufruf): legt einen Quell-Stream-Kanal in den Flow. |
| `0x3400` | 34 B | Kanal-Info abfragen (Antwort enthält Kanalnamen `Ch 1` / `CH1`) |
| `0x3600` | 34 B | RX-Status/Flow-Liste abfragen (Polling) |

### Beweis aus Capture 2 (`dante2.pcapng`)

Sechs `0x3201`-Kommandos, **Byte 102 = 1,2,3,4,5,6** = exakt die sechs gerouteten
Stream-Quellkanäle. Davor genau **ein** `0x3410` mit Zielfeld `0001` = Dante-RX-Kanal 1.
Damit ist Byte 102 eindeutig der **Quellkanal im Stream** (nicht der Zielkanal).

Die `0x3xxx`-Range ist die Empfänger-Seite (vgl. netaudio: `0x3001` RX-Kanalname,
`0x3010/0x3014` Subscription add/remove). `0x3201` unter Protokoll `0x2809` ist damit
konsistent die **AES67-Empfangs-Konfiguration**.

## Feldkarte Opcode `0x3201` (112 Byte)

Diff über die 3 Instanzen (#509, #681, #794): **nur zwei Bytes ändern sich** —
die Transaction-ID (Offset 4–5) und **Offset 102** (`0x01` → `0x02`). Alles andere
ist identisch.

```
Offset  Bytes           Bedeutung (bestätigt / vermutet)
  0:2   2809            Protokoll AES67-Config          [bestätigt]
  2:4   0070            Länge 112                        [bestätigt]
  4:6   00xx            Transaction-ID                   [bestätigt]
  6:8   3201            Opcode                           [bestätigt]
 8:10   0000            Trenner                          [bestätigt]
   16   4202            ? Flow-/Format-Kennung           [vermutet]
   35   03              ?                                [offen]
   47   40              ?                                [offen]
   68   c0 a8 01 64     Source-IP 192.168.1.100 (Sender, unicast)  [BESTÄTIGT]
   76   0001e240        0x1E240 (=123456) Session-/Stream-Feld     [offen]
  102   01..06          >> QUELL-Kanal im Stream <<                 [BESTÄTIGT: nahm 1..6 an]
  106   13 8c           RTP-Port 5004                               [BESTÄTIGT]
  108   ef 01 01 01     Multicast 239.1.1.1                         [BESTÄTIGT]

### Opcode 0x3410 (Flow-Bindung, 28 B)

```
    4:6   Transaction-ID                              [BESTÄTIGT]
   16     08            Flow-Slot / -ID?              [offen]
   20:22  00 01         Ziel-Dante-RX-Kanal (=1)      [HYPOTHESE, passt zu "auf dante ch1"]
   22:24  00 03         ?                             [offen]
```
```

Hex der ersten Instanz (#509):
```
280900700020 3201 0000 010100100000000042020000000000000000000100000000
0068000000000000000000030040000000000002006000000000000000001000000b
c0a80164 000000000001e240 00000000000000000000000000000000 0001 0002 000001 00
0802138cef 010101
```

## Was gesichert ist vs. was noch fehlt

**Gesichert:**
- Empfangs-Steuerung läuft über Protokoll `0x2809`, Port 4440.
- `0x3201` ist der schreibende RX-Konfig-Befehl; `0x3400`/`0x3600` sind Abfragen.
- Offset 102 ist der Kanal-/Slot-Selektor (variierte 1→2).
- Framing identisch zum bereits offengelegten netaudio-Schema.

**Noch nicht gesichert (nur eine Flow-Konfiguration in der Capture):**
**Per bekannter Flow-Parameter bestätigt** (Source 192.168.1.100 / Multicast 239.1.1.1 /
Port 5004): Source-IP @68, RX-Kanal @102, RTP-Port @106, Multicast @108. Der Builder
reproduziert das Originalpaket damit byte-genau.

**Noch offen:**
- Bedeutung von Offset 76 (`0001e240`) und der `4202`-Kennung @16 (bleiben im Builder
  als Template-Werte erhalten).
- Ob `0x3201` einen Flow **anlegt** oder eine bestehende **Subscription referenziert**,
  und ob die `0x3600`/`0x3400`-Queries zwingend vorausgeschickt werden müssen.
- Verhalten bei >255 Kanälen (Feld @102 ist 1 Byte).

## Nächster Schritt: gezielte Captures zum Festnageln

Um die Feld-Semantik zu bestätigen, jeweils **eine Variable ändern** und mitschneiden
(Wireshark-Filter: `udp.port==4440 || udp.port==8700 || udp.port==9875`):

1. **RX-Kanal variieren:** denselben Flow einmal auf RX-Kanal 1, einmal auf 3, einmal 8
   abonnieren. -> bestätigt Offset 102 (und ob weitere Bytes mitwandern).
2. **Multicast-Adresse variieren:** zwei Flows mit unterschiedlichen, dir bekannten
   AES67-Multicast-Adressen empfangen. -> lokalisiert das Adressfeld eindeutig.
3. **Fremd-Sender testen:** wenn ein Nicht-Dante-AES67-Sender empfangen werden soll,
   eine Capture *inkl. Port 9875 (SAP)* machen — dann sehen wir, ob Dante zusätzlich
   über SDP/SAP geht (anderer Pfad als hier).

Schick die neuen `.pcapng` — ich diffe sie und baue daraus den bestätigten
Python-Kommando-Builder für `0x3201` (analog `build_create_tx_flow`).
